#include "Drive/disk.h"
#include "Utils/utils.h"
#include "options.h"
#include "Commands/commands.h"
#include "NTFS/ntfs.h"
#include "NTFS/ntfs_explorer.h"
#include "Utils/constant_names.h"
#include "Utils/table.h"

#include <nlohmann/json.hpp>

#include <cstdint>
#include <string>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <memory>
#include <iterator>
#include <Utils/csv_file.h>
#include <Utils/json_file.h>

void fixup_sequence(PRECORD_PAGE_HEADER prh)
{
	if (prh->update_sequence_array_count > 1)
	{
		PWORD pfixup = POINTER_ADD(PWORD, prh, prh->update_sequence_array_offset);
		DWORD offset = 0x200 - sizeof(WORD);
		for (int i = 1; i < prh->update_sequence_array_count; i++)
		{
			if (*POINTER_ADD(PWORD, prh, offset) == pfixup[0])
			{
				*POINTER_ADD(PWORD, prh, offset) = pfixup[i];
			}
			offset += 0x200;
			if (offset > 0x1000 - sizeof(WORD))
			{
				break;
			}
		}
	}
}

PRESTART_PAGE_HEADER find_newest_restart_page(PBYTE logfile)
{
	PRESTART_PAGE_HEADER newestRestartPageHeader = nullptr;

	PRESTART_PAGE_HEADER prstpage0 = POINTER_ADD(PRESTART_PAGE_HEADER, logfile, 0);
	PRESTART_PAGE_HEADER prstpage1 = POINTER_ADD(PRESTART_PAGE_HEADER, logfile, 4096);
	PRESTART_AREA prstarea0 = POINTER_ADD(PRESTART_AREA, prstpage0, prstpage0->restart_area_offset);
	PRESTART_AREA prstarea1 = POINTER_ADD(PRESTART_AREA, prstpage1, prstpage1->restart_area_offset);
	if (prstarea0->current_lsn > prstarea1->current_lsn)
	{
		newestRestartPageHeader = prstpage0;
	}
	else
	{
		newestRestartPageHeader = prstpage1;
	}

	return newestRestartPageHeader;
}

std::vector<std::string> get_log_clients(PRESTART_AREA ra)
{
	std::vector<std::string> ret;
	WORD log_clients_count = ra->log_clients;
	if (log_clients_count != MFT_LOGFILE_NO_CLIENT)
	{
		PLOG_CLIENT_RECORD plcr = POINTER_ADD(PLOG_CLIENT_RECORD, ra, ra->client_array_offset);
		for (int i = 0; i < log_clients_count; i++)
		{
			std::wstring client_name = std::wstring(plcr->client_name);
			client_name.resize(plcr->client_name_length);
			ret.push_back(utils::strings::to_utf8(client_name));
			plcr = POINTER_ADD(PLOG_CLIENT_RECORD, plcr, plcr->next_client);
		}
	}
	return ret;
}

void _add_record(std::shared_ptr<FormatteddFile> ffile, PRECORD_LOG rl)
{
	ffile->add_item(rl->lsn);
	ffile->add_item(rl->client_previous_lsn);
	ffile->add_item(rl->client_undo_next_lsn);
	ffile->add_item(rl->client_id.client_index);
	ffile->add_item(rl->record_type);
	ffile->add_item(rl->transaction_id);
	ffile->add_item(constants::disk::logfile::operation(rl->redo_operation));
	ffile->add_item(constants::disk::logfile::operation(rl->undo_operation));
	ffile->add_item(rl->mft_cluster_index);
	ffile->add_item(rl->target_vcn);
	ffile->add_item(rl->target_lcn);

	ffile->new_line();
}


int print_logfile_records(std::shared_ptr<Disk> disk, std::shared_ptr<Volume> vol, const std::string& format, std::string output)
{
	if (!commands::helpers::is_ntfs(disk, vol)) return 1;

	utils::ui::title("LogFile from " + disk->name() + " > Volume:" + std::to_string(vol->index()));

	std::cout << "[+] Opening " << vol->name() << std::endl;

	std::shared_ptr<NTFSExplorer> explorer = std::make_shared<NTFSExplorer>(vol);

	std::cout << "[+] Reading $LogFile record" << std::endl;
	std::shared_ptr<MFTRecord> record = explorer->mft()->record_from_number(LOG_FILE_NUMBER);

	ULONG64 total_size = record->datasize();
	std::cout << "[+] $LogFile size : " << utils::format::size(total_size) << std::endl;

	std::cout << "[+] Creating " << output << std::endl;

	if (format == "raw")
	{
		HANDLE houtput = CreateFileA(output.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
		if (houtput == INVALID_HANDLE_VALUE)
		{
			std::cout << "[!] Failed to create output file" << std::endl;
			return 1;
		}

		ULONG64 processed_size = 0;

		for (auto& block : record->process_data(MFT_ATTRIBUTE_DATA_USN_NAME, 1024 * 1024, true))
		{
			std::cout << "\r[+] Processing data: " << utils::format::size(processed_size) << "     ";
			processed_size += block.second;

			DWORD written = 0;
			WriteFile(houtput, block.first, block.second, &written, NULL);
		}
		std::cout << "\r[+] Processing data: " << utils::format::size(processed_size);

		CloseHandle(houtput);

		std::cout << "[+] Closing volume" << std::endl;
	}
	else if (format == "json" || format == "csv")
	{
		std::shared_ptr<Buffer<PBYTE>> logfile = record->data();

		PRESTART_PAGE_HEADER newest_restart_header = find_newest_restart_page(logfile->data());
		PRESTART_AREA newest_restart_area = POINTER_ADD(PRESTART_AREA, newest_restart_header, newest_restart_header->restart_area_offset);

		std::cout << "[-] Newest Restart Page LSN : " << std::to_string(newest_restart_area->current_lsn) << std::endl;

		if (newest_restart_area->flags & MFT_LOGFILE_RESTART_AREA_FLAG_VOLUME_CLEANLY_UNMOUNTED)
		{
			std::cout << "[!] Volume marked as not cleanly unmounted" << std::endl;
		}
		else
		{
			std::cout << "[-] Volume marked as cleanly unmounted" << std::endl;
		}

		//////////

		DWORD client_i = 1;
		for (auto& client : get_log_clients(newest_restart_area))
		{
			std::cout << "[-] Client found : [" << std::to_string(client_i++) << "] " << client << std::endl;
		}

		//////////

		std::cout << "[+] Parsing $LogFile Record Pages" << std::endl;

		std::vector<PRECORD_PAGE_HEADER> record_page_offsets;

		for (DWORD offset = 4 * newest_restart_header->log_page_size; offset < logfile->size(); offset += newest_restart_header->log_page_size)
		{
			PRECORD_PAGE_HEADER prh = POINTER_ADD(PRECORD_PAGE_HEADER, logfile->data(), offset);
			if (memcmp(prh->magic, "RCRD", 4) != 0) {
				continue;
			}
			record_page_offsets.push_back(prh);
		}

		std::cout << "[-] $LogFile Record Page Count : " << std::to_string(record_page_offsets.size()) << std::endl;

		/////////

		std::shared_ptr<FormatteddFile> ffile;

		if (format == "csv")
		{
			ffile = std::make_shared<CSVFile>(output);
		}
		else
		{
			ffile = std::make_shared<JSONFile>(output);
		}

		ffile->set_columns(
			{
			"LSN",
			"ClientPreviousLSN",
			"UndoNextLSN",
			"ClientID",
			"RecordType",
			"TransactionID",
			"RedoOperation",
			"UndoOperation",
			"MFTClusterIndex",
			"TargetVCN",
			"TargetLCN"
			}
		);

		std::cout << "[-] Parsing $LogFile Records" << std::endl;

		Buffer<PBYTE> leftover_buffer(8 * 4096);
		DWORD leftover_size = 0;
		DWORD leftover_missing_size = 0;
		DWORD processed = 0;

		for (PRECORD_PAGE_HEADER prh : record_page_offsets)
		{
			fixup_sequence(prh);

			DWORD offset = 64;
			DWORD index = 1;

			if (leftover_size > 0)
			{
				memcpy(leftover_buffer.data() + leftover_size, POINTER_ADD(PBYTE, prh, offset), min(leftover_missing_size, 4096 - offset));
				leftover_missing_size -= min(leftover_missing_size, 4096 - offset);

				if (leftover_missing_size == 0)
				{
					_add_record(ffile, POINTER_ADD(PRECORD_LOG, leftover_buffer.data(), 0));

					processed++;
					std::cout << "\r[-] $LogFile Record Count : " << std::to_string(processed) + "     ";

					offset += leftover_missing_size;
					leftover_size = 0;
				}
				else
				{
					continue;
				}
			}

			index = 1;
			DWORD stop = min(prh->header.packed.next_record_offset + MFT_LOGFILE_LOG_RECORD_HEADER_SIZE, 4096 - MFT_LOGFILE_LOG_RECORD_HEADER_SIZE);

			int error = 0;
			while (offset < stop)
			{
				PRECORD_LOG prl = POINTER_ADD(PRECORD_LOG, prh, offset);

				if (error > 1)
				{
					break;
				}

				if (prl->lsn == 0 || prl->record_type == 0 || prl->record_type > 37)
				{
					error++;
					offset = prh->header.packed.next_record_offset;
					continue;
				}

				offset += MFT_LOGFILE_LOG_RECORD_HEADER_SIZE + prl->client_data_length;

				if (prl->flags & LOG_RECORD_MULTI_PAGE)
				{
					memcpy(leftover_buffer.data(), prl, 4096 - prh->header.packed.next_record_offset);
					leftover_size = 4096 - prh->header.packed.next_record_offset;
					leftover_missing_size = prl->client_data_length - (leftover_size - MFT_LOGFILE_LOG_RECORD_HEADER_SIZE);
				}
				else
				{
					_add_record(ffile, prl);

					processed++;
					std::cout << "\r[-] $LogFile Record Count : " << std::to_string(processed) + "     ";
				}
			}
		}
	}
	else
	{
		std::cout << "[!] Invalid or missing format" << std::endl;
		return 2;
	}

	std::cout << std::endl << "[+] Closing volume" << std::endl;

	return 0;
}

namespace commands
{
	namespace logfile
	{
		int dispatch(std::shared_ptr<Options> opts)
		{
			std::ios_base::fmtflags flag_backup(std::cout.flags());

			std::shared_ptr<Disk> disk = get_disk(opts);
			if (disk != nullptr)
			{
				std::shared_ptr<Volume> volume = disk->volumes(opts->volume);
				if (volume != nullptr)
				{
					if (opts->output != "")
					{
						if (opts->format == "") opts->format = "raw";

						print_logfile_records(disk, volume, opts->format, opts->output);
					}
					else
					{
						invalid_option(opts, "output", opts->output);
					}
				}
				else
				{
					invalid_option(opts, "volume", opts->volume);
				}
			}
			else
			{
				invalid_option(opts, "disk", opts->disk);
			}

			std::cout.flags(flag_backup);
			return 0;
		}
	}
}