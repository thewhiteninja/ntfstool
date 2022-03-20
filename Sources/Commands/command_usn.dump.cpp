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
#include <Utils/csv_file.h>
#include <Utils/json_file.h>

int print_usn_journal(std::shared_ptr<Disk> disk, std::shared_ptr<Volume> vol, const std::string& format, std::string output)
{
	if (!commands::helpers::is_ntfs(disk, vol)) return 1;

	std::cout << std::setfill('0');
	utils::ui::title("USN Journals from " + disk->name() + " > Volume:" + std::to_string(vol->index()));

	DWORD cluster_size = ((PBOOT_SECTOR_NTFS)vol->bootsector())->bytePerSector * ((PBOOT_SECTOR_NTFS)vol->bootsector())->sectorPerCluster;

	std::cout << "[+] Opening " << vol->name() << std::endl;

	std::shared_ptr<NTFSExplorer> explorer = std::make_shared<NTFSExplorer>(vol);

	std::cout << "[+] Finding $Extend\\$UsnJrnl record" << std::endl;

	std::shared_ptr<MFTRecord> record = explorer->mft()->record_from_path("\\$Extend\\$UsnJrnl");

	if (record == nullptr)
	{
		std::cout << "[!] Not found" << std::endl;
		return 2;
	}

	std::cout << "[+] Found in file record: " << std::to_string(record->header()->MFTRecordIndex) << std::endl;

	PMFT_RECORD_HEADER record_header = record->header();

	Buffer<PBYTE> clusterBuf((DWORD64)2 * 1024 * 1024);
	ULONG64 total_size = record->datasize(MFT_ATTRIBUTE_DATA_USN_NAME, true);
	ULONG64 filled_size = 0;

	std::cout << "[+] $J stream size: " << utils::format::size(total_size) << " (maybe sparse, ~32MiBs on disk by default)" << std::endl;

	std::cout << "[+] Creating " << output << std::endl;

	if (format == "raw")
	{
		HANDLE houtput = CreateFileA(output.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
		if (houtput == INVALID_HANDLE_VALUE)
		{
			std::cout << "[!] Error creating output file" << std::endl;
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
	}
	else if (format == "csv" || format == "json")
	{
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
			"MajorVersion",
			"MinorVersion",
			"FileReferenceNumber",
			"FileReferenceSequenceNumber",
			"ParentFileReferenceNumber",
			"ParentFileReferenceSequenceNumber",
			"Usn",
			"Timestamp",
			"Reason",
			"SourceInfo",
			"SecurityId",
			"FileAttributes",
			"Filename"
			}
		);

		ULONG64 processed_size = 0;
		ULONG64 processed_count = 0;

		for (auto& block : record->process_data(MFT_ATTRIBUTE_DATA_USN_NAME, cluster_size, true))
		{
			processed_size += block.second;

			std::cout << "\r[+] Processing entry: " << std::to_string(processed_count) << " (" << utils::format::size(processed_size) << ")     ";

			memcpy(clusterBuf.data() + filled_size, block.first, block.second);
			filled_size += block.second;

			PUSN_RECORD_COMMON_HEADER header = (PUSN_RECORD_COMMON_HEADER)clusterBuf.data();
			while ((filled_size > 0) && (header->RecordLength <= filled_size))
			{
				switch (header->MajorVersion)
				{
				case 0:
				{
					DWORD i = 0;
					while ((i < filled_size) && (((PBYTE)header)[i] == 0)) i++;
					header = POINTER_ADD(PUSN_RECORD_COMMON_HEADER, header, i);
					filled_size -= i;
					break;
				}
				case 2:
				{
					PUSN_RECORD_V2 usn_record = (PUSN_RECORD_V2)header;
					std::wstring a = std::wstring(usn_record->FileName);
					a.resize(usn_record->FileNameLength / sizeof(WCHAR));

					processed_count++;

					ffile->add_item(usn_record->MajorVersion);
					ffile->add_item(usn_record->MinorVersion);
					ffile->add_item(usn_record->FileReferenceNumber & 0xffffffffffff);
					ffile->add_item(usn_record->FileReferenceNumber >> 48);
					ffile->add_item(usn_record->ParentFileReferenceNumber & 0xffffffffffff);
					ffile->add_item(usn_record->ParentFileReferenceNumber >> 48);
					ffile->add_item(usn_record->Usn);

					SYSTEMTIME st = { 0 };
					utils::times::ull_to_local_systemtime(usn_record->TimeStamp.QuadPart, &st);
					ffile->add_item(utils::times::display_systemtime(st));
					ffile->add_item(constants::disk::usn::reasons(usn_record->Reason));
					ffile->add_item((usn_record->SourceInfo));
					ffile->add_item((usn_record->SecurityId));
					ffile->add_item(constants::disk::usn::fileattributes(usn_record->FileAttributes));
					ffile->add_item(utils::strings::to_utf8(a));

					ffile->new_line();

					filled_size -= usn_record->RecordLength;
					header = POINTER_ADD(PUSN_RECORD_COMMON_HEADER, header, usn_record->RecordLength);
					break;
				}
				default:
					std::cout << std::endl << "[!] Unknown USN record version (" << std::to_string(header->MajorVersion) << ")" << std::endl;
					return 1;
				}
			}

			memcpy(clusterBuf.data(), header, (size_t)filled_size);
		}
		std::cout << "\r[+] Processing entry: " << std::to_string(processed_count) << " (" << utils::format::size(processed_size) << ")     ";
	}
	else
	{
		std::cout << "[!] Invalid or missing format" << std::endl;
	}

	std::cout << std::endl << "[+] Closing volume" << std::endl;

	return 0;
}

namespace commands
{
	namespace usn
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

						print_usn_journal(disk, volume, opts->format, opts->output);
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