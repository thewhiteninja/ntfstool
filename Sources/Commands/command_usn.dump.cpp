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

void load_mft(std::shared_ptr<NTFSExplorer> explorer, std::unordered_map<DWORD64, DWORD64>& map_parent, std::unordered_map<DWORD64, std::string>& map_name)
{
	std::cout << "[+] Loading $MFT records" << std::endl;

	map_name.clear();
	map_parent.clear();

	std::shared_ptr<MFTRecord> record_mft = explorer->mft()->record_from_number(0);
	if (record_mft == nullptr)
	{
		std::cout << "[!] Error accessing record 0" << std::endl;
		return;
	}
	ULONG64 total_size_mft = record_mft->datasize();
	DWORD record_size = explorer->reader()->sizes.cluster_size;

	std::shared_ptr<MFTRecord> record = nullptr;

	auto index = 0ULL;
	for (index = 0ULL; index < (total_size_mft / record_size); index++)
	{
		std::cout << "\r[+] Processing $MFT records: " << utils::format::size(index * record_size) << "     ";

		record = explorer->mft()->record_from_number(index);

		if (record == nullptr || !MFTRecord::is_valid(record->header()))
		{
			continue;
		}

		ULONGLONG file_info_parentid = 0;
		PMFT_RECORD_ATTRIBUTE_HEADER pattr = record->attribute_header($FILE_NAME, "", 0);
		if (pattr != nullptr)
		{
			auto pattr_filename = POINTER_ADD(PMFT_RECORD_ATTRIBUTE_FILENAME, pattr, pattr->Form.Resident.ValueOffset);
			file_info_parentid = pattr_filename->ParentDirectory.SequenceNumber << 48 | pattr_filename->ParentDirectory.FileRecordNumber;
		}

		ULONGLONG file_record_num = record->header()->sequenceNumber;
		file_record_num = file_record_num << 48 | record->header()->MFTRecordIndex;

		map_parent[file_record_num] = file_info_parentid;
		map_name[file_record_num] = utils::strings::to_utf8(record->filename());
	}
	std::cout << "\r[+] Processing $MFT records: " << utils::format::size(index * record_size) << "     " << std::endl;

	std::cout << "[+] " << index << " record loaded" << std::endl;
}

std::string get_file_path(std::unordered_map<DWORD64, DWORD64>& map_parent, std::unordered_map<DWORD64, std::string>& map_name, DWORD64 parent_inode, std::string filename)
{
	std::string path = filename;

	while ((parent_inode & 0xffffffffffff) != 5)
	{
		auto tmp = map_parent.find(parent_inode);
		if (tmp != map_parent.end())
		{
			path = map_name[parent_inode] + "\\" + path;
			parent_inode = tmp->second;
		}
		else
		{
			break;
		}
	}
	if ((parent_inode & 0xffffffffffff) == 5)
	{
		path = "volume:\\" + path;
	}
	else
	{
		path = "orphan:\\" + path;
	}

	return path;
}

int print_usn_journal(std::shared_ptr<Disk> disk, std::shared_ptr<Volume> vol, const std::string& format, std::string output)
{
	if (!commands::helpers::is_ntfs(disk, vol)) return 1;

	utils::ui::title("Dump USN journal for " + disk->name() + " > Volume:" + std::to_string(vol->index()));

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

	Buffer<PBYTE> clusterBuf((DWORD64)2 * 1024 * 1024);
	ULONG64 total_size = record->datasize(MFT_ATTRIBUTE_DATA_USN_NAME, true);
	ULONG64 filled_size = 0;

	std::cout << "[+] $J stream size: " << utils::format::size(total_size) << " (could be sparse)" << std::endl;

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
			std::cout << "\r[+] Processing USN records: " << utils::format::size(processed_size) << "     ";
			processed_size += block.second;

			DWORD written = 0;
			WriteFile(houtput, block.first, block.second, &written, NULL);
		}
		std::cout << "\r[+] Processing USN records: " << utils::format::size(processed_size);

		CloseHandle(houtput);
	}
	else if (format == "csv" || format == "json")
	{
		std::unordered_map<DWORD64, DWORD64> map_parent;
		std::unordered_map<DWORD64, std::string> map_name;

		load_mft(explorer, map_parent, map_name);

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

		for (auto& block : record->process_data(MFT_ATTRIBUTE_DATA_USN_NAME, explorer->reader()->sizes.cluster_size, true))
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
					ffile->add_item(get_file_path(map_parent, map_name, usn_record->ParentFileReferenceNumber, utils::strings::to_utf8(a)));

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

		map_parent.clear();
		map_name.clear();
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
		namespace dump
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
}