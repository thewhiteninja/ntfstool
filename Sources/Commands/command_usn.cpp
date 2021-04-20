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

int print_usn_journal(std::shared_ptr<Disk> disk, std::shared_ptr<Volume> vol, const std::string& format, std::string output) {
	if ((vol->filesystem() != "NTFS") && (vol->filesystem() != "Bitlocker"))
	{
		std::cerr << "[!] NTFS volume required" << std::endl;
		return 1;
	}

	std::cout << std::setfill('0');
	utils::ui::title("USN Journal from " + disk->name() + " > Volume:" + std::to_string(vol->index()));

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

	std::cout << "[+] Found in file record : " << std::to_string(record->header()->MFTRecordIndex) << std::endl;

	PMFT_RECORD_HEADER record_header = record->header();

	Buffer<PBYTE> clusterBuf((DWORD64)2 * cluster_size);
	ULONG64 total_size = record->datasize(MFT_ATTRIBUTE_DATA_USN_NAME);

	std::cout << "[+] Data stream $J size : " << utils::format::size(total_size) << std::endl;

	ULONG64 processed_size = 0;
	ULONG64 processed_count = 0;
	ULONG64 filled_size = 0;

	std::cout << "[+] Reading $J" << std::endl;

	HANDLE houtput = CreateFileA(output.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
	if (houtput == INVALID_HANDLE_VALUE)
	{
		std::cout << "[!] Error creating output file" << std::endl;
		return 1;
	}

	if (format == "raw")
	{
		for (auto& block : record->process_data(MFT_ATTRIBUTE_DATA_USN_NAME))
		{
			std::cout << "\r[+] Processing cluster : " << std::to_string(++processed_count);
			DWORD written = 0;
			WriteFile(houtput, block.first, block.second, &written, NULL);
		}
	}
	else if (format == "csv")
	{
		std::string csv_header = "MajorVersion,MinorVersion,FileReferenceNumber,FileReferenceSequenceNumber,ParentFileReferenceNumber,ParentFileReferenceSequenceNumber,Usn,Timestamp,Reason,SourceInfo,SecurityId,FileAttributes,Filename\n";
		DWORD written = 0;
		DWORD header_size = 0;
		if (!FAILED(SizeTToDWord(csv_header.size(), &header_size))) WriteFile(houtput, csv_header.c_str(), header_size, &written, NULL);

		for (auto& block : record->process_data(MFT_ATTRIBUTE_DATA_USN_NAME))
		{
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
					processed_size += i;
					header = POINTER_ADD(PUSN_RECORD_COMMON_HEADER, header, i);
					filled_size -= i;
					break;
				}
				case 2:
				{
					PUSN_RECORD_V2 usn_record = (PUSN_RECORD_V2)header;
					processed_size += usn_record->RecordLength;
					std::wstring a = std::wstring(usn_record->FileName);
					a.resize(usn_record->FileNameLength / sizeof(WCHAR));

					std::cout << "\r[+] Processing entry : " << std::to_string(++processed_count);

					std::ostringstream entry;
					entry << usn_record->MajorVersion << ",";
					entry << usn_record->MinorVersion << ",";
					entry << (usn_record->FileReferenceNumber & 0xffffffffffff) << ",";
					entry << (usn_record->FileReferenceNumber >> 48) << ",";
					entry << (usn_record->ParentFileReferenceNumber & 0xffffffffffff) << ",";
					entry << (usn_record->ParentFileReferenceNumber >> 48) << ",";
					entry << usn_record->Usn << ",";
					SYSTEMTIME st = { 0 };
					utils::times::ull_to_local_systemtime(usn_record->TimeStamp.QuadPart, &st);
					entry << utils::times::display_systemtime(st) << ",";
					entry << constants::disk::usn::reasons(usn_record->Reason) << ",";
					entry << std::to_string(usn_record->SourceInfo) << ",";
					entry << std::to_string(usn_record->SecurityId) << ",";
					entry << constants::disk::usn::fileattributes(usn_record->FileAttributes) << ",";
					entry << utils::strings::to_utf8(a) << std::endl;

					std::string line = entry.str();
					DWORD write_size = 0;
					if (!FAILED(SizeTToDWord(line.size(), &write_size))) WriteFile(houtput, line.c_str(), write_size, &written, NULL);

					filled_size -= usn_record->RecordLength;
					header = POINTER_ADD(PUSN_RECORD_COMMON_HEADER, header, usn_record->RecordLength);
					break;
				}
				default:
					std::cout << std::endl << "[!] Unknown USN record version" << std::endl;
					return 1;
				}
			}

			memcpy(clusterBuf.data(), header, (size_t)filled_size);
		}
	}
	else if (format == "json")
	{
		DWORD written = 0;
		WriteFile(houtput, "[\n", 2, &written, NULL);

		for (auto& block : record->process_data(MFT_ATTRIBUTE_DATA_USN_NAME))
		{
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
					processed_size += i;
					header = POINTER_ADD(PUSN_RECORD_COMMON_HEADER, header, i);
					filled_size -= i;
					break;
				}
				case 2:
				{
					PUSN_RECORD_V2 usn_record = (PUSN_RECORD_V2)header;
					processed_size += usn_record->RecordLength;
					std::wstring a = std::wstring(usn_record->FileName);
					a.resize(usn_record->FileNameLength / sizeof(WCHAR));

					std::cout << "\r[+] Processing entry : " << std::to_string(++processed_count);

					nlohmann::json entry;
					entry["MajorVersion"] = usn_record->MajorVersion;
					entry["MinorVersion"] = usn_record->MinorVersion;
					entry["FileReferenceNumber"] = (usn_record->FileReferenceNumber & 0xffffffffffff);
					entry["FileReferenceSequenceNumber"] = (usn_record->FileReferenceNumber >> 48);
					entry["ParentFileReferenceNumber"] = (usn_record->ParentFileReferenceNumber & 0xffffffffffff);
					entry["ParentFileReferenceSequenceNumber"] = (usn_record->ParentFileReferenceNumber >> 48);
					entry["Usn"] = usn_record->Usn;
					SYSTEMTIME st = { 0 };
					utils::times::ull_to_local_systemtime(usn_record->TimeStamp.QuadPart, &st);
					entry["Timestamp"] = utils::times::display_systemtime(st);
					entry["Reasons"] = constants::disk::usn::reasons(usn_record->Reason);
					entry["SourceInfo"] = usn_record->SourceInfo;
					entry["SecurityId"] = usn_record->SecurityId;
					entry["FileAttributes"] = constants::disk::usn::fileattributes(usn_record->FileAttributes);
					entry["FileName"] = utils::strings::to_utf8(a);

					std::string line = entry.dump() + ",\n";
					DWORD line_size = 0;

					if (!FAILED(SizeTToDWord(line.size(), &line_size))) WriteFile(houtput, line.c_str(), line_size, &written, NULL);

					filled_size -= usn_record->RecordLength;
					header = POINTER_ADD(PUSN_RECORD_COMMON_HEADER, header, usn_record->RecordLength);
					break;
				}
				default:
					std::cout << std::endl << "[!] Unknown USN record version" << std::endl;
					return 1;
				}
			}

			memcpy(clusterBuf.data(), header, (size_t)filled_size);
		}

		WriteFile(houtput, "{}]\n", 2, &written, NULL);
	}
	else
	{
		std::cout << "[!] Invalid or missing format" << std::endl;
	}

	CloseHandle(houtput);
	std::cout << std::endl << "[+] Closing volume" << std::endl;

	return 0;
}

namespace commands
{
	namespace usn
	{
		int print_usn_journal(std::shared_ptr<Options> opts)
		{
			std::ios_base::fmtflags flag_backup(std::cout.flags());

			std::shared_ptr<Disk> disk = get_disk(opts);
			if (disk != nullptr)
			{
				std::shared_ptr<Volume> volume = disk->volumes(opts->volume);
				if (volume != nullptr)
				{
					if (opts->out != "")
					{
						print_usn_journal(disk, volume, opts->format, opts->out);
					}
					else
					{
						std::cerr << "[!] Invalid or missing output file";
						return 1;
					}
				}
			}

			std::cout.flags(flag_backup);
			return 0;
		}
	}
}