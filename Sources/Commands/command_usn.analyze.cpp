#include "Drive/disk.h"
#include "Utils/utils.h"
#include "options.h"
#include "Commands/commands.h"
#include "NTFS/ntfs.h"
#include "NTFS/ntfs_explorer.h"
#include "Utils/constant_names.h"
#include <Utils/csv_file.h>
#include "Utils/table.h"

#include <nlohmann/json.hpp>

#include <cstdint>
#include <string>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <memory>
#include <Utils/usn_rules.h>


int analyze_usn_journal(std::shared_ptr<Disk> disk, std::shared_ptr<Volume> vol, const std::string& rules, std::string& output)
{
	if (!commands::helpers::is_ntfs(disk, vol)) return 1;

	std::cout << std::setfill('0');
	utils::ui::title("Analyze USN journal from " + disk->name() + " > Volume:" + std::to_string(vol->index()));

	std::cout << "[+] Opening " << vol->name() << std::endl;

	std::shared_ptr<NTFSExplorer> explorer = std::make_shared<NTFSExplorer>(vol);

	std::cout << "[+] Searching for $Extend\\$UsnJrnl" << std::endl;

	std::shared_ptr<MFTRecord> record = explorer->mft()->record_from_path("\\$Extend\\$UsnJrnl");

	if (record == nullptr)
	{
		std::cout << "[!] Not found" << std::endl;
		return 2;
	}

	std::cout << "[-] Found in file record: " << std::to_string(record->header()->MFTRecordIndex) << std::endl;

	Buffer<PBYTE> clusterBuf((DWORD64)2 * 1024 * 1024);
	ULONG64 total_size = record->datasize(MFT_ATTRIBUTE_DATA_USN_NAME, true);
	ULONG64 filled_size = 0;

	std::cout << "[-] $J stream size: " << utils::format::size(total_size) << " (maybe sparse, ~32MiBs on disk by default)" << std::endl;

	std::cout << "[+] Loading rules from: " << rules << std::endl;
	std::shared_ptr<USNRules> usn_rules = std::make_shared<USNRules>(rules);
	if (usn_rules->size() > 0)
	{
		std::cout << "[-] " << usn_rules->size() << " rules loaded" << std::endl;
	}
	else
	{
		std::cout << "[!] No rule loaded. Exiting." << std::endl;
		return 1;
	}

	std::cout << "[+] Creating " << output << std::endl;

	std::shared_ptr<FormatteddFile> ffile = std::make_shared<CSVFile>(output);

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
	ULONG64 matches = 0;

	for (auto& block : record->process_data(MFT_ATTRIBUTE_DATA_USN_NAME, explorer->reader()->sizes.cluster_size, true))
	{
		processed_size += block.second;

		std::cout << "\r[-] Processing entry: " << std::to_string(processed_count) << " (" << utils::format::size(processed_size) << ") - " << matches << " matches     ";

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
				std::wstring wfilename = std::wstring(usn_record->FileName);
				wfilename.resize(usn_record->FileNameLength / sizeof(WCHAR));
				std::string filename = utils::strings::to_utf8(wfilename);

				SYSTEMTIME st = { 0 };
				utils::times::ull_to_local_systemtime(usn_record->TimeStamp.QuadPart, &st);

				for (auto rule : usn_rules->rules())
				{
					if (rule->match(filename, usn_record))
					{
						matches++;
					}
				}

				processed_count++;

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
	std::cout << "\r[-] Processing entry: " << std::to_string(processed_count) << " (" << utils::format::size(processed_size) << ") - " << matches << " matches     ";

	std::cout << std::endl << "[+] Closing volume" << std::endl;

	return 0;
}

namespace commands
{
	namespace usn
	{
		namespace analyze
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
							if (opts->rules != "")
							{
								analyze_usn_journal(disk, volume, opts->rules, opts->output);
							}
							else
							{
								invalid_option(opts, "rules", opts->rules);
							}
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