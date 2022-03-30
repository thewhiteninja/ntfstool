#include <cstdint>
#include <string>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <memory>

#include "Commands/commands.h"
#include "NTFS/ntfs.h"
#include "NTFS/ntfs_explorer.h"
#include "Utils/constant_names.h"
#include "Utils/table.h"
#include "Utils/utils.h"

#include "options.h"
#include "Drive/disk.h"
#include "Drive/volume.h"
#include <Utils/index_details.h>
#include <Utils/zone_identifier.h>
#include <Utils/csv_file.h>
#include <Utils/json_file.h>


int dump_mft(std::shared_ptr<Disk> disk, std::shared_ptr<Volume> vol, std::shared_ptr<Options> opts, const std::string& format, std::string output)
{
	if (!commands::helpers::is_ntfs(disk, vol)) return 1;

	utils::ui::title("MFT Dump (inode:0) for " + disk->name() + " > Volume:" + std::to_string(vol->index()));

	std::shared_ptr<NTFSExplorer> explorer = std::make_shared<NTFSExplorer>(vol);

	std::shared_ptr<MFTRecord> record = explorer->mft()->record_from_number(0);
	if (record == nullptr)
	{
		std::cout << "[!] Error accessing record 0" << std::endl;
		return 1;
	}

	DWORD record_size = explorer->reader()->sizes.record_size;
	ULONG64 total_size = record->datasize();

	std::cout << "[+] $MFT size   : " << utils::format::size(total_size) << std::endl;
	std::cout << "[-] Record size : " << record_size << std::endl;
	std::cout << "[-] Record count: " << (total_size / record_size) << std::endl;

	std::cout << "[+] Creating " << output << std::endl;

	if (format == "raw")
	{
		HANDLE houtput = CreateFileA(output.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
		if (houtput == INVALID_HANDLE_VALUE)
		{
			std::cout << "[!] Error creating output file" << std::endl;
			return 2;
		}

		ULONG64 processed_size = 0;

		for (auto& block : record->process_data("", 1024 * 1024, true))
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
		SYSTEMTIME file_info_creation = { 0 };
		SYSTEMTIME file_info_access = { 0 };
		SYSTEMTIME file_info_modification = { 0 };
		SYSTEMTIME file_info_mft = { 0 };
		unsigned long long file_info_size = 0;
		WORD file_info_hardlink_count = 0;
		std::set<std::string> file_info_parentids;

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
			"RecordIndex",
			"InUse",
			"Type",
			"Filename",
			"Ext",
			"Size",
			"Parents",
			"Time_MFT",
			"Time_Create",
			"Time_Alter",
			"Time_Read",
			"Att_Archive",
			"Att_Compressed",
			"Att_Device",
			"Att_Encrypted",
			"Att_Hidden",
			"Att_Normal",
			"Att_NotIndexed",
			"Att_Offline",
			"Att_Readonly",
			"Att_Reparse",
			"Att_Sparse",
			"Att_System",
			"Att_Temp",
			"USN",
			"Hardlinks",
			"ADS",
			"ZoneId",
			"ReferrerUrl",
			"HostUrl"
			}
		);

		std::shared_ptr<MFTRecord> record = nullptr;

		auto index = 0ULL;
		for (index = 0ULL; index < (total_size / record_size); index++)
		{
			std::cout << "\r[+] Processing data: " << utils::format::size(index * record_size) << "     ";

			record = explorer->mft()->record_from_number(index);

			if (record == nullptr || !MFTRecord::is_valid(record->header()))
			{
				continue;
			}

			ffile->add_item(record->header()->MFTRecordIndex);
			ffile->add_item(record->header()->flag & FILE_RECORD_FLAG_INUSE ? "True" : "False");
			ffile->add_item(record->header()->flag & FILE_RECORD_FLAG_DIR ? "Directory" : "File");

			auto path = std::filesystem::path(record->filename());

			ffile->add_item(utils::strings::to_utf8(path.filename().generic_wstring()));
			ffile->add_item(utils::strings::lower(utils::strings::to_utf8(path.extension().generic_wstring())));

			ffile->add_item(record->datasize());

			file_info_parentids.clear();
			int att_index = 0;
			PMFT_RECORD_ATTRIBUTE_HEADER pattr = record->attribute_header($FILE_NAME, "", att_index);
			while (pattr != nullptr)
			{
				auto pattr_filename = POINTER_ADD(PMFT_RECORD_ATTRIBUTE_FILENAME, pattr, pattr->Form.Resident.ValueOffset);
				file_info_parentids.insert(std::to_string(pattr_filename->ParentDirectory.FileRecordNumber));
				att_index++;
				if (att_index > 4) break;
				pattr = record->attribute_header($FILE_NAME, "", att_index);
			}
			ffile->add_item(utils::strings::join_set(file_info_parentids, "|"));

			pattr = record->attribute_header($STANDARD_INFORMATION);
			if (pattr != nullptr)
			{
				PMFT_RECORD_ATTRIBUTE_STANDARD_INFORMATION psubattr = POINTER_ADD(PMFT_RECORD_ATTRIBUTE_STANDARD_INFORMATION, pattr, pattr->Form.Resident.ValueOffset);
				utils::times::ull_to_systemtime(psubattr->MFTTime, &file_info_mft);
				utils::times::ull_to_systemtime(psubattr->CreateTime, &file_info_creation);
				utils::times::ull_to_systemtime(psubattr->AlterTime, &file_info_modification);
				utils::times::ull_to_systemtime(psubattr->ReadTime, &file_info_access);

				ffile->add_item(utils::times::display_systemtime(file_info_mft));
				ffile->add_item(utils::times::display_systemtime(file_info_creation));
				ffile->add_item(utils::times::display_systemtime(file_info_modification));
				ffile->add_item(utils::times::display_systemtime(file_info_access));

				ffile->add_item(psubattr->u.Permission.archive ? "True" : "False");
				ffile->add_item(psubattr->u.Permission.compressed ? "True" : "False");
				ffile->add_item(psubattr->u.Permission.device ? "True" : "False");
				ffile->add_item(psubattr->u.Permission.encrypted ? "True" : "False");
				ffile->add_item(psubattr->u.Permission.hidden ? "True" : "False");
				ffile->add_item(psubattr->u.Permission.normal ? "True" : "False");
				ffile->add_item(psubattr->u.Permission.not_indexed ? "True" : "False");
				ffile->add_item(psubattr->u.Permission.offline ? "True" : "False");
				ffile->add_item(psubattr->u.Permission.readonly ? "True" : "False");
				ffile->add_item(psubattr->u.Permission.reparse ? "True" : "False");
				ffile->add_item(psubattr->u.Permission.sparse ? "True" : "False");
				ffile->add_item(psubattr->u.Permission.system ? "True" : "False");
				ffile->add_item(psubattr->u.Permission.temp ? "True" : "False");

				ffile->add_item(psubattr->USN);
			}
			else
			{
				ffile->add_item();
				ffile->add_item();
				ffile->add_item();
				ffile->add_item();
				ffile->add_item();

				ffile->add_item();
				ffile->add_item();
				ffile->add_item();
				ffile->add_item();
				ffile->add_item();
				ffile->add_item();
				ffile->add_item();
				ffile->add_item();
				ffile->add_item();
				ffile->add_item();
				ffile->add_item();
				ffile->add_item();
				ffile->add_item();

				ffile->add_item();
			}

			ffile->add_item(record->header()->hardLinkCount);

			auto ads = record->ads_names();
			ffile->add_item(utils::strings::join_vec(ads, "|"));

			if (std::find(ads.begin(), ads.end(), "Zone.Identifier") != ads.end())
			{
				std::shared_ptr<utils::dfir::ZoneIdentifier> zi = std::make_shared<utils::dfir::ZoneIdentifier>(record->data("Zone.Identifier"));
				ffile->add_item(zi->get_value("ZoneId"));
				ffile->add_item(zi->get_value("ReferrerUrl"));
				ffile->add_item(zi->get_value("HostUrl"));
				zi = nullptr;
			}
			else
			{
				ffile->add_item();
				ffile->add_item();
				ffile->add_item();
			}

			ffile->new_line();
		}
		std::cout << "\r[+] Processing data: " << utils::format::size(index * record_size) << "     ";
	}
	else
	{
		std::cout << "[!] Invalid or missing format";
	}

	std::cout << std::endl << "[+] Closing volume" << std::endl;

	return 0;
}

namespace commands
{
	namespace mft
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

							dump_mft(disk, volume, opts, opts->format, opts->output);
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