
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


int extract_file(std::shared_ptr<Disk> disk, std::shared_ptr<Volume> vol, std::shared_ptr<Options> opts)
{
	if ((vol->filesystem() != "NTFS") && (vol->filesystem() != "Bitlocker"))
	{
		std::cerr << "[!] NTFS volume required" << std::endl;
		return 1;
	}

	std::cout << std::setfill('0');
	utils::ui::title("Extract file from " + disk->name() + " > Volume:" + std::to_string(vol->index()));

	std::cout << "[+] Opening " << vol->name() << std::endl;

	std::shared_ptr<NTFSExplorer> explorer = std::make_shared<NTFSExplorer>(utils::strings::from_string(vol->name()));

	auto from_file = utils::files::split_file_and_stream(opts->from);
	std::cout << "[-] Source      : " << from_file.first << (from_file.second == "" ? "" : ":" + from_file.second) << std::endl;
	std::cout << "[-] Destination : " << opts->out << std::endl;

	std::shared_ptr<MFTRecord> record = explorer->mft()->record_from_path(from_file.first);
	if (record == nullptr)
	{
		std::cout << "[!] Invalid or non-existent path" << std::endl;
		return 2;
	}
	else
	{
		std::cout << "[-] Record Num  : " << record->header()->MFTRecordIndex << " (" << utils::format::hex(record->header()->MFTRecordIndex, true) << ")" << std::endl;
	}

	record->copy_data_to_file(utils::strings::from_string(opts->out), from_file.second);

	std::cout << "[+] File extracted (" << record->datasize(from_file.second) << " bytes written)" << std::endl;

	return 0;
}

namespace commands {

	namespace extract {

		int extract_file(std::shared_ptr<Options> opts)
		{
			std::ios_base::fmtflags flag_backup(std::cout.flags());

			std::shared_ptr<Disk> disk = get_disk(opts);
			if (disk != nullptr)
			{
				std::shared_ptr<Volume> volume = disk->volumes(opts->volume);
				if (volume != nullptr)
				{
					if (opts->from == "" && opts->sam)
					{
						opts->from = "c:\\windows\\system32\\config\\sam";
					}
					if (opts->from == "" && opts->system)
					{
						opts->from = "c:\\windows\\system32\\config\\system";
					}
					if (opts->from != "")
					{
						if (opts->out != "")
						{
							extract_file(disk, volume, opts);
						}
						else
						{
							std::cerr << "[!] Invalid or missing output file";
							return 1;
						}
					}
					else
					{
						std::cerr << "[!] Invalid or missing from file";
						return 1;
					}
				}
			}
			std::cout.flags(flag_backup);
			return 0;
		}
	}

}