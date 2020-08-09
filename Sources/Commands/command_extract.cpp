
#include "disk.h"
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

	DWORD cluster_size = ((PBOOT_SECTOR_NTFS)vol->bootsector())->bytePerSector * ((PBOOT_SECTOR_NTFS)vol->bootsector())->sectorPerCluster;

	std::cout << "[+] Opening " << vol->name() << std::endl;

	std::shared_ptr<NTFSExplorer> explorer = std::make_shared<NTFSExplorer>(utils::strings::from_string(vol->name()));

	std::shared_ptr<MFTRecord> record = explorer->mft()->record_from_path(opts->from);

	if (record == nullptr)
	{
		std::cout << "[!] Invalid or non-existent path" << std::endl;
		return 2;
	}
	else
	{
		std::cout << "[-] File found in record " << utils::format::hex(record->header()->MFTRecordIndex) << std::endl;
	}

	std::cout << "[-] Source      : " << opts->from << std::endl;
	std::cout << "[-] Destination : " << opts->out << std::endl;

	// Parse input file name (check :ads)
	size_t ads_sep = opts->from.find(':');
	std::string stream_name = "";
	if (ads_sep != std::string::npos)
	{
		stream_name = opts->from.substr(ads_sep + 1);
		opts->from = opts->from.substr(0, ads_sep);
	}

	record->copy_data_to_file(utils::strings::from_string(opts->out), stream_name);

	std::cout << "[+] File extracted (" << record->datasize() << " bytes written)" << std::endl;

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