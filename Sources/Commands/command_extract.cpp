
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

	std::shared_ptr<MFTRecord> record = explorer->mft()->record_from_path(opts->path);

	if (record == nullptr)
	{
		std::cout << "[!] Invalid path" << std::endl;
		return 2;
	}

	auto pattr = record->attribute_header($FILE_NAME);
	if (pattr != nullptr)
	{
		PMFT_RECORD_ATTRIBUTE_FILENAME psubattr = POINTER_ADD(PMFT_RECORD_ATTRIBUTE_FILENAME, pattr, pattr->Form.Resident.ValueOffset);
		auto name = std::wstring(psubattr->Name);
		name.resize(psubattr->NameLength);

		std::cout << "[+] Extracting ";
		std::wcout << name;
		std::cout << " to " << opts->out << std::endl;

		std::wstring output(opts->out.begin(), opts->out.end());
		record->copy_data_to_file(output);

		std::cout << "[+] " << record->datasize() << " bytes written" << std::endl;
	}

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
					if (opts->path != "")
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
						std::cerr << "[!] Invalid or missing path file";
						return 1;
					}
				}
			}
			std::cout.flags(flag_backup);
			return 0;
		}
	}

}