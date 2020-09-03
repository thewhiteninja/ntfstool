
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



int print_reparse(std::shared_ptr<Disk> disk, std::shared_ptr<Volume> vol, const std::string& format, std::string output) {

	if ((vol->filesystem() != "NTFS") && (vol->filesystem() != "Bitlocker"))
	{
		std::cerr << "[!] NTFS volume required" << std::endl;
		return 1;
	}

	utils::ui::title("Reparse points from " + disk->name() + " > Volume:" + std::to_string(vol->index()));

	std::cout << "[+] Opening " << vol->name() << std::endl;

	std::shared_ptr<NTFSExplorer> explorer = std::make_shared<NTFSExplorer>(vol);

	std::cout << "[+] Reading $Extend\\$Reparse" << std::endl;

	std::shared_ptr<MFTRecord> record = explorer->mft()->record_from_path("\\$Extend\\$Reparse");

	auto a = record->index();
	for (auto b : a)
	{
		if (b->type() == MFT_ATTRIBUTE_INDEX_REPARSE)
		{
			std::cout << std::hex << b->record_number() << " " << b->tag() << std::endl;
		}
	}

	std::cout << "[+] Closing volume" << std::endl;

	return 0;
}


namespace commands {

	namespace reparse {

		int print_reparse(std::shared_ptr<Options> opts)
		{
			std::ios_base::fmtflags flag_backup(std::cout.flags());

			std::shared_ptr<Disk> disk = get_disk(opts);
			if (disk != nullptr)
			{
				std::shared_ptr<Volume> volume = disk->volumes(opts->volume);
				if (volume != nullptr)
				{
					if (opts->out == "")
					{
						print_reparse(disk, volume, opts->format, opts->out);
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
