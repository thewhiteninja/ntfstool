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

int list_streams(std::shared_ptr<Disk> disk, std::shared_ptr<Volume> vol, std::shared_ptr<Options> opts)
{
	if (!commands::helpers::is_ntfs(disk, vol)) return 1;

	utils::ui::title("Listing streams for " + disk->name() + " > Volume:" + std::to_string(vol->index()));

	std::cout << "[+] Opening " << (vol->name().empty() ? reinterpret_cast<Disk*>(vol->parent())->name() : vol->name()) << std::endl;

	std::shared_ptr<NTFSExplorer> explorer = std::make_shared<NTFSExplorer>(vol);
	std::shared_ptr<MFTRecord> record = commands::helpers::find_record(explorer, opts);

	std::cout << "[-] Record Num  : " << record->header()->MFTRecordIndex << " (" << utils::format::hex(record->header()->MFTRecordIndex, true) << ")" << std::endl;

	std::vector<std::string> ads_names = record->ads_names();

	if (ads_names.size() > 0)
	{
		std::cout << "[+] Alternate data stream(s):" << std::endl;

		std::shared_ptr<utils::ui::Table> tab = std::make_shared<utils::ui::Table>();
		tab->set_margin_left(4);
		tab->set_interline(false);
		tab->add_header_line("Id", utils::ui::TableAlign::RIGHT);
		tab->add_header_line("Name");
		tab->add_header_line("Size", utils::ui::TableAlign::RIGHT);

		int i = 0;
		for (auto& ads : ads_names)
		{
			tab->add_item_line(std::to_string(i++));
			tab->add_item_line(ads);
			tab->add_item_line(std::to_string(record->datasize(ads)));
			tab->new_line();
		}

		tab->render(std::cout);
	}
	else
	{
		std::cout << "[+] No alternate data stream" << std::endl;
	}

	return 0;
}

namespace commands {
	namespace streams {
		int dispatch(std::shared_ptr<Options> opts)
		{
			std::ios_base::fmtflags flag_backup(std::cout.flags());

			std::shared_ptr<Disk> disk = get_disk(opts);
			if (disk != nullptr)
			{
				std::shared_ptr<Volume> volume = disk->volumes(opts->volume);
				if (volume != nullptr)
				{
					list_streams(disk, volume, opts);
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