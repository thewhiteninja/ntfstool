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

	std::cout << "[+] Opening " << (vol->name().empty() ? reinterpret_cast<Disk*>(vol->parent())->name() : vol->name()) << std::endl;

	std::shared_ptr<NTFSExplorer> explorer = std::make_shared<NTFSExplorer>(vol);
	std::shared_ptr<MFTRecord> record = commands::helpers::find_record(explorer, opts);
	auto [filepath, stream_name] = utils::files::split_file_and_stream(opts->from);

	std::cout << "[-] Record Num  : " << record->header()->MFTRecordIndex << " (" << utils::format::hex(record->header()->MFTRecordIndex, true) << ")" << std::endl;

	std::cout << "[-] Destination : " << opts->output << std::endl;

	std::cout << "[+] Writing file" << std::endl;

	ULONG64 written = record->data_to_file(utils::strings::from_string(opts->output), stream_name);

	std::cout << "[+] " << written << " bytes (" + utils::format::size(written) << ") written" << std::endl;

	return 0;
}

namespace commands
{
	namespace extract
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
					if (opts->from == "" && opts->sam)
					{
						opts->from = "c:\\windows\\system32\\config\\sam";
					}
					if (opts->from == "" && opts->system)
					{
						opts->from = "c:\\windows\\system32\\config\\system";
					}
					if (opts->output != "")
					{
						extract_file(disk, volume, opts);
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