#include "Commands/commands.h"
#include "NTFS/ntfs_explorer.h"
#include <Utils/table.h>
#include <Utils/constant_names.h>
#include "EFS/certificate.h"

int backup_keys(std::shared_ptr<Disk> disk, std::shared_ptr<Volume> vol, std::shared_ptr<Options> opts)
{


	return 0;
}

namespace commands
{
	namespace efs
	{
		namespace backup
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
						backup_keys(disk, volume, opts);
					}
					else
					{
						std::cerr << "[!] Invalid or missing volume option" << std::endl;
						opts->subcommand = "efs.backup";
						commands::help::dispatch(opts);
					}
				}
				else
				{
					std::cerr << "[!] Invalid or missing disk option" << std::endl;
					opts->subcommand = "efs.backup";
					commands::help::dispatch(opts);
				}

				std::cout.flags(flag_backup);
				return 0;
			}
		}
	}
}
