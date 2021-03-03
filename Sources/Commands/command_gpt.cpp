
#include "Utils/buffer.h"
#include "Drive/disk.h"
#include "Utils/utils.h"
#include "Utils/table.h"
#include "options.h"
#include "Utils/constant_names.h"

#include <intrin.h>
#include <distorm.h>

#include <algorithm>
#include <cstdint>
#include <string>
#include <iostream>
#include <iomanip>
#include <memory>
#include <stdexcept> 


namespace commands {

	namespace gpt {

		int print_gpt(std::shared_ptr<Options> opts)
		{
			std::ios_base::fmtflags flag_backup(std::cout.flags());

			std::shared_ptr<Disk> disk = get_disk(opts);
			if (disk != nullptr)
			{
				PGPT_HEADER pgpt = disk->gpt();
				if (disk->has_protective_mbr())
				{
					utils::ui::title("GPT from " + disk->name());

					std::vector<GPT_PARTITION_ENTRY> gpt_entries = disk->gpt_entries();

					std::cout << "Signature        : " << pgpt->magic << std::endl;
					std::cout << "Revision         : " << pgpt->revision_high << "." << pgpt->revision_low << std::endl;
					std::cout << "Header Size      : " << pgpt->header_size << std::endl;
					std::cout << "Header CRC32     : " << std::setfill('0') << std::setw(8) << std::hex << _byteswap_ulong(pgpt->header_crc32) << std::endl;
					std::cout << "Reserved         : " << std::setfill('0') << std::setw(8) << std::hex << pgpt->reserved1 << std::endl;
					std::cout << std::dec << std::setw(0);
					std::cout << "Current LBA      : " << pgpt->current_lba << std::endl;
					std::cout << "Backup LBA       : " << pgpt->backup_lba << std::endl;
					std::cout << "First Usable LBA : " << pgpt->first_usable_lba << std::endl;
					std::cout << "Last Usable LBA  : " << pgpt->last_usable_lba << std::endl;
					std::cout << "GUID             : " << utils::id::guid_to_string(pgpt->disk_guid) << std::endl;
					std::cout << "Entry LBA        : " << pgpt->partition_entry_lba << std::endl;
					std::cout << "Entries Num      : " << pgpt->num_partition_entries << std::endl;
					std::cout << "Entries Size     : " << pgpt->sizeof_partition_entry << std::endl;
					std::cout << "Partitions CRC32 : " << std::setfill('0') << std::setw(8) << std::hex << _byteswap_ulong(pgpt->partition_entry_array_crc32) << std::endl;

					std::shared_ptr<utils::ui::Table> partitions = std::make_shared<utils::ui::Table>();

					partitions->add_header_line("Id");
					partitions->add_header_line("Name");
					partitions->add_header_line("GUID");
					partitions->add_header_line("First sector");
					partitions->add_header_line("Last sector");
					partitions->add_header_line("Flags");

					unsigned int n_partitions = 0;
					for (GPT_PARTITION_ENTRY& entry : gpt_entries) {
						n_partitions++;
						partitions->add_item_line(std::to_string(n_partitions));
						partitions->add_item_line(utils::strings::to_utf8(entry.PartitionName));
						partitions->add_item_line(utils::id::guid_to_string(entry.UniquePartitionGUID));
						partitions->add_item_line(std::to_string(entry.StartingLBA));
						partitions->add_item_line(std::to_string(entry.EndingLBA));
						partitions->add_item_line(utils::format::hex(entry.Attributes));
						partitions->new_line();
					}

					std::cout << std::endl << "Partition table  : " << gpt_entries.size() << " entries" << std::endl;
					partitions->render(std::cout);
					std::cout << std::endl;
				}
				else
				{
					std::cerr << "[!] Invalid or non-GPT partition table";
					return 1;
				}
			}

			std::cout.flags(flag_backup);
			return 0;
		}
	}
}