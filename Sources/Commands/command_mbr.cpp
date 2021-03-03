
#include "Utils/buffer.h"
#include "Drive/disk.h"
#include "Utils/table.h"
#include "Utils/utils.h"
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


void print_mbr(std::shared_ptr<Disk> disk)
{
	utils::ui::title("MBR from " + disk->name());

	PMBR mbr = disk->mbr();

	std::cout << "    Disk signature  : " << utils::format::hex(_byteswap_ulong(mbr->disk_signature)) << std::endl;
	std::cout << "    Reserved bytes  : " << utils::format::hex(_byteswap_ushort(mbr->reserved)) << std::endl;

	std::shared_ptr<utils::ui::Table> partitions = std::make_shared<utils::ui::Table>();
	partitions->set_margin_left(4);

	partitions->add_header_line("Id");
	partitions->add_header_line("Boot");
	partitions->add_header_line("Flags");
	partitions->add_header_line("Filesystem");
	partitions->add_header_line("First sector");
	partitions->add_header_line("Last sector");
	partitions->add_header_line("Offset");
	partitions->add_header_line("Sectors");
	partitions->add_header_line("Size");

	unsigned int n_partitions = 0;
	for (int i = 0; i < 4; i++) {
		if (mbr->partition[i].partition_type != 0)
		{
			n_partitions++;
			partitions->add_item_line(std::to_string(n_partitions));
			partitions->add_item_line((mbr->partition[i].status == 0x80 ? "Yes" : "No"));
			partitions->add_item_line("Principal");
			partitions->add_item_line(constants::disk::mbr_type(mbr->partition[i].partition_type));
			partitions->add_item_line(std::to_string(mbr->partition[i].first_sector.cylinder) + " " + std::to_string(mbr->partition[i].first_sector.head) + " " + std::to_string(mbr->partition[i].first_sector.sector));
			partitions->add_item_line(std::to_string(mbr->partition[i].last_sector.cylinder) + " " + std::to_string(mbr->partition[i].last_sector.head) + " " + std::to_string(mbr->partition[i].last_sector.sector));
			partitions->add_item_line(std::to_string(mbr->partition[i].first_sector_lba));
			partitions->add_item_line(std::to_string(mbr->partition[i].sectors));
			partitions->add_item_line(utils::format::size(static_cast<DWORD64>(mbr->partition[i].sectors) * 512));
			partitions->new_line();
		}
	}
	for (EBR& ebr : disk->ebrs())
	{
		n_partitions++;
		partitions->add_item_line(std::to_string(n_partitions));
		partitions->add_item_line((ebr.partition[0].status == 0x80 ? "Yes" : "No"));
		partitions->add_item_line("Logical");
		partitions->add_item_line(constants::disk::mbr_type(ebr.partition[0].partition_type));
		partitions->add_item_line(std::to_string(ebr.partition[0].first_sector.cylinder) + " " + std::to_string(ebr.partition[0].first_sector.head) + " " + std::to_string(ebr.partition[0].first_sector.sector));
		partitions->add_item_line(std::to_string(ebr.partition[0].last_sector.cylinder) + " " + std::to_string(ebr.partition[0].last_sector.head) + " " + std::to_string(ebr.partition[0].last_sector.sector));
		partitions->add_item_line(std::to_string(ebr.partition[0].first_sector_lba));
		partitions->add_item_line(std::to_string(ebr.partition[0].sectors));
		partitions->add_item_line(utils::format::size(static_cast<DWORD64>(ebr.partition[0].sectors) * LOGICAL_SECTOR_SIZE));
		partitions->new_line();
	}

	std::cout << std::endl << "    Partition table";
	if (disk->has_protective_mbr())
	{
		std::cout << " (Protective MBR)";
	}
	std::cout << " : " << std::endl;
	partitions->render(std::cout);
	std::cout << std::endl;

	std::cout << "    MBR signature  : " << std::setw(4) << std::hex << _byteswap_ushort(mbr->mbr_signature) << std::endl;

	std::cout << std::endl << "    Strings:" << std::endl;
	std::vector<unsigned long> string_offsets;
	for (int i = 0; i < 3; i++) string_offsets.push_back((mbr->code[0x1b5 + i] & 0xff) + 0x100);

	if (std::all_of(string_offsets.begin(), string_offsets.end(), [string_offsets](int x) { return (x & 0xff) == 0; }))
	{
		std::cout << "        No strings found" << std::endl;
	}
	else
	{
		for (auto& offset : string_offsets)
		{
			if ((offset < 0x1b5) && offset > 0)
			{
				std::cout << "        [" << utils::format::hex((BYTE)(offset & 0xff)) << "] : " << std::string((PCHAR)mbr->code + offset) << std::endl;
			}
		}
	}

	unsigned int size_to_disass = min(*std::min_element(string_offsets.begin(), string_offsets.end()), 0x1b4);
	while (mbr->code[size_to_disass] == 0 && size_to_disass > 0) size_to_disass--;

	std::cout << std::endl;

	if (utils::ui::ask_question("    Disassemble Bootstrap Code"))
	{
		if (size_to_disass)
		{
			std::cout << std::endl;
			for (std::string& line : utils::disass::buffer(mbr->code, size_to_disass, Decode16Bits, 0))
			{
				std::cout << "        " << line << std::endl;
			}
		}
		else {
			std::cout << "        Empty code" << std::endl;
		}
	}
}

namespace commands {

	namespace mbr {

		int print_mbr(std::shared_ptr<Options> opts) {
			std::ios_base::fmtflags flag_backup(std::cout.flags());

			std::shared_ptr<Disk> disk = get_disk(opts);

			if (disk != nullptr)
			{
				print_mbr(disk);
			}

			std::cout.flags(flag_backup);
			return 0;
		}
	}
}