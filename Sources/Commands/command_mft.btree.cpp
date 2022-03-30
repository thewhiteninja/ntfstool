#include <iostream>
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




int print_btree_info(std::shared_ptr<Disk> disk, std::shared_ptr<Volume> vol, std::shared_ptr<Options> opts)
{
	if (!commands::helpers::is_ntfs(disk, vol)) return 1;

	std::shared_ptr<NTFSExplorer> explorer = std::make_shared<NTFSExplorer>(vol);
	std::shared_ptr<MFTRecord> record = commands::helpers::find_record(explorer, opts);
	PMFT_RECORD_HEADER record_header = record->header();

	if (!(record_header->flag & MFT_RECORD_IS_DIRECTORY))
	{
		std::cout << "[!] Inode " << std::to_string(record->header()->MFTRecordIndex) << " is not a directory" << std::endl;
		return 3;
	}

	utils::ui::title("B-tree index (inode:" + std::to_string(record->header()->MFTRecordIndex) + ") for " + disk->name() + " > Volume:" + std::to_string(vol->index()));

	std::shared_ptr<utils::ui::Table> fr_attributes = std::make_shared<utils::ui::Table>();
	fr_attributes->set_interline(true);

	fr_attributes->add_header_line("Id");
	fr_attributes->add_header_line("Type");
	fr_attributes->add_header_line("Non-resident");
	fr_attributes->add_header_line("Length");
	fr_attributes->add_header_line("Overview");

	int n = 1;
	PMFT_RECORD_ATTRIBUTE_HEADER pAttribute = POINTER_ADD(PMFT_RECORD_ATTRIBUTE_HEADER, record_header, record_header->attributeOffset);
	while (pAttribute->TypeCode != $END)
	{
		uint64_t raw_address = 0;
		auto raw_offset = reinterpret_cast<uint64_t>(pAttribute) - reinterpret_cast<uint64_t>(record_header);
		if (pAttribute->FormCode == NON_RESIDENT_FORM)
		{
			raw_address = record->raw_address() + raw_offset + pAttribute->Form.Nonresident.MappingPairsOffset;
		}
		else
		{
			raw_address = record->raw_address() + raw_offset + pAttribute->Form.Resident.ValueOffset;
		}

		if (pAttribute->TypeCode == $INDEX_ROOT || pAttribute->TypeCode == $INDEX_ALLOCATION)
		{
			fr_attributes->add_item_line(std::to_string(n++));
			fr_attributes->add_item_multiline(
				{
					constants::disk::mft::file_record_attribute_type(pAttribute->TypeCode),
					"Raw address: " + utils::format::hex6(raw_address, true),
				}
			);
			fr_attributes->add_item_line((pAttribute->FormCode == NON_RESIDENT_FORM ? "True" : "False"));
			if (pAttribute->FormCode == NON_RESIDENT_FORM)
			{
				fr_attributes->add_item_line(std::to_string(pAttribute->Form.Nonresident.ValidDataLength));
			}
			else
			{
				fr_attributes->add_item_line(std::to_string(pAttribute->Form.Resident.ValueLength));
			}
			switch (pAttribute->TypeCode)
			{
			case $INDEX_ROOT:
			{
				PMFT_RECORD_ATTRIBUTE_INDEX_ROOT pattr = nullptr;
				if (pAttribute->FormCode == RESIDENT_FORM)
				{
					pattr = POINTER_ADD(PMFT_RECORD_ATTRIBUTE_INDEX_ROOT, pAttribute, pAttribute->Form.Resident.ValueOffset);
				}
				else
				{
					wprintf(L"Non-resident $INDEX_ROOT is not supported");
				};
				fr_attributes->add_item_multiline(commands::mft::print_attribute_index_root(pattr, record->index()));
				break;
			}
			case $INDEX_ALLOCATION:
			{
				fr_attributes->add_item_multiline(commands::mft::print_attribute_index_allocation(pAttribute, record, explorer->reader()->sizes.cluster_size, record->index()));
				break;
			}
			default:
				break;
			}
			fr_attributes->new_line();
		}

		pAttribute = POINTER_ADD(PMFT_RECORD_ATTRIBUTE_HEADER, pAttribute, pAttribute->RecordLength);
	}
	utils::ui::title("Attributes:");
	fr_attributes->render(std::cout);
	std::cout << std::endl;


	std::shared_ptr<IndexDetails> idx_details = std::make_shared<IndexDetails>(record);
	std::shared_ptr<utils::ui::Table> fr_index = std::make_shared<utils::ui::Table>();

	if (idx_details->is_large())
	{
		utils::ui::title("$INDEX_ALLOCATION entries:");
	}
	else
	{
		utils::ui::title("$INDEX_ROOT entries:");
	}

	fr_index->set_interline(true);

	fr_index->add_header_line("VCN");
	fr_index->add_header_line("Raw address");
	fr_index->add_header_line("Size");
	fr_index->add_header_line("Entries");

	for (const auto& v : idx_details->VCN_info())
	{
		std::vector<std::string> lines;
		if (idx_details->is_large())
		{
			fr_index->add_item_line("0x" + utils::format::hex6(v.first));
			fr_index->add_item_line(utils::format::hex6(std::get<0>(v.second), true));
		}
		else
		{
			fr_index->add_item_line("Resident");
			fr_index->add_item_multiline(
				{
					"Record          : " + utils::format::hex6(record->raw_address(), true),
					"Offset to Index : " + utils::format::hex6(std::get<0>(v.second), true)
				}
			);
		}

		lines.clear();

		fr_index->add_item_line(utils::format::hex6(std::get<1>(v.second), true));
		for (auto& e : std::get<2>(v.second))
		{
			lines.push_back(utils::format::hex6(std::get<0>(e)) + ": " + utils::strings::to_utf8(std::get<1>(e)));
		}
		fr_index->add_item_multiline(lines);

		fr_index->new_line();
	}

	fr_index->render(std::cout);
	std::cout << std::endl;

	if (idx_details->is_large())
	{
		utils::ui::title("B-tree index:");

		idx_details->VCNtree()->print();

		std::cout << std::endl;
	}

	return 0;
}


namespace commands
{
	namespace mft
	{
		namespace btree
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
						if (opts->from != "")
						{
							print_btree_info(disk, volume, opts);
						}
						else
						{
							if (opts->inode >= 0)
							{
								print_btree_info(disk, volume, opts);
							}
							else
							{
								invalid_option(opts, "inode", opts->inode);
							}
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
