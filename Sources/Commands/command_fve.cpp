#include <algorithm>
#include <cstdint>
#include <string>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <memory>
#include <stdexcept>
#include <distorm.h>

#include "Drive/disk.h"
#include "Drive/vbr.h"
#include "Bitlocker/bitlocker.h"
#include "options.h"
#include "Utils/utils.h"
#include "Utils/constant_names.h"
#include "Utils/table.h"

void print_bitlocker_fve_block_header(FVE_BLOCK_HEADER fve_bh, unsigned long block_id)
{
	utils::ui::title("FVE Metadata Block #" + std::to_string(block_id) + " Header");

	std::string signature = std::string((char*)fve_bh.signature);
	signature.resize(8);
	std::cout << "Signature             : " << signature << std::endl;
	std::cout << "Size                  : " << fve_bh.size << std::endl;
	std::cout << "Version               : " << fve_bh.version << std::endl;
	std::cout << "Current State         : " << constants::bitlocker::state(fve_bh.curr_state) << " (" << fve_bh.curr_state << ")" << std::endl;
	std::cout << "Next State            : " << constants::bitlocker::state(fve_bh.next_state) << " (" << fve_bh.next_state << ")" << std::endl;
	std::cout << "Encrypted Size        : " << fve_bh.encrypted_volume_size << " (" << utils::format::size(fve_bh.encrypted_volume_size) << ")" << std::endl;
	std::cout << "Convert Size          : " << fve_bh.convert_size << std::endl;
	std::cout << "Backup Sectors        : " << fve_bh.nb_sectors << std::endl;
	std::cout << "FVE Block 1           : " << utils::format::hex(fve_bh.block_header_offsets[0]) << std::endl;
	std::cout << "FVE Block 2           : " << utils::format::hex(fve_bh.block_header_offsets[1]) << std::endl;
	std::cout << "FVE Block 3           : " << utils::format::hex(fve_bh.block_header_offsets[2]) << std::endl;
	std::cout << "Backup Sectors Offset : " << utils::format::hex(fve_bh.backup_sector_offset) << std::endl;
	std::cout << std::endl;
}

void print_bitlocker_fve_header(FVE_HEADER fve_h)
{
	utils::ui::title("FVE Metadata Header");

	std::cout << "Size                  : " << fve_h.size << std::endl;
	std::cout << "Version               : " << fve_h.version << std::endl;
	std::cout << "Header Size           : " << fve_h.header_size << std::endl;
	std::cout << "Copy Size             : " << fve_h.copy_size << std::endl;
	std::cout << "Volume GUID           : " << utils::id::guid_to_string(fve_h.volume_guid) << std::endl;
	std::cout << "Next Counter          : " << fve_h.next_counter << std::endl;
	std::cout << "Algorithm             : " << constants::bitlocker::algorithm(fve_h.algorithm) << " (" << utils::format::hex(fve_h.algorithm) << ")" << std::endl;
	SYSTEMTIME st;
	utils::times::filetime_to_local_systemtime(fve_h.timestamp, &st);
	std::cout << "Timestamp             : " << utils::times::display_systemtime(st) << std::endl;
	std::cout << std::endl;
}

std::vector<std::string> get_fve_entry_values(PFVE_ENTRY entry, const std::string& level = "")
{
	std::vector<std::string> ret;
	switch (entry->value_type)
	{
	case FVE_METADATA_ENTRY_VALUE_TYPE_ERASED:
		ret.push_back("Null");
		break;
	case FVE_METADATA_ENTRY_VALUE_TYPE_KEY:
		ret.push_back("Encryption   : " + constants::bitlocker::algorithm(((PFVE_ENTRY_KEY)entry->data)->encryption_method));
		ret.push_back("Key          : " + utils::format::hex(((PFVE_ENTRY_KEY)entry->data)->key, entry->size - 12, false));
		break;
	case FVE_METADATA_ENTRY_VALUE_TYPE_UNICODE_STRING:
	{
		ret.push_back("String        : " + utils::strings::to_utf8(((PFVE_ENTRY_UNICODE)entry->data)->string));
		break;
	}
	case FVE_METADATA_ENTRY_VALUE_TYPE_STRETCH_KEY:
	{
		ret.push_back("Encryption    : " + constants::bitlocker::algorithm(((PFVE_ENTRY_STRETCH_KEY)entry->data)->encryption_method));
		ret.push_back("MAC           : " + utils::format::hex(((PFVE_ENTRY_STRETCH_KEY)entry->data)->salt, 16, false));

		int sub_entry_size_left = entry->size - 28;
		PFVE_ENTRY psubentry = (PFVE_ENTRY)(((PFVE_ENTRY_STRETCH_KEY)entry->data)->subentries);
		int n = 1;
		while (sub_entry_size_left > 0)
		{
			ret.push_back("");
			ret.push_back("Property #" + level + std::to_string(n) + " - " + constants::bitlocker::fve_value_type(psubentry->value_type) + " - " + std::to_string(psubentry->size));
			ret.push_back("--------");
			for (auto& t : get_fve_entry_values(psubentry, std::to_string(n) + ".")) ret.push_back(t);
			sub_entry_size_left -= psubentry->size;
			psubentry = POINTER_ADD(PFVE_ENTRY, psubentry, psubentry->size);
			n++;
		}

		break;
	}
	case FVE_METADATA_ENTRY_VALUE_TYPE_USE_KEY:
	{
		ret.push_back("Encryption    : " + constants::bitlocker::algorithm(((PFVE_ENTRY_USE_KEY)entry->data)->encryption_method));

		int sub_entry_size_left = entry->size - 12;
		PFVE_ENTRY psubentry = (PFVE_ENTRY)(((PFVE_ENTRY_USE_KEY)entry->data)->subentries);
		int n = 1;
		while (sub_entry_size_left > 0)
		{
			ret.push_back("");
			ret.push_back("Property #" + level + std::to_string(n) + " - " + constants::bitlocker::fve_value_type(psubentry->value_type) + " - " + std::to_string(psubentry->size));
			ret.push_back("--------");
			for (auto& t : get_fve_entry_values(psubentry, std::to_string(n) + ".")) ret.push_back(t);
			sub_entry_size_left -= psubentry->size;
			psubentry = POINTER_ADD(PFVE_ENTRY, psubentry, psubentry->size);
			n++;
		}

		break;
	}
	case FVE_METADATA_ENTRY_VALUE_TYPE_AES_CCM_ENCRYPTED_KEY:
	{
		FILETIME nonce_time = ((PFVE_ENTRY_AES_CCM)entry->data)->nonce_time;
		ULARGE_INTEGER nonce_val = { 0 };
		nonce_val.HighPart = nonce_time.dwHighDateTime;
		nonce_val.LowPart = nonce_time.dwLowDateTime;

		SYSTEMTIME st;
		utils::times::filetime_to_local_systemtime(nonce_time, &st);

		ret.push_back("Nonce as Hex  : " + utils::format::hex(nonce_val.QuadPart, false));
		ret.push_back("Nonce as Time : " + utils::times::display_systemtime(st));
		ret.push_back("Nonce Counter : " + utils::format::hex(((PFVE_ENTRY_AES_CCM)entry->data)->nonce_counter));
		ret.push_back("MAC           : " + utils::format::hex(((PFVE_ENTRY_AES_CCM)entry->data)->mac, 16, false));
		ret.push_back("Key           : " + utils::format::hex(((PFVE_ENTRY_AES_CCM)entry->data)->key, entry->size - 36, false));
		break;
	}
	case FVE_METADATA_ENTRY_VALUE_TYPE_TPM_ENCODED_KEY:
	case FVE_METADATA_ENTRY_VALUE_TYPE_VALIDATION:
		break;
	case FVE_METADATA_ENTRY_VALUE_TYPE_VOLUME_MASTER_KEY:
	{
		GUID key_id = ((PFVE_ENTRY_VMK)entry->data)->key_id;
		FILETIME last_change = ((PFVE_ENTRY_VMK)entry->data)->last_change;
		LARGE_INTEGER last_change_val = { 0 };
		last_change_val.HighPart = last_change.dwHighDateTime;
		last_change_val.LowPart = last_change.dwLowDateTime;

		SYSTEMTIME st;
		utils::times::filetime_to_local_systemtime(last_change, &st);

		ret.push_back("Key ID        : " + utils::id::guid_to_string(key_id));
		ret.push_back("Last Change   : " + utils::times::display_systemtime(st));
		ret.push_back("Protection    : " + constants::bitlocker::fve_key_protection_type(((PFVE_ENTRY_VMK)entry->data)->protection_type));

		int sub_entry_size_left = entry->size - 36;
		PFVE_ENTRY psubentry = (PFVE_ENTRY)(((PFVE_ENTRY_VMK)entry->data)->subentries);
		int n = 1;
		while (sub_entry_size_left > 0)
		{
			ret.push_back("");
			ret.push_back("Property #" + level + std::to_string(n) + " - " + constants::bitlocker::fve_value_type(psubentry->value_type) + " - " + std::to_string(psubentry->size));
			ret.push_back("--------");
			for (auto& t : get_fve_entry_values(psubentry, std::to_string(n) + ".")) ret.push_back(t);
			sub_entry_size_left -= psubentry->size;
			psubentry = POINTER_ADD(PFVE_ENTRY, psubentry, psubentry->size);
			n++;
		}
		break;
	}
	case FVE_METADATA_ENTRY_VALUE_TYPE_EXTERNAL_KEY:

	{
		GUID key_id = ((PFVE_ENTRY_EXTERNAL_KEY)entry->data)->key_id;
		FILETIME last_change = ((PFVE_ENTRY_EXTERNAL_KEY)entry->data)->last_change;
		LARGE_INTEGER last_change_val = { 0 };
		last_change_val.HighPart = last_change.dwHighDateTime;
		last_change_val.LowPart = last_change.dwLowDateTime;

		SYSTEMTIME st;
		utils::times::filetime_to_local_systemtime(last_change, &st);

		ret.push_back("Key ID        : " + utils::id::guid_to_string(key_id));
		ret.push_back("Last Change   : " + utils::times::display_systemtime(st));
		ret.push_back("Key           : " + utils::format::hex(((PFVE_ENTRY_EXTERNAL_KEY)entry->data)->key, entry->size - 32, false));
		break;
	}
	case FVE_METADATA_ENTRY_VALUE_TYPE_UPDATE:
	case FVE_METADATA_ENTRY_VALUE_TYPE_ERROR:
	case FVE_METADATA_ENTRY_VALUE_TYPE_ASYMMETRIC_ENCRYPTION:
	case FVE_METADATA_ENTRY_VALUE_TYPE_EXPORTED_KEY:
	case FVE_METADATA_ENTRY_VALUE_TYPE_PUBLIC_KEY:
		break;
	case FVE_METADATA_ENTRY_VALUE_TYPE_OFFSET_AND_SIZE:
	{
		ret.push_back("Offset        : " + utils::format::hex(((PFVE_ENTRY_OFFSET_SIZE)entry->data)->offset));
		ret.push_back("Size          : " + utils::format::hex(((PFVE_ENTRY_OFFSET_SIZE)entry->data)->size));
		break;
	}
	case FVE_METADATA_ENTRY_VALUE_TYPE_CONCAT_HASH_KEY:
	default:
		ret.push_back("Unknown Value Type (" + std::to_string(entry->value_type) + ")");
	}
	return ret;
}

void print_bitlocker_vbr(std::shared_ptr<Disk> disk, std::shared_ptr<Volume> vol, unsigned long block_id) {
	std::cout << std::setfill('0');
	utils::ui::title("FVE Info from " + disk->name() + " > Volume:" + std::to_string(vol->index()));

	PBOOT_SECTOR_COMMON pbsc = (PBOOT_SECTOR_COMMON)vol->bootsector();
	if (strncmp((char*)pbsc->oemID, "-FVE-FS-", 8) == 0)
	{
		print_bitlocker_fve_block_header(vol->bitlocker().metadata[block_id].block_header, block_id);
		print_bitlocker_fve_header(vol->bitlocker().metadata[block_id].header);

		std::shared_ptr<utils::ui::Table> fve_entries = std::make_shared<utils::ui::Table>();
		fve_entries->set_interline(true);

		fve_entries->add_header_line("Id");
		fve_entries->add_header_line("Version");
		fve_entries->add_header_line("Size");
		fve_entries->add_header_line("Entry Type");
		fve_entries->add_header_line("Value Type");
		fve_entries->add_header_line("Value");

		unsigned int n = 0;
		for (auto& entry : vol->bitlocker().metadata[block_id].entries)
		{
			n++;
			fve_entries->add_item_line(std::to_string(n));
			fve_entries->add_item_line(std::to_string(entry->data()->version));
			fve_entries->add_item_line(std::to_string(entry->data()->size));
			fve_entries->add_item_line(constants::bitlocker::fve_entry_type(entry->data()->entry_type));
			fve_entries->add_item_line(constants::bitlocker::fve_value_type(entry->data()->value_type));

			fve_entries->add_item_multiline(get_fve_entry_values(entry->data()));

			fve_entries->new_line();
		}

		utils::ui::title("FVE Metadata Entries (" + std::to_string(vol->bitlocker().metadata[block_id].entries.size()) + ")");
		fve_entries->render(std::cout);
		std::cout << std::endl;
	}
	else
	{
		std::cout << "[!] Volume is not Bitlocked" << std::endl;
	}
}

namespace commands {
	namespace bitlocker {
		int print_fve(std::shared_ptr<Options> opts)
		{
			std::ios_base::fmtflags flag_backup(std::cout.flags());

			std::shared_ptr<Disk> disk = get_disk(opts);
			if (disk != nullptr)
			{
				std::shared_ptr<Volume> volume = disk->volumes(opts->volume);
				if (volume != nullptr)
				{
					if ((opts->fve_block >= 0) && (opts->fve_block < 3)) print_bitlocker_vbr(disk, volume, opts->fve_block);
					else
					{
						std::cerr << "[!] Invalid FVE block index [0-2]";
						return 1;
					}
				}
			}

			std::cout.flags(flag_backup);
			return 0;
		}
	}
}