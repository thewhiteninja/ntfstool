
#include <algorithm>
#include <cstdint>
#include <string>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <memory>
#include <stdexcept>
#include <fstream>

#include "Drive/disk.h"
#include "Drive/vbr.h"
#include "Bitlocker/bitlocker.h"
#include "Bitlocker/bek.h"
#include "Bitlocker/password.h"
#include "options.h"
#include "Utils/utils.h"
#include "Utils/constant_names.h"
#include "Utils/table.h"
#include <Bitlocker\recovery.h>
#include "commands.h"
#include <Bitlocker/unprotected.h>

void print_test_bitlocker_unprotected(std::shared_ptr<Disk> disk, std::shared_ptr<Volume> vol, std::shared_ptr<Options> opts)
{
	utils::ui::title("Bitlocker Unprotected Test for " + disk->name() + " > Volume:" + std::to_string(vol->index()));

	PBOOT_SECTOR_COMMON pbsc = (PBOOT_SECTOR_COMMON)vol->bootsector();
	if (strncmp((char*)pbsc->oemID, "-FVE-FS-", 8) == 0)
	{
		std::cout << "FVE Version    : " << vol->bitlocker().metadata[0].block_header.version << std::endl;
		std::cout << "State          : " << constants::bitlocker::state(vol->bitlocker().metadata[0].block_header.curr_state) << std::endl;
		std::cout << "Size           : " << vol->size() << " (" << utils::format::size(vol->size()) << ")" << std::endl;
		std::cout << "Encrypted Size : " << vol->bitlocker().metadata[0].block_header.encrypted_volume_size << " (" << utils::format::size(vol->bitlocker().metadata[0].block_header.encrypted_volume_size) << ")" << std::endl;
		std::cout << "Algorithm      : " << constants::bitlocker::algorithm(vol->bitlocker().metadata[0].header.algorithm) << std::endl;
		SYSTEMTIME st;
		utils::times::filetime_to_local_systemtime(vol->bitlocker().metadata[0].header.timestamp, &st);
		std::cout << "Timestamp      : " << utils::times::display_systemtime(st) << std::endl;
		std::cout << std::endl;

		std::shared_ptr<utils::ui::Table> table = std::make_shared<utils::ui::Table>();
		table->set_interline(true);

		table->add_header_line("Id");
		table->add_header_line("Type");
		table->add_header_line("GUID");
		table->add_header_line("Password");
		table->add_header_line("Result");

		PFVE_ENTRY fvek_entry = nullptr;
		for (auto& entry : vol->bitlocker().metadata[0].entries)
		{
			if (entry->data()->entry_type == FVE_METADATA_ENTRY_TYPE_FKEV && entry->data()->value_type == FVE_METADATA_ENTRY_VALUE_TYPE_AES_CCM_ENCRYPTED_KEY)
			{
				fvek_entry = entry->data();
			}
		}


		unsigned int n = 0;
		for (auto& entry : vol->bitlocker().metadata[0].entries)
		{
			if (entry->data()->entry_type == FVE_METADATA_ENTRY_TYPE_VMK && entry->data()->value_type == FVE_METADATA_ENTRY_VALUE_TYPE_VOLUME_MASTER_KEY)
			{
				n++;
				if (((PFVE_ENTRY_VMK)entry->data()->data)->protection_type == FVE_METADATA_KEY_PROTECTION_TYPE_CLEARTEXT)
				{
					table->add_item_line(std::to_string(n));
					table->add_item_line(constants::bitlocker::fve_key_protection_type(((PFVE_ENTRY_VMK)entry->data()->data)->protection_type));
					table->add_item_line(utils::id::guid_to_string(((PFVE_ENTRY_VMK)entry->data()->data)->key_id));

					ULONG64 nonce_time = 0;
					ULONG32 nonce_ctr = 0;
					ULONG32 enc_size = 0;
					BYTE* mac_val = NULL;
					BYTE* enc_key = NULL;
					BYTE unprotected_key[32] = { 0 };

					int sub_entry_size_left = entry->data()->size - 36;
					PFVE_ENTRY psubentry = (PFVE_ENTRY)(((PFVE_ENTRY_VMK)entry->data()->data)->subentries);
					while (sub_entry_size_left > 0)
					{
						if (psubentry->value_type == FVE_METADATA_ENTRY_VALUE_TYPE_AES_CCM_ENCRYPTED_KEY)
						{
							nonce_time = ULARGE_INTEGER{ ((PFVE_ENTRY_AES_CCM)psubentry->data)->nonce_time.dwLowDateTime, ((PFVE_ENTRY_AES_CCM)psubentry->data)->nonce_time.dwHighDateTime }.QuadPart;
							nonce_ctr = ((PFVE_ENTRY_AES_CCM)psubentry->data)->nonce_counter;
							mac_val = ((PFVE_ENTRY_AES_CCM)psubentry->data)->mac;
							enc_key = ((PFVE_ENTRY_AES_CCM)psubentry->data)->key;
							enc_size = psubentry->size - 36;
							break;
						}
						else if (psubentry->value_type == FVE_METADATA_ENTRY_VALUE_TYPE_KEY)
						{
							memcpy_s(unprotected_key, 32, ((PFVE_ENTRY_KEY)psubentry->data)->key, psubentry->size - 12);
						}
						sub_entry_size_left -= psubentry->size;
						psubentry = POINTER_ADD(PFVE_ENTRY, psubentry, psubentry->size);
					}

					table->add_item_line("**unprotected**");

					std::vector<std::string> content;

					content.push_back("Ok");

					content.push_back("");

					unsigned char vmk_buffer[256] = { 0 };
					get_vmk_from_unprotected_key(nonce_time, nonce_ctr, mac_val, enc_key, enc_size, unprotected_key, vmk_buffer, 256);
					content.push_back("VMK  : " + utils::format::hex(((PFVE_VMK)vmk_buffer)->vmk, 32));

					if (fvek_entry != nullptr)
					{
						unsigned char fvek_buffer[256] = { 0 };

						nonce_time = ULARGE_INTEGER{ ((PFVE_ENTRY_AES_CCM)fvek_entry->data)->nonce_time.dwLowDateTime, ((PFVE_ENTRY_AES_CCM)fvek_entry->data)->nonce_time.dwHighDateTime }.QuadPart;
						nonce_ctr = ((PFVE_ENTRY_AES_CCM)fvek_entry->data)->nonce_counter;
						mac_val = ((PFVE_ENTRY_AES_CCM)fvek_entry->data)->mac;
						enc_key = ((PFVE_ENTRY_AES_CCM)fvek_entry->data)->key;
						enc_size = fvek_entry->size - 36;

						get_fvek_from_vmk(nonce_time, nonce_ctr, mac_val, enc_key, enc_size, ((PFVE_VMK)vmk_buffer)->vmk, fvek_buffer, 256);
						content.push_back("FVEK : " + utils::format::hex(((PFVE_FVEK)fvek_buffer)->fvek, ((PFVE_FVEK)fvek_buffer)->size - 0xc));
					}

					table->add_item_multiline(content);

					table->new_line();
				}
			}
		}

		utils::ui::title("Tested with unprotected key:");
		table->render(std::cout);
		std::cout << std::endl;
	}
	else
	{
		std::cout << "[!] Volume is not Bitlocked" << std::endl;
	}
}

void print_test_bitlocker_password(std::shared_ptr<Disk> disk, std::shared_ptr<Volume> vol, std::shared_ptr<Options> opts)
{
	utils::ui::title("Bitlocker Password Test for " + disk->name() + " > Volume:" + std::to_string(vol->index()));

	PBOOT_SECTOR_COMMON pbsc = (PBOOT_SECTOR_COMMON)vol->bootsector();
	if (strncmp((char*)pbsc->oemID, "-FVE-FS-", 8) == 0)
	{
		std::cout << "FVE Version    : " << vol->bitlocker().metadata[0].block_header.version << std::endl;
		std::cout << "State          : " << constants::bitlocker::state(vol->bitlocker().metadata[0].block_header.curr_state) << std::endl;
		std::cout << "Size           : " << vol->size() << " (" << utils::format::size(vol->size()) << ")" << std::endl;
		std::cout << "Encrypted Size : " << vol->bitlocker().metadata[0].block_header.encrypted_volume_size << " (" << utils::format::size(vol->bitlocker().metadata[0].block_header.encrypted_volume_size) << ")" << std::endl;
		std::cout << "Algorithm      : " << constants::bitlocker::algorithm(vol->bitlocker().metadata[0].header.algorithm) << std::endl;
		SYSTEMTIME st;
		utils::times::filetime_to_local_systemtime(vol->bitlocker().metadata[0].header.timestamp, &st);
		std::cout << "Timestamp      : " << utils::times::display_systemtime(st) << std::endl;
		std::cout << std::endl;

		std::shared_ptr<utils::ui::Table> table = std::make_shared<utils::ui::Table>();
		table->set_interline(true);

		table->add_header_line("Id");
		table->add_header_line("Type");
		table->add_header_line("GUID");
		table->add_header_line("Password");
		table->add_header_line("Result");

		PFVE_ENTRY fvek_entry = nullptr;
		for (auto& entry : vol->bitlocker().metadata[0].entries)
		{
			if (entry->data()->entry_type == FVE_METADATA_ENTRY_TYPE_FKEV && entry->data()->value_type == FVE_METADATA_ENTRY_VALUE_TYPE_AES_CCM_ENCRYPTED_KEY)
			{
				fvek_entry = entry->data();
			}
		}

		unsigned int n = 0;
		for (auto& entry : vol->bitlocker().metadata[0].entries)
		{
			if (entry->data()->entry_type == FVE_METADATA_ENTRY_TYPE_VMK && entry->data()->value_type == FVE_METADATA_ENTRY_VALUE_TYPE_VOLUME_MASTER_KEY)
			{
				n++;
				if (((PFVE_ENTRY_VMK)entry->data()->data)->protection_type == FVE_METADATA_KEY_PROTECTION_TYPE_PASSWORD)
				{
					table->add_item_line(std::to_string(n));
					table->add_item_line(constants::bitlocker::fve_key_protection_type(((PFVE_ENTRY_VMK)entry->data()->data)->protection_type));
					table->add_item_line(utils::id::guid_to_string(((PFVE_ENTRY_VMK)entry->data()->data)->key_id));

					ULONG64 nonce_time = 0;
					ULONG32 nonce_ctr = 0;
					ULONG32 enc_size = 0;
					BYTE* salt = NULL;
					BYTE* mac_val = NULL;
					BYTE* enc_key = NULL;

					int sub_entry_size_left = entry->data()->size - 36;
					PFVE_ENTRY psubentry = (PFVE_ENTRY)(((PFVE_ENTRY_VMK)entry->data()->data)->subentries);
					while (sub_entry_size_left > 0)
					{
						if (psubentry->value_type == FVE_METADATA_ENTRY_VALUE_TYPE_AES_CCM_ENCRYPTED_KEY)
						{
							nonce_time = ULARGE_INTEGER{ ((PFVE_ENTRY_AES_CCM)psubentry->data)->nonce_time.dwLowDateTime, ((PFVE_ENTRY_AES_CCM)psubentry->data)->nonce_time.dwHighDateTime }.QuadPart;
							nonce_ctr = ((PFVE_ENTRY_AES_CCM)psubentry->data)->nonce_counter;
							mac_val = ((PFVE_ENTRY_AES_CCM)psubentry->data)->mac;
							enc_key = ((PFVE_ENTRY_AES_CCM)psubentry->data)->key;
							enc_size = psubentry->size - 36;
							break;
						}
						if (psubentry->value_type == FVE_METADATA_ENTRY_VALUE_TYPE_STRETCH_KEY)
						{
							salt = ((PFVE_ENTRY_STRETCH_KEY)psubentry->data)->salt;
						}
						sub_entry_size_left -= psubentry->size;
						psubentry = POINTER_ADD(PFVE_ENTRY, psubentry, psubentry->size);
					}

					table->add_item_line(opts->password);

					std::vector<std::string> content;

					bool valid = enc_key && mac_val && salt && test_bitlocker_password(nonce_time, nonce_ctr, mac_val, enc_key, enc_size, salt, opts->password);
					content.push_back(valid ? "Valid" : "Invalid");
					if (valid)
					{
						content.push_back("");

						unsigned char vmk_buffer[256] = { 0 };
						get_vmk_from_password(nonce_time, nonce_ctr, mac_val, enc_key, enc_size, salt, opts->password, vmk_buffer, 256);
						content.push_back("VMK  : " + utils::format::hex(((PFVE_VMK)vmk_buffer)->vmk, 32));

						if (fvek_entry != nullptr)
						{
							unsigned char fvek_buffer[256] = { 0 };

							nonce_time = ULARGE_INTEGER{ ((PFVE_ENTRY_AES_CCM)fvek_entry->data)->nonce_time.dwLowDateTime, ((PFVE_ENTRY_AES_CCM)fvek_entry->data)->nonce_time.dwHighDateTime }.QuadPart;
							nonce_ctr = ((PFVE_ENTRY_AES_CCM)fvek_entry->data)->nonce_counter;
							mac_val = ((PFVE_ENTRY_AES_CCM)fvek_entry->data)->mac;
							enc_key = ((PFVE_ENTRY_AES_CCM)fvek_entry->data)->key;
							enc_size = fvek_entry->size - 36;

							get_fvek_from_vmk(nonce_time, nonce_ctr, mac_val, enc_key, enc_size, ((PFVE_VMK)vmk_buffer)->vmk, fvek_buffer, 256);
							content.push_back("FVEK : " + utils::format::hex(((PFVE_FVEK)fvek_buffer)->fvek, ((PFVE_FVEK)fvek_buffer)->size - 0xc));
						}
					}

					table->add_item_multiline(content);

					table->new_line();
				}
			}
		}

		utils::ui::title("Tested Password:");
		table->render(std::cout);
		std::cout << std::endl;
	}
	else
	{
		std::cout << "[!] Volume is not Bitlocked" << std::endl;
	}
}

void print_test_bitlocker_recovery(std::shared_ptr<Disk> disk, std::shared_ptr<Volume> vol, std::shared_ptr<Options> opts)
{
	utils::ui::title("Bitlocker Recovery Key Test for " + disk->name() + " > Volume:" + std::to_string(vol->index()));

	PBOOT_SECTOR_COMMON pbsc = (PBOOT_SECTOR_COMMON)vol->bootsector();
	if (strncmp((char*)pbsc->oemID, "-FVE-FS-", 8) == 0)
	{
		std::cout << "FVE Version    : " << vol->bitlocker().metadata[0].block_header.version << std::endl;
		std::cout << "State          : " << constants::bitlocker::state(vol->bitlocker().metadata[0].block_header.curr_state) << std::endl;
		std::cout << "Size           : " << vol->size() << " (" << utils::format::size(vol->size()) << ")" << std::endl;
		std::cout << "Encrypted Size : " << vol->bitlocker().metadata[0].block_header.encrypted_volume_size << " (" << utils::format::size(vol->bitlocker().metadata[0].block_header.encrypted_volume_size) << ")" << std::endl;
		std::cout << "Algorithm      : " << constants::bitlocker::algorithm(vol->bitlocker().metadata[0].header.algorithm) << std::endl;
		SYSTEMTIME st;
		utils::times::filetime_to_local_systemtime(vol->bitlocker().metadata[0].header.timestamp, &st);
		std::cout << "Timestamp      : " << utils::times::display_systemtime(st) << std::endl;
		std::cout << std::endl;

		std::shared_ptr<utils::ui::Table> table = std::make_shared<utils::ui::Table>();
		table->set_interline(true);

		PFVE_ENTRY fvek_entry = nullptr;
		for (auto& entry : vol->bitlocker().metadata[0].entries)
		{
			if (entry->data()->entry_type == FVE_METADATA_ENTRY_TYPE_FKEV && entry->data()->value_type == FVE_METADATA_ENTRY_VALUE_TYPE_AES_CCM_ENCRYPTED_KEY)
			{
				fvek_entry = entry->data();
			}
		}

		table->add_header_line("Id");
		table->add_header_line("Type");
		table->add_header_line("GUID");
		table->add_header_line("Recovery Key");
		table->add_header_line("Result");

		unsigned int n = 0;
		for (auto& entry : vol->bitlocker().metadata[0].entries)
		{
			if (entry->data()->entry_type == FVE_METADATA_ENTRY_TYPE_VMK && entry->data()->value_type == FVE_METADATA_ENTRY_VALUE_TYPE_VOLUME_MASTER_KEY)
			{
				n++;
				if (((PFVE_ENTRY_VMK)entry->data()->data)->protection_type == FVE_METADATA_KEY_PROTECTION_TYPE_RECOVERY_PASSWORD)
				{
					table->add_item_line(std::to_string(n));
					table->add_item_line(constants::bitlocker::fve_key_protection_type(((PFVE_ENTRY_VMK)entry->data()->data)->protection_type));
					table->add_item_line(utils::id::guid_to_string(((PFVE_ENTRY_VMK)entry->data()->data)->key_id));

					ULONG64 nonce_time = 0;
					ULONG32 nonce_ctr = 0;
					ULONG32 enc_size = 0;
					BYTE* salt = nullptr;
					BYTE* mac_val = nullptr;
					BYTE* enc_key = nullptr;

					int sub_entry_size_left = entry->data()->size - 36;
					PFVE_ENTRY psubentry = (PFVE_ENTRY)(((PFVE_ENTRY_VMK)entry->data()->data)->subentries);
					while (sub_entry_size_left > 0)
					{
						if (psubentry->value_type == FVE_METADATA_ENTRY_VALUE_TYPE_AES_CCM_ENCRYPTED_KEY)
						{
							nonce_time = ULARGE_INTEGER{ ((PFVE_ENTRY_AES_CCM)psubentry->data)->nonce_time.dwLowDateTime, ((PFVE_ENTRY_AES_CCM)psubentry->data)->nonce_time.dwHighDateTime }.QuadPart;
							nonce_ctr = ((PFVE_ENTRY_AES_CCM)psubentry->data)->nonce_counter;
							mac_val = ((PFVE_ENTRY_AES_CCM)psubentry->data)->mac;
							enc_key = ((PFVE_ENTRY_AES_CCM)psubentry->data)->key;
							enc_size = psubentry->size - 36;
							break;
						}
						if (psubentry->value_type == FVE_METADATA_ENTRY_VALUE_TYPE_STRETCH_KEY)
						{
							salt = ((PFVE_ENTRY_STRETCH_KEY)psubentry->data)->salt;
						}
						sub_entry_size_left -= psubentry->size;
						psubentry = POINTER_ADD(PFVE_ENTRY, psubentry, psubentry->size);
					}

					table->add_item_line(opts->recovery);

					std::vector<std::string> content;

					bool valid = mac_val && enc_key && test_bitlocker_recovery(nonce_time, nonce_ctr, mac_val, enc_key, enc_size, salt, opts->recovery);
					content.push_back(valid ? "Valid" : "Invalid");
					if (valid)
					{
						content.push_back("");

						unsigned char vmk_buffer[256] = { 0 };
						get_vmk_from_recovery(nonce_time, nonce_ctr, mac_val, enc_key, enc_size, salt, opts->recovery, vmk_buffer, 256);
						content.push_back("VMK  : " + utils::format::hex(((PFVE_VMK)vmk_buffer)->vmk, 32));

						if (fvek_entry != nullptr)
						{
							unsigned char fvek_buffer[256] = { 0 };

							nonce_time = ULARGE_INTEGER{ ((PFVE_ENTRY_AES_CCM)fvek_entry->data)->nonce_time.dwLowDateTime, ((PFVE_ENTRY_AES_CCM)fvek_entry->data)->nonce_time.dwHighDateTime }.QuadPart;
							nonce_ctr = ((PFVE_ENTRY_AES_CCM)fvek_entry->data)->nonce_counter;
							mac_val = ((PFVE_ENTRY_AES_CCM)fvek_entry->data)->mac;
							enc_key = ((PFVE_ENTRY_AES_CCM)fvek_entry->data)->key;
							enc_size = fvek_entry->size - 36;

							get_fvek_from_vmk(nonce_time, nonce_ctr, mac_val, enc_key, enc_size, ((PFVE_VMK)vmk_buffer)->vmk, fvek_buffer, 256);
							content.push_back("FVEK : " + utils::format::hex(((PFVE_FVEK)fvek_buffer)->fvek, ((PFVE_FVEK)fvek_buffer)->size - 0xc));
						}
					}

					table->add_item_multiline(content);

					table->new_line();
				}
			}
		}

		utils::ui::title("Tested Recovery Key:");
		table->render(std::cout);
		std::cout << std::endl;
	}
	else
	{
		std::cout << "[!] Volume is not Bitlocked" << std::endl;
	}
}

void print_test_bitlocker_bek(std::shared_ptr<Disk> disk, std::shared_ptr<Volume> vol, std::shared_ptr<Options> opts)
{
	utils::ui::title("Bitlocker Encryption Key Test for " + disk->name() + " > Volume:" + std::to_string(vol->index()));

	PBOOT_SECTOR_COMMON pbsc = (PBOOT_SECTOR_COMMON)vol->bootsector();
	if (strncmp((char*)pbsc->oemID, "-FVE-FS-", 8) == 0)
	{
		std::cout << "FVE Version    : " << vol->bitlocker().metadata[0].block_header.version << std::endl;
		std::cout << "State          : " << constants::bitlocker::state(vol->bitlocker().metadata[0].block_header.curr_state) << std::endl;
		std::cout << "Size           : " << vol->size() << " (" << utils::format::size(vol->size()) << ")" << std::endl;
		std::cout << "Encrypted Size : " << vol->bitlocker().metadata[0].block_header.encrypted_volume_size << " (" << utils::format::size(vol->bitlocker().metadata[0].block_header.encrypted_volume_size) << ")" << std::endl;
		std::cout << "Algorithm      : " << constants::bitlocker::algorithm(vol->bitlocker().metadata[0].header.algorithm) << std::endl;
		SYSTEMTIME st;
		utils::times::filetime_to_local_systemtime(vol->bitlocker().metadata[0].header.timestamp, &st);
		std::cout << "Timestamp      : " << utils::times::display_systemtime(st) << std::endl;
		std::cout << std::endl;

		std::shared_ptr<utils::ui::Table> table = std::make_shared<utils::ui::Table>();
		table->set_interline(true);

		PFVE_ENTRY fvek_entry = nullptr;
		for (auto& entry : vol->bitlocker().metadata[0].entries)
		{
			if (entry->data()->entry_type == FVE_METADATA_ENTRY_TYPE_FKEV && entry->data()->value_type == FVE_METADATA_ENTRY_VALUE_TYPE_AES_CCM_ENCRYPTED_KEY)
			{
				fvek_entry = entry->data();
			}
		}

		table->add_header_line("Id");
		table->add_header_line("Type");
		table->add_header_line("GUID");
		table->add_header_line("BEK File");
		table->add_header_line("Result");

		unsigned int n = 0;
		for (auto& entry : vol->bitlocker().metadata[0].entries)
		{
			if (entry->data()->entry_type == FVE_METADATA_ENTRY_TYPE_VMK && entry->data()->value_type == FVE_METADATA_ENTRY_VALUE_TYPE_VOLUME_MASTER_KEY)
			{
				n++;
				if (((PFVE_ENTRY_VMK)entry->data()->data)->protection_type == FVE_METADATA_KEY_PROTECTION_TYPE_STARTUP_KEY)
				{
					table->add_item_line(std::to_string(n));
					table->add_item_line(constants::bitlocker::fve_key_protection_type(((PFVE_ENTRY_VMK)entry->data()->data)->protection_type));
					table->add_item_line(utils::id::guid_to_string(((PFVE_ENTRY_VMK)entry->data()->data)->key_id));

					ULONG64 nonce_time = 0;
					ULONG32 nonce_ctr = 0;
					ULONG32 enc_size = 0;
					BYTE* salt = NULL;
					BYTE* mac_val = NULL;
					BYTE* enc_key = NULL;

					int sub_entry_size_left = entry->data()->size - 36;
					PFVE_ENTRY psubentry = (PFVE_ENTRY)(((PFVE_ENTRY_VMK)entry->data()->data)->subentries);
					while (sub_entry_size_left > 0)
					{
						if (psubentry->value_type == FVE_METADATA_ENTRY_VALUE_TYPE_AES_CCM_ENCRYPTED_KEY)
						{
							nonce_time = ULARGE_INTEGER{ ((PFVE_ENTRY_AES_CCM)psubentry->data)->nonce_time.dwLowDateTime, ((PFVE_ENTRY_AES_CCM)psubentry->data)->nonce_time.dwHighDateTime }.QuadPart;
							nonce_ctr = ((PFVE_ENTRY_AES_CCM)psubentry->data)->nonce_counter;
							mac_val = ((PFVE_ENTRY_AES_CCM)psubentry->data)->mac;
							enc_key = ((PFVE_ENTRY_AES_CCM)psubentry->data)->key;
							enc_size = psubentry->size - 36;
							break;
						}
						if (psubentry->value_type == FVE_METADATA_ENTRY_VALUE_TYPE_STRETCH_KEY)
						{
							salt = ((PFVE_ENTRY_STRETCH_KEY)psubentry->data)->salt;
						}
						sub_entry_size_left -= psubentry->size;
						psubentry = POINTER_ADD(PFVE_ENTRY, psubentry, psubentry->size);
					}

					table->add_item_line(utils::files::basename(opts->bek));

					std::vector<std::string> content;

					bool valid = mac_val && enc_key && test_bitlocker_bek(nonce_time, nonce_ctr, mac_val, enc_key, enc_size, salt, opts->bek);
					content.push_back(valid ? "Valid" : "Invalid");
					if (valid)
					{
						content.push_back("");

						unsigned char vmk_buffer[256] = { 0 };
						get_vmk_from_bek(nonce_time, nonce_ctr, mac_val, enc_key, enc_size, salt, opts->bek, vmk_buffer, 256);
						content.push_back("VMK  : " + utils::format::hex(((PFVE_VMK)vmk_buffer)->vmk, 32));

						if (fvek_entry != nullptr)
						{
							unsigned char fvek_buffer[256] = { 0 };

							nonce_time = ULARGE_INTEGER{ ((PFVE_ENTRY_AES_CCM)fvek_entry->data)->nonce_time.dwLowDateTime, ((PFVE_ENTRY_AES_CCM)fvek_entry->data)->nonce_time.dwHighDateTime }.QuadPart;
							nonce_ctr = ((PFVE_ENTRY_AES_CCM)fvek_entry->data)->nonce_counter;
							mac_val = ((PFVE_ENTRY_AES_CCM)fvek_entry->data)->mac;
							enc_key = ((PFVE_ENTRY_AES_CCM)fvek_entry->data)->key;
							enc_size = fvek_entry->size - 36;

							get_fvek_from_vmk(nonce_time, nonce_ctr, mac_val, enc_key, enc_size, ((PFVE_VMK)vmk_buffer)->vmk, fvek_buffer, 256);
							content.push_back("FVEK : " + utils::format::hex(((PFVE_FVEK)fvek_buffer)->fvek, ((PFVE_FVEK)fvek_buffer)->size - 0xc));
						}
					}

					table->add_item_multiline(content);

					table->new_line();
				}
			}
		}

		utils::ui::title("Tested BEK File:");
		table->render(std::cout);
		std::cout << std::endl;
	}
	else
	{
		std::cout << "[!] Volume is not Bitlocked" << std::endl;
	}
}

void print_bitlocker_info(std::shared_ptr<Disk> disk, std::shared_ptr<Volume> vol) {

	utils::ui::title("Bitlocker Info for " + disk->name() + " > Volume:" + std::to_string(vol->index()));

	PBOOT_SECTOR_COMMON pbsc = (PBOOT_SECTOR_COMMON)vol->bootsector();
	if (strncmp((char*)pbsc->oemID, "-FVE-FS-", 8) == 0)
	{
		std::cout << "FVE Version    : " << vol->bitlocker().metadata[0].block_header.version << std::endl;
		std::cout << "State          : " << constants::bitlocker::state(vol->bitlocker().metadata[0].block_header.curr_state) << std::endl;
		std::cout << "Size           : " << vol->size() << " (" << utils::format::size(vol->size()) << ")" << std::endl;
		std::cout << "Encrypted Size : " << vol->bitlocker().metadata[0].block_header.encrypted_volume_size << " (" << utils::format::size(vol->bitlocker().metadata[0].block_header.encrypted_volume_size) << ")" << std::endl;
		std::cout << "Algorithm      : " << constants::bitlocker::algorithm(vol->bitlocker().metadata[0].header.algorithm) << std::endl;
		SYSTEMTIME st;
		utils::times::filetime_to_local_systemtime(vol->bitlocker().metadata[0].header.timestamp, &st);
		std::cout << "Timestamp      : " << utils::times::display_systemtime(st) << std::endl;
		std::cout << std::endl;

		std::shared_ptr<utils::ui::Table> table = std::make_shared<utils::ui::Table>();
		table->set_interline(true);

		table->add_header_line("Id");
		table->add_header_line("Type");
		table->add_header_line("GUID");
		table->add_header_line("Details");

		unsigned int n = 0;
		for (auto& entry : vol->bitlocker().metadata[0].entries)
		{
			if (entry->data()->entry_type == FVE_METADATA_ENTRY_TYPE_VMK && entry->data()->value_type == FVE_METADATA_ENTRY_VALUE_TYPE_VOLUME_MASTER_KEY)
			{
				n++;
				table->add_item_line(std::to_string(n));
				table->add_item_line(constants::bitlocker::fve_key_protection_type(((PFVE_ENTRY_VMK)entry->data()->data)->protection_type));
				table->add_item_line(utils::id::guid_to_string(((PFVE_ENTRY_VMK)entry->data()->data)->key_id));

				ULONG64 nonce_val = 0;
				ULONG32 nonce_ctr = 0;
				BYTE* main_mac_val = NULL;
				BYTE* mac_val = NULL;
				BYTE* enc_key = NULL;
				ULONG32 enc_key_size = 0;

				int sub_entry_size_left = entry->data()->size - 36;
				PFVE_ENTRY psubentry = (PFVE_ENTRY)(((PFVE_ENTRY_VMK)entry->data()->data)->subentries);
				int item_required = 2;
				while (sub_entry_size_left > 0)
				{
					if (psubentry->value_type == FVE_METADATA_ENTRY_VALUE_TYPE_AES_CCM_ENCRYPTED_KEY)
					{
						nonce_val = ULARGE_INTEGER{ ((PFVE_ENTRY_AES_CCM)psubentry->data)->nonce_time.dwLowDateTime, ((PFVE_ENTRY_AES_CCM)psubentry->data)->nonce_time.dwHighDateTime }.QuadPart;
						nonce_ctr = ((PFVE_ENTRY_AES_CCM)psubentry->data)->nonce_counter;
						mac_val = ((PFVE_ENTRY_AES_CCM)psubentry->data)->mac;
						enc_key = ((PFVE_ENTRY_AES_CCM)psubentry->data)->key;
						enc_key_size = psubentry->size - 36;
						item_required--;
					}
					if (psubentry->value_type == FVE_METADATA_ENTRY_VALUE_TYPE_STRETCH_KEY)
					{
						main_mac_val = ((PFVE_ENTRY_STRETCH_KEY)psubentry->data)->salt;
						item_required--;
					}
					sub_entry_size_left -= psubentry->size;
					psubentry = POINTER_ADD(PFVE_ENTRY, psubentry, psubentry->size);
				}

				if (item_required == 0)
				{
					table->add_item_multiline(
						{
						"Nonce         : " + utils::format::hex(nonce_val, false) + utils::format::hex(nonce_ctr, false),
						"MAC           : " + utils::format::hex(main_mac_val, 16, false),
						"Encrypted Key : " + utils::format::hex(enc_key, enc_key_size, false),
						"",
						"JtR Hash      : $bitlocker$1$16$" + utils::format::hex(main_mac_val, 16, false) + "$1048576$12$" + utils::format::hex(nonce_val, false, true) + utils::format::hex(nonce_ctr, false, true) + "$60$" + utils::format::hex(mac_val, 16, false) + utils::format::hex(enc_key, enc_key_size, false)
						}
					);
				}
				else
				{
					table->add_item_line("Datasize: " + std::to_string(psubentry->size));
				}
				table->new_line();
			}
		}

		utils::ui::title("Volume Master Keys:");
		table->render(std::cout);
		std::cout << std::endl;
	}
	else
	{
		std::cout << "[!] Volume is not Bitlocked" << std::endl;
	}
}

std::string get_guid_from_volume(std::shared_ptr<Volume> vol)
{
	for (auto& entry : vol->bitlocker().metadata[0].entries)
	{
		if (entry->data()->entry_type == FVE_METADATA_ENTRY_TYPE_VMK && entry->data()->value_type == FVE_METADATA_ENTRY_VALUE_TYPE_VOLUME_MASTER_KEY)
		{
			if ((((PFVE_ENTRY_VMK)entry->data()->data)->protection_type) == FVE_METADATA_KEY_PROTECTION_TYPE_RECOVERY_PASSWORD)
			{
				return utils::id::guid_to_string(((PFVE_ENTRY_VMK)entry->data()->data)->key_id);
			}
		}
	}
	return "Not found";
}

void list_guid_for_all_disks(std::vector<std::shared_ptr<Disk>> disks)
{
	utils::ui::title("Bitlocker Recovery Key GUIDs");

	std::shared_ptr<utils::ui::Table> table = std::make_shared<utils::ui::Table>();
	table->set_interline(true);

	table->add_header_line("Disk Id:Name");
	table->add_header_line("Volume Id:Label");
	table->add_header_line("GUID");

	for (std::shared_ptr<Disk> disk : core::win::disks::list()) {
		for (std::shared_ptr<Volume> volume : disk->volumes()) {
			if (volume->filesystem() == "Bitlocker")
			{
				table->add_item_line(std::to_string(disk->index()) + ": " + disk->product_id());
				table->add_item_line(std::to_string(volume->index()) + ": " + volume->label());
				table->add_item_line(get_guid_from_volume(volume));
				table->new_line();
			}
		}
	}

	table->render(std::cout);
	std::cout << std::endl;
}

int test_password(std::shared_ptr<Options> opts)
{
	std::ios_base::fmtflags flag_backup(std::cout.flags());

	std::shared_ptr<Disk> disk = get_disk(opts);
	if (disk != nullptr)
	{
		std::shared_ptr<Volume> volume = disk->volumes(opts->volume);
		if (volume != nullptr)
		{
			if (opts->password != "") print_test_bitlocker_password(disk, volume, opts);
			else if (opts->recovery != "") print_test_bitlocker_recovery(disk, volume, opts);
			else if (opts->bek != "") print_test_bitlocker_bek(disk, volume, opts);
			else if (opts->unprotected) print_test_bitlocker_unprotected(disk, volume, opts);
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

int print_bitlocker(std::shared_ptr<Options> opts)
{
	std::ios_base::fmtflags flag_backup(std::cout.flags());

	std::shared_ptr<Disk> disk = get_disk(opts);
	if (disk != nullptr)
	{
		std::shared_ptr<Volume> volume = disk->volumes(opts->volume);
		if (volume != nullptr)
		{
			print_bitlocker_info(disk, volume);
		}
		else
		{
			invalid_option(opts, "volume", opts->volume);
		}
	}
	else
	{
		list_guid_for_all_disks(core::win::disks::list());
	}

	std::cout.flags(flag_backup);
	return 0;
}

namespace commands
{
	namespace bitlocker
	{
		namespace info
		{
			int dispatch(std::shared_ptr<Options> opts)
			{
				if (opts->password != "" || opts->recovery != "" || opts->bek != "" || opts->unprotected)
				{
					test_password(opts);
				}
				else
				{
					print_bitlocker(opts);
				}
				return 0;
			}
		}
	}

}
