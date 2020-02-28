
#include <algorithm>
#include <cstdint>
#include <string>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <memory>
#include <stdexcept>
#include <fstream>

#include "disk.h"
#include "vbr.h"
#include "bitlocker.h"
#include "options.h"
#include "Utils/utils.h"
#include "Utils/constant_names.h"
#include "Utils/table.h"

#include "openssl/sha.h"
#include "openssl/aes.h"



void bitlocker_prepare_password(std::string password, unsigned char* password_hash)
{
	std::u16string password_utf16_le = utils::strings::str_to_utf16(password);

	SHA256_CTX ctx = { 0 };
	SHA256_Init(&ctx);
	SHA256_Update(&ctx, password_utf16_le.c_str(), password_utf16_le.size() * 2);
	SHA256_Final(password_hash, &ctx);
	SHA256_Init(&ctx);
	SHA256_Update(&ctx, password_hash, 32);
	SHA256_Final(password_hash, &ctx);
}

void bitlocker_derive_key(unsigned char* password_hash, unsigned char* password_salt, unsigned int iterations, unsigned char* key)
{
	FVE_KEY_DATA fkd = { 0 };
	SHA256_CTX ctx = { 0 };
	uint64_t ic = 0;

	memset(&fkd, 0, sizeof(FVE_KEY_DATA));
	memcpy(fkd.initial_sha256_hash, password_hash, 32);
	memcpy(fkd.salt, password_salt, 16);

	for (ic = 0; ic < iterations; ic++) {
		SHA256_Init(&ctx);
		fkd.iteration_count = ic;
		SHA256_Update(&ctx, &fkd, sizeof(FVE_KEY_DATA));
		SHA256_Final(fkd.last_sha256_hash, &ctx);
	}

	memcpy(key, fkd.last_sha256_hash, 32);

}

void bitlocker_decrypt_data(PBYTE encrypted_data, ULONG32 encrypted_data_size, PBYTE key, PBYTE mac, PBYTE nonce, PBYTE decrypted_data)
{
	uint8_t block_data[16];
	uint8_t iv[16];
	size_t data_offset = 0;
	AES_KEY ctx;

	AES_set_encrypt_key(key, 256, &ctx);

	memset(iv, 0, 16);
	memcpy(&(iv[1]), nonce, 12);
	iv[0] = 2;

	memcpy(decrypted_data, mac, 16);
	memcpy(decrypted_data + 16, encrypted_data, encrypted_data_size);
	encrypted_data_size += 16;

	while ((data_offset + 16) < encrypted_data_size)
	{
		AES_ecb_encrypt(iv, block_data, &ctx, AES_ENCRYPT);
		for (size_t block_index = 0; block_index < 16; block_index++)
		{
			decrypted_data[data_offset++] ^= block_data[block_index];
		}
		iv[15] += 1;
	}
	if (data_offset < encrypted_data_size)
	{
		AES_ecb_encrypt(iv, block_data, &ctx, AES_ENCRYPT);
		size_t left = encrypted_data_size - data_offset;

		for (size_t block_index = 0; block_index < left; block_index++)
		{
			decrypted_data[data_offset++] ^= block_data[block_index];
		}
	}
}

bool bitlocker_check_recovery_key(std::string recovery)
{
	std::vector<std::string> blocks = utils::strings::split(recovery, '-');
	if (blocks.size() != 8) return false;

	for (int b = 0; b < 8; b++)
	{
		if (atol(blocks[b].c_str()) % 11 != 0) return false;
		if (atol(blocks[b].c_str()) > 720896) return false;
		int check = (blocks[b][0] - blocks[b][1] + blocks[b][2] - blocks[b][3] + blocks[b][4] - 48) % 11;
		while (check < 0) check += 11;

		if (check != (blocks[b][5] - 48)) return false;
	}

	return true;
}

void bitlocker_prepare_recovery_key(std::string recovery, unsigned char* recovery_hash)
{
	PUSHORT recovery_hash_tmp = (PUSHORT)recovery_hash;

	ULONG32 blocks[8] = { 0 };

	int ret = sscanf_s(recovery.c_str(), "%6u-%6u-%6u-%6u-%6u-%6u-%6u-%6u", &blocks[0], &blocks[1], &blocks[2], &blocks[3], &blocks[4], &blocks[5], &blocks[6], &blocks[7]);
	if (ret == 8)
	{
		for (int b = 0; b < 8; b++)
		{
			recovery_hash_tmp[b] = (USHORT)(blocks[b] / 11);
		}
	}

	SHA256_CTX ctx = { 0 };
	SHA256_Init(&ctx);
	SHA256_Update(&ctx, recovery_hash, 16);
	SHA256_Final(recovery_hash, &ctx);
}

void xor_buffer(PBYTE a, PBYTE b, int size)
{
	for (int i = 0; i < size; i++)
	{
		a[i] = a[i] ^ b[i];
	}
}

bool bitlocker_mac_check(PBYTE clear_mac, PBYTE key, PBYTE nonce, PBYTE data, ULONG32 data_size)
{
	unsigned char iv[16] = { 0 };
	iv[0] = 0x3a;
	memcpy(iv + 1, nonce, 12);
	*(((PUSHORT)iv) + 7) = _byteswap_ushort((USHORT)(data_size & 0xffff));

	AES_KEY ctx;
	AES_set_encrypt_key(key, 256, &ctx);
	AES_ecb_encrypt(iv, iv, &ctx, AES_ENCRYPT);

	while (data_size > 16)
	{
		xor_buffer(iv, data, 16);
		AES_ecb_encrypt(iv, iv, &ctx, AES_ENCRYPT);
		data += 16;
		data_size -= 16;
	}
	if (data_size > 0)
	{
		xor_buffer(iv, data, data_size);
		AES_ecb_encrypt(iv, iv, &ctx, AES_ENCRYPT);
	}

	return memcmp(clear_mac, iv, 16) == 0;
}

bool test_bitlocker_recovery(ULONG64 nonce_time, ULONG32 nonce_ctr, PBYTE mac_val, PBYTE enc_vmk, ULONG32 enc_size, PBYTE salt, const std::string& recovery)
{
	if (bitlocker_check_recovery_key(recovery))
	{
		unsigned char nonce[12] = { 0 };
		*((PULONG64)nonce) = nonce_time;
		*((PULONG32)(nonce + 8)) = nonce_ctr;

		unsigned char key_buffer[32] = { 0 };

		unsigned char vmk_buffer[256] = { 0 };

		bitlocker_prepare_recovery_key(recovery, key_buffer);
		bitlocker_derive_key(key_buffer, salt, 1048576, key_buffer);
		bitlocker_decrypt_data(enc_vmk, enc_size, key_buffer, mac_val, nonce, vmk_buffer);
		return bitlocker_mac_check(vmk_buffer, key_buffer, nonce, vmk_buffer + 16, enc_size);
	}

	return false;
}

bool test_bitlocker_password(ULONG64 nonce_time, ULONG32 nonce_ctr, PBYTE mac_val, PBYTE enc_vmk, ULONG32 enc_size, PBYTE salt, const std::string& password)
{
	unsigned char key_buffer[32] = { 0 };
	unsigned char vmk_buffer[256] = { 0 };

	unsigned char nonce[12] = { 0 };
	*((PULONG64)nonce) = nonce_time;
	*((PULONG32)(nonce + 8)) = nonce_ctr;

	bitlocker_prepare_password(password, key_buffer);
	bitlocker_derive_key(key_buffer, salt, 1048576, key_buffer);
	bitlocker_decrypt_data(enc_vmk, enc_size, key_buffer, mac_val, nonce, vmk_buffer);
	return bitlocker_mac_check(vmk_buffer, key_buffer, nonce, vmk_buffer + 16, enc_size);
}

std::shared_ptr<Buffer<PBYTE>> read_bek_file(std::wstring filename)
{
	std::shared_ptr<Buffer<PBYTE>> key = nullptr;

	std::shared_ptr<Buffer<PBYTE>> bekfile = Buffer<PBYTE>::from_file(filename);
	PEXTERNAL_KEY_FILE pbek = (PEXTERNAL_KEY_FILE)bekfile->data();
	PFVE_ENTRY entry = POINTER_ADD(PFVE_ENTRY, bekfile->data(), pbek->metadata_header_size);
	if (entry->entry_type == FVE_METADATA_ENTRY_TYPE_STARTUP_KEY && entry->value_type == FVE_METADATA_ENTRY_VALUE_TYPE_EXTERNAL_KEY)
	{
		PFVE_ENTRY_EXTERNAL_KEY pext = (PFVE_ENTRY_EXTERNAL_KEY)entry->data;
		key = std::make_shared<Buffer<PBYTE>>(32);
		memcpy(key->data(), pext->key + 0xc, 32);
	}

	return key;
}

bool test_bitlocker_bek(ULONG64 nonce_time, ULONG32 nonce_ctr, PBYTE mac_val, PBYTE enc_vmk, ULONG32 enc_size, PBYTE salt, std::string bek_file)
{
	std::shared_ptr<Buffer<PBYTE>> bek = read_bek_file(utils::strings::from_string(bek_file));
	if (bek != nullptr)
	{
		unsigned char vmk_buffer[256] = { 0 };
		unsigned char nonce[12] = { 0 };
		*((PULONG64)nonce) = nonce_time;
		*((PULONG32)(nonce + 8)) = nonce_ctr;

		bitlocker_decrypt_data(enc_vmk, enc_size, bek->data(), mac_val, nonce, vmk_buffer);
		return bitlocker_mac_check(vmk_buffer, bek->data(), nonce, vmk_buffer + 16, enc_size);
	}
	return false;
}

void get_vmk_from_bek(ULONG64 nonce_time, ULONG32 nonce_ctr, PBYTE mac_val, PBYTE enc_vmk, ULONG32 enc_size, PBYTE salt, std::string bekfile, PBYTE vmk)
{
	std::shared_ptr<Buffer<PBYTE>> bek = read_bek_file(utils::strings::from_string(bekfile));
	if (bek != nullptr)
	{
		unsigned char nonce[12] = { 0 };
		*((PULONG64)nonce) = nonce_time;
		*((PULONG32)(nonce + 8)) = nonce_ctr;

		bitlocker_decrypt_data(enc_vmk, enc_size, bek->data(), mac_val, nonce, vmk);
	}
}

void get_vmk_from_recovery(ULONG64 nonce_time, ULONG32 nonce_ctr, PBYTE mac_val, PBYTE enc_vmk, ULONG32 enc_size, PBYTE salt, const std::string& recovery, PBYTE vmk)
{
	if (bitlocker_check_recovery_key(recovery))
	{
		unsigned char nonce[12] = { 0 };
		*((PULONG64)nonce) = nonce_time;
		*((PULONG32)(nonce + 8)) = nonce_ctr;

		unsigned char key_buffer[32] = { 0 };

		bitlocker_prepare_recovery_key(recovery, key_buffer);
		bitlocker_derive_key(key_buffer, salt, 1048576, key_buffer);
		bitlocker_decrypt_data(enc_vmk, enc_size, key_buffer, mac_val, nonce, vmk);
	}
}

void get_vmk_from_password(ULONG64 nonce_time, ULONG32 nonce_ctr, PBYTE mac_val, PBYTE enc_vmk, ULONG32 enc_size, PBYTE salt, const std::string& password, PBYTE vmk)
{
	unsigned char key_buffer[32] = { 0 };

	unsigned char nonce[12] = { 0 };
	*((PULONG64)nonce) = nonce_time;
	*((PULONG32)(nonce + 8)) = nonce_ctr;

	bitlocker_prepare_password(password, key_buffer);
	bitlocker_derive_key(key_buffer, salt, 1048576, key_buffer);
	bitlocker_decrypt_data(enc_vmk, enc_size, key_buffer, mac_val, nonce, vmk);
}

void get_fvek_from_vmk(ULONG64 nonce_time, ULONG32 nonce_ctr, PBYTE mac_val, PBYTE enc_fvek, ULONG32 enc_size, PBYTE vmk, PBYTE fvek)
{
	unsigned char nonce[12] = { 0 };
	*((PULONG64)nonce) = nonce_time;
	*((PULONG32)(nonce + 8)) = nonce_ctr;

	bitlocker_decrypt_data(enc_fvek, enc_size, vmk, mac_val, nonce, fvek);
}

void print_test_bitlocker_password(std::shared_ptr<Disk> disk, std::shared_ptr<Volume> vol, std::shared_ptr<Options> opts)
{
	std::cout << std::setfill('0');
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

					bool valid = enc_key && mac_val && test_bitlocker_password(nonce_time, nonce_ctr, mac_val, enc_key, enc_size, salt, opts->password);
					content.push_back(valid ? "Valid" : "Invalid");
					if (valid)
					{
						content.push_back("");

						unsigned char vmk_buffer[256] = { 0 };
						get_vmk_from_password(nonce_time, nonce_ctr, mac_val, enc_key, enc_size, salt, opts->password, vmk_buffer);
						content.push_back("VMK  : " + utils::format::hex(((PFVE_VMK)vmk_buffer)->vmk, 32));

						if (fvek_entry != nullptr)
						{
							unsigned char fvek_buffer[256] = { 0 };

							nonce_time = ULARGE_INTEGER{ ((PFVE_ENTRY_AES_CCM)fvek_entry->data)->nonce_time.dwLowDateTime, ((PFVE_ENTRY_AES_CCM)fvek_entry->data)->nonce_time.dwHighDateTime }.QuadPart;
							nonce_ctr = ((PFVE_ENTRY_AES_CCM)fvek_entry->data)->nonce_counter;
							mac_val = ((PFVE_ENTRY_AES_CCM)fvek_entry->data)->mac;
							enc_key = ((PFVE_ENTRY_AES_CCM)fvek_entry->data)->key;
							enc_size = fvek_entry->size - 36;

							get_fvek_from_vmk(nonce_time, nonce_ctr, mac_val, enc_key, enc_size, ((PFVE_VMK)vmk_buffer)->vmk, fvek_buffer);
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
	std::cout << std::setfill('0');
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
						get_vmk_from_recovery(nonce_time, nonce_ctr, mac_val, enc_key, enc_size, salt, opts->recovery, vmk_buffer);
						content.push_back("VMK  : " + utils::format::hex(((PFVE_VMK)vmk_buffer)->vmk, 32));

						if (fvek_entry != nullptr)
						{
							unsigned char fvek_buffer[256] = { 0 };

							nonce_time = ULARGE_INTEGER{ ((PFVE_ENTRY_AES_CCM)fvek_entry->data)->nonce_time.dwLowDateTime, ((PFVE_ENTRY_AES_CCM)fvek_entry->data)->nonce_time.dwHighDateTime }.QuadPart;
							nonce_ctr = ((PFVE_ENTRY_AES_CCM)fvek_entry->data)->nonce_counter;
							mac_val = ((PFVE_ENTRY_AES_CCM)fvek_entry->data)->mac;
							enc_key = ((PFVE_ENTRY_AES_CCM)fvek_entry->data)->key;
							enc_size = fvek_entry->size - 36;

							get_fvek_from_vmk(nonce_time, nonce_ctr, mac_val, enc_key, enc_size, ((PFVE_VMK)vmk_buffer)->vmk, fvek_buffer);
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
	std::cout << std::setfill('0');
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
						get_vmk_from_bek(nonce_time, nonce_ctr, mac_val, enc_key, enc_size, salt, opts->bek, vmk_buffer);
						content.push_back("VMK  : " + utils::format::hex(((PFVE_VMK)vmk_buffer)->vmk, 32));

						if (fvek_entry != nullptr)
						{
							unsigned char fvek_buffer[256] = { 0 };

							nonce_time = ULARGE_INTEGER{ ((PFVE_ENTRY_AES_CCM)fvek_entry->data)->nonce_time.dwLowDateTime, ((PFVE_ENTRY_AES_CCM)fvek_entry->data)->nonce_time.dwHighDateTime }.QuadPart;
							nonce_ctr = ((PFVE_ENTRY_AES_CCM)fvek_entry->data)->nonce_counter;
							mac_val = ((PFVE_ENTRY_AES_CCM)fvek_entry->data)->mac;
							enc_key = ((PFVE_ENTRY_AES_CCM)fvek_entry->data)->key;
							enc_size = fvek_entry->size - 36;

							get_fvek_from_vmk(nonce_time, nonce_ctr, mac_val, enc_key, enc_size, ((PFVE_VMK)vmk_buffer)->vmk, fvek_buffer);
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

	std::cout << std::setfill('0');
	utils::ui::title("Bitlocker Info from " + disk->name() + " > Volume:" + std::to_string(vol->index()));

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
					table->add_item_line("suce");
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


namespace commands {

	namespace bitlocker {

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
					else
					{
						std::cerr << "[!] Invalid or missing auth method (password, recovery or bek file)";
						return 1;
					}
				}
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
			}

			std::cout.flags(flag_backup);
			return 0;
		}

	}

}