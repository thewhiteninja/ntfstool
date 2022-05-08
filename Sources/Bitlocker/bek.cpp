#include "Bitlocker/bek.h"

#include "Utils/buffer.h"
#include "Utils/utils.h"

#include "Bitlocker/bitlocker.h"

bool test_bitlocker_bek(ULONG64 nonce_time, ULONG32 nonce_ctr, PBYTE mac_val, PBYTE enc_vmk, ULONG32 enc_size, PBYTE salt, std::string bek_file)
{
	std::shared_ptr<Buffer<PBYTE>> bek = read_bek_file(utils::strings::from_string(bek_file));
	if (bek != nullptr)
	{
		unsigned char vmk_buffer[256] = { 0 };
		unsigned char nonce[12] = { 0 };
		*((PULONG64)nonce) = nonce_time;
		*((PULONG32)(nonce + 8)) = nonce_ctr;

		bitlocker_decrypt_data(enc_vmk, enc_size, bek->data(), mac_val, nonce, vmk_buffer, 256);
		return bitlocker_mac_check(vmk_buffer, bek->data(), nonce, vmk_buffer + 16, enc_size);
	}
	return false;
}

void get_vmk_from_bek(ULONG64 nonce_time, ULONG32 nonce_ctr, PBYTE mac_val, PBYTE enc_vmk, ULONG32 enc_size, PBYTE salt, std::string bekfile, PBYTE vmk, ULONG32 vmk_len)
{
	std::shared_ptr<Buffer<PBYTE>> bek = read_bek_file(utils::strings::from_string(bekfile));
	if (bek != nullptr)
	{
		unsigned char nonce[12] = { 0 };
		*((PULONG64)nonce) = nonce_time;
		*((PULONG32)(nonce + 8)) = nonce_ctr;

		bitlocker_decrypt_data(enc_vmk, enc_size, bek->data(), mac_val, nonce, vmk, vmk_len);
	}
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