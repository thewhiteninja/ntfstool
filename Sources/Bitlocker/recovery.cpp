#include "Bitlocker/recovery.h"
#include <Bitlocker\bitlocker.h>

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

	utils::crypto::hash::sha256_buffer(recovery_hash, 16, recovery_hash);
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
		bitlocker_decrypt_data(enc_vmk, enc_size, key_buffer, mac_val, nonce, vmk_buffer, 256);
		return bitlocker_mac_check(vmk_buffer, key_buffer, nonce, vmk_buffer + 16, enc_size);
	}

	return false;
}

void get_vmk_from_recovery(ULONG64 nonce_time, ULONG32 nonce_ctr, PBYTE mac_val, PBYTE enc_vmk, ULONG32 enc_size, PBYTE salt, const std::string& recovery, PBYTE vmk, ULONG32 vmk_len)
{
	if (bitlocker_check_recovery_key(recovery))
	{
		unsigned char nonce[12] = { 0 };
		*((PULONG64)nonce) = nonce_time;
		*((PULONG32)(nonce + 8)) = nonce_ctr;

		unsigned char key_buffer[32] = { 0 };

		bitlocker_prepare_recovery_key(recovery, key_buffer);
		bitlocker_derive_key(key_buffer, salt, 1048576, key_buffer);
		bitlocker_decrypt_data(enc_vmk, enc_size, key_buffer, mac_val, nonce, vmk, vmk_len);
	}
}