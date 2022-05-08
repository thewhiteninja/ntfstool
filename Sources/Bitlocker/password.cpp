#include "Bitlocker/password.h"

#include <openssl/sha.h>
#include <Bitlocker\bitlocker.h>

void bitlocker_prepare_password(std::string password, unsigned char* password_hash)
{
	std::u16string password_utf16_le = utils::strings::str_to_utf16(password);

	utils::crypto::hash::sha256_buffer((PBYTE)password_utf16_le.c_str(), password_utf16_le.size() * 2, password_hash);
	utils::crypto::hash::sha256_buffer(password_hash, 32, password_hash);
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
	bitlocker_decrypt_data(enc_vmk, enc_size, key_buffer, mac_val, nonce, vmk_buffer, 256);
	return bitlocker_mac_check(vmk_buffer, key_buffer, nonce, vmk_buffer + 16, enc_size);
}

void get_vmk_from_password(ULONG64 nonce_time, ULONG32 nonce_ctr, PBYTE mac_val, PBYTE enc_vmk, ULONG32 enc_size, PBYTE salt, const std::string& password, PBYTE vmk, ULONG32 vmk_len)
{
	unsigned char key_buffer[32] = { 0 };

	unsigned char nonce[12] = { 0 };
	*((PULONG64)nonce) = nonce_time;
	*((PULONG32)(nonce + 8)) = nonce_ctr;

	bitlocker_prepare_password(password, key_buffer);
	bitlocker_derive_key(key_buffer, salt, 1048576, key_buffer);
	bitlocker_decrypt_data(enc_vmk, enc_size, key_buffer, mac_val, nonce, vmk, vmk_len);
}
