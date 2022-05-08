#include "Bitlocker/bitlocker.h"

void bitlocker_derive_key(unsigned char* password_hash, unsigned char* password_salt, unsigned int iterations, unsigned char* key)
{
	FVE_KEY_DATA fkd = { 0 };
	SHA256_CTX ctx = { 0 };
	uint64_t ic = 0;

	memset(&fkd, 0, sizeof(FVE_KEY_DATA));
	memcpy_s(fkd.initial_sha256_hash, 32, password_hash, 32);
	memcpy_s(fkd.salt, 16, password_salt, 16);

	for (ic = 0; ic < iterations; ic++) {
		fkd.iteration_count = ic;
		utils::crypto::hash::sha256_buffer((PBYTE)(&fkd), sizeof(FVE_KEY_DATA), fkd.last_sha256_hash);
	}

	memcpy_s(key, 32, fkd.last_sha256_hash, 32);
}

void bitlocker_decrypt_data(PBYTE encrypted_data, ULONG32 encrypted_data_size, PBYTE key, PBYTE mac, PBYTE nonce, PBYTE decrypted_data, ULONG32 decrypted_data_len)
{
	uint8_t block_data[16];
	uint8_t iv[16];
	size_t data_offset = 0;
	int outLen = 0;

	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	if (ctx)
	{
		EVP_CipherInit(ctx, EVP_aes_256_ecb(), key, NULL, TRUE);

		memset(iv, 0, 16);
		memcpy_s(&(iv[1]), 15, nonce, 12);
		iv[0] = 2;

		memcpy_s(decrypted_data, 16, mac, 16);
		memcpy_s(decrypted_data + 16, decrypted_data_len, encrypted_data, encrypted_data_size);
		encrypted_data_size += 16;

		while ((data_offset + 16) < encrypted_data_size)
		{
			EVP_CipherUpdate(ctx, block_data, &outLen, iv, 16);
			for (size_t block_index = 0; block_index < 16; block_index++)
			{
				decrypted_data[data_offset++] ^= block_data[block_index];
			}
			iv[15] += 1;
		}
		if (data_offset < encrypted_data_size)
		{
			EVP_CipherUpdate(ctx, block_data, &outLen, iv, 16);
			size_t left = encrypted_data_size - data_offset;

			for (size_t block_index = 0; block_index < left; block_index++)
			{
				decrypted_data[data_offset++] ^= block_data[block_index];
			}
		}
		EVP_CIPHER_CTX_free(ctx);
	}
}

bool bitlocker_mac_check(PBYTE clear_mac, PBYTE key, PBYTE nonce, PBYTE data, ULONG32 data_size)
{
	unsigned char iv[16] = { 0 };
	int outLen = 0;

	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	if (ctx)
	{
		EVP_CipherInit(ctx, EVP_aes_256_ecb(), key, NULL, TRUE);

		iv[0] = 0x3a;
		memcpy(iv + 1, nonce, 12);
		*(((PUSHORT)iv) + 7) = _byteswap_ushort((USHORT)(data_size & 0xffff));

		EVP_CipherUpdate(ctx, iv, &outLen, iv, 16);

		while (data_size > 16)
		{
			utils::crypto::xor_buffer(iv, 16, data, 16);
			EVP_CipherUpdate(ctx, iv, &outLen, iv, 16);
			data += 16;
			data_size -= 16;
		}
		if (data_size > 0)
		{
			utils::crypto::xor_buffer(iv, data_size, data, data_size);
			EVP_CipherUpdate(ctx, iv, &outLen, iv, 16);
		}

		EVP_CIPHER_CTX_free(ctx);

		return memcmp(clear_mac, iv, 16) == 0;
	}

	return 1;
}

void get_fvek_from_vmk(ULONG64 nonce_time, ULONG32 nonce_ctr, PBYTE mac_val, PBYTE enc_fvek, ULONG32 enc_size, PBYTE vmk, PBYTE fvek, ULONG32 fvek_len)
{
	unsigned char nonce[12] = { 0 };
	*((PULONG64)nonce) = nonce_time;
	*((PULONG32)(nonce + 8)) = nonce_ctr;

	bitlocker_decrypt_data(enc_fvek, enc_size, vmk, mac_val, nonce, fvek, fvek_len);
}