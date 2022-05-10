#include "Bitlocker/decryption.h"

#include "Utils/utils.h"

#pragma comment(lib, "gdi32")
#pragma comment(lib, "crypt32")

void diffuser_a_decrypt(uint8_t* sector, uint16_t sector_size, uint32_t* buffer)
{
	int Acycles = 5;
	uint16_t Ra[] = { 9, 0, 13, 0 };
	uint16_t int_size = sector_size >> 2;

	while (Acycles--)
	{
		for (int i = 0; i < int_size; ++i)
		{
			*(buffer + i) = *(buffer + i) + (*(buffer + ((i - 2 + int_size) % int_size)) ^ ROTATE_LEFT(*(buffer + ((i - 5 + int_size) % int_size)), Ra[i % 4]));
		}
	}
}

void diffuser_b_decrypt(uint8_t* sector, uint16_t sector_size, uint32_t* buffer)
{
	int Bcycles = 3;
	uint16_t Rb[] = { 0, 10, 0, 25 };
	uint16_t int_size = sector_size >> 2;

	while (Bcycles--)
	{
		for (int i = 0; i < int_size; ++i)
		{
			*(buffer + i) = *(buffer + i) + (*(buffer + ((i + 2) % int_size)) ^ ROTATE_LEFT(*(buffer + ((i + 5) % int_size)), Rb[i % 4]));
		}
	}
}

void decrypt_sector_aes_128(EVP_CIPHER_CTX* pctx, PBYTE sector, PBYTE key, DWORD64 sector_offset, DWORD sector_size, PBYTE decrypted)
{
	int len = 0;
	unsigned char null_iv[16] = { 0 };
	union {
		unsigned char data[16] = { 0 };
		DWORD64 sector;
	} iv;
	iv.sector = sector_offset;
	EVP_EncryptInit(pctx, EVP_aes_128_ecb(), key, null_iv);
	EVP_EncryptUpdate(pctx, iv.data, &len, iv.data, 16);
	EVP_CIPHER_CTX_cleanup(pctx);

	EVP_DecryptInit(pctx, EVP_aes_128_cbc(), key, iv.data);
	EVP_CIPHER_CTX_set_padding(pctx, 0);
	EVP_DecryptUpdate(pctx, decrypted, &len, sector, sector_size);
	EVP_DecryptFinal(pctx, decrypted + len, &len);
	EVP_CIPHER_CTX_cleanup(pctx);
}

void decrypt_sector_aes_128_diffuser(EVP_CIPHER_CTX* pctx, PBYTE sector, PBYTE key, DWORD64 sector_offset, DWORD sector_size, PBYTE decrypted)
{
	int len = 0;
	unsigned char null_iv[16] = { 0 };
	union {
		unsigned char data[16] = { 0 };
		DWORD64 sector;
	} iv;
	iv.sector = sector_offset;

	uint8_t sector_key[32] = { 0 };

	EVP_EncryptInit(pctx, EVP_aes_128_ecb(), key + 0x20, null_iv);
	EVP_EncryptUpdate(pctx, sector_key, &len, iv.data, 16);
	iv.data[15] = 0x80;
	EVP_EncryptUpdate(pctx, sector_key + 16, &len, iv.data, 16);
	EVP_CIPHER_CTX_cleanup(pctx);

	decrypt_sector_aes_128(pctx, sector, key, sector_offset, sector_size, decrypted);

	diffuser_b_decrypt(decrypted, sector_size & 0xffff, (uint32_t*)decrypted);
	diffuser_a_decrypt(decrypted, sector_size & 0xffff, (uint32_t*)decrypted);

	utils::crypto::xor_buffer(decrypted, sector_size, sector_key, 32);
}

void decrypt_sector_aes_256(EVP_CIPHER_CTX* pctx, PBYTE sector, PBYTE key, DWORD64 sector_offset, DWORD sector_size, PBYTE decrypted)
{
	int len = 0;
	unsigned char null_iv[16] = { 0 };
	union {
		unsigned char data[16] = { 0 };
		DWORD64 sector;
	} iv;
	iv.sector = sector_offset;
	EVP_EncryptInit(pctx, EVP_aes_256_ecb(), key, null_iv);
	EVP_EncryptUpdate(pctx, iv.data, &len, iv.data, 16);
	EVP_CIPHER_CTX_cleanup(pctx);

	EVP_DecryptInit(pctx, EVP_aes_256_cbc(), key, iv.data);
	EVP_CIPHER_CTX_set_padding(pctx, 0);
	EVP_DecryptUpdate(pctx, decrypted, &len, sector, sector_size);
	EVP_DecryptFinal(pctx, decrypted + len, &len);
	EVP_CIPHER_CTX_cleanup(pctx);
}

void decrypt_sector_aes_256_diffuser(EVP_CIPHER_CTX* pctx, PBYTE sector, PBYTE key, DWORD64 sector_offset, DWORD sector_size, PBYTE decrypted)
{
	int len = 0;
	unsigned char null_iv[16] = { 0 };
	union {
		unsigned char data[16] = { 0 };
		DWORD64 sector;
	} iv;
	iv.sector = sector_offset;

	uint8_t sector_key[32] = { 0 };

	EVP_EncryptInit(pctx, EVP_aes_256_ecb(), key + 0x20, null_iv);
	EVP_EncryptUpdate(pctx, sector_key, &len, iv.data, 16);
	iv.data[15] = 0x80;
	EVP_EncryptUpdate(pctx, sector_key + 16, &len, iv.data, 16);
	EVP_CIPHER_CTX_cleanup(pctx);

	decrypt_sector_aes_256(pctx, sector, key, sector_offset, sector_size, decrypted);

	diffuser_b_decrypt(decrypted, sector_size & 0xffff, (uint32_t*)decrypted);
	diffuser_a_decrypt(decrypted, sector_size & 0xffff, (uint32_t*)decrypted);

	utils::crypto::xor_buffer(decrypted, sector_size, sector_key, 32);
}

void decrypt_sector_xts_256(EVP_CIPHER_CTX* pctx, PBYTE sector, PBYTE key, DWORD64 sector_offset, DWORD sector_size, PBYTE decrypted)
{
	int len = 0;
	union {
		unsigned char data[16] = { 0 };
		DWORD64 sector;
	} iv;
	iv.sector = sector_offset / sector_size;
	EVP_DecryptInit(pctx, EVP_aes_256_xts(), key, iv.data);
	EVP_DecryptUpdate(pctx, decrypted, &len, sector, sector_size);
	EVP_CIPHER_CTX_cleanup(pctx);
}

void decrypt_sector_xts_128(EVP_CIPHER_CTX* pctx, PBYTE sector, PBYTE key, DWORD64 sector_offset, DWORD sector_size, PBYTE decrypted)
{
	int len = 0;
	union {
		unsigned char data[16] = { 0 };
		DWORD64 sector;
	} iv;
	iv.sector = sector_offset / sector_size;
	EVP_DecryptInit(pctx, EVP_aes_128_xts(), key, iv.data);
	EVP_DecryptUpdate(pctx, decrypted, &len, sector, sector_size);
	EVP_CIPHER_CTX_cleanup(pctx);
}