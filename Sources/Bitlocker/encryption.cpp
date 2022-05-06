#include "encryption.h"

void diffuser_b_encrypt(size_t sector_size, uint32_t* buffer)
{
	uint16_t int_size = sector_size / 4;
	uint16_t Rb[] = { 0, 10, 0, 25 };
	int Bcycles = 3;
	while (Bcycles--)
	{
		for (int i = int_size - 1; i >= 0; --i)
		{
			*(buffer + i) = *(buffer + i) - (*(buffer + ((i + 2) % int_size))
				^ ROTATE_LEFT(*(buffer + ((i + 5) % int_size)), Rb[i % 4]));
		}
	}
}

void diffuser_a_encrypt(size_t sector_size, uint32_t* buffer)
{
	int Acycles = 5;
	uint16_t Ra[] = { 9, 0, 13, 0 };
	uint16_t int_size = sector_size >> 2;
	while (Acycles--)
	{
		for (int i = int_size - 1; i >= 0; --i)
		{
			*(buffer + i) = *(buffer + i) - (*(buffer + ((i - 2 + int_size) % int_size))
				^ ROTATE_LEFT(*(buffer + ((i - 5 + int_size) % int_size)), Ra[i % 4]));
		}
	}
}

void encrypt_sector_aes_128(EVP_CIPHER_CTX* pctx, 
	PBYTE sector, PBYTE key, DWORD64 sector_offset, DWORD sector_size, PBYTE encrypted)
{
	int len = 0;
	unsigned char null_iv[16] = { 0 };
	union {
		unsigned char data[16] = { 0 };
		DWORD64 sector;
	} iv;
	iv.sector = sector_offset;	// 一定要正确

	// 设置加密向量
	EVP_EncryptInit(pctx, EVP_aes_128_ecb(), key, null_iv);
	EVP_EncryptUpdate(pctx, iv.data, &len, iv.data, 16);
	EVP_CIPHER_CTX_cleanup(pctx);

	// 加密
	EVP_EncryptInit(pctx, EVP_aes_128_cbc(), key, iv.data);
	EVP_CIPHER_CTX_set_padding(pctx, 0);
	EVP_EncryptUpdate(pctx, encrypted, &len, sector, sector_size);
	EVP_EncryptFinal(pctx, encrypted + len, &len);
	EVP_CIPHER_CTX_cleanup(pctx);
}

void encrypt_sector_aes_128_diffuser(EVP_CIPHER_CTX* pctx, 
	PBYTE sector, PBYTE key, DWORD64 sector_offset, DWORD sector_size, PBYTE encrypted)
{
	int len = 0;
	unsigned char null_iv[16] = { 0 };
	union {
		unsigned char data[16] = { 0 };
		DWORD64 sector;
	} iv;
	iv.sector = sector_offset;

	uint8_t sector_key[32] = { 0 };

	EVP_EncryptInit(pctx, EVP_aes_128_ecb(), key + 0x20, null_iv);		// 初始化ctx，加密算法初始化  
	EVP_EncryptUpdate(pctx, sector_key, &len, iv.data, 16);				// 更新扇区key
	iv.data[15] = 0x80;
	EVP_EncryptUpdate(pctx, sector_key + 16, &len, iv.data, 16);		// 更新扇区key	
	EVP_CIPHER_CTX_cleanup(pctx);

	utils::crypto::xor_buffer(sector, sector_size, sector_key, 32);
	diffuser_a_encrypt(sector_size & 0xffff, (uint32_t*)sector);
	diffuser_b_encrypt(sector_size & 0xffff, (uint32_t*)sector);

	encrypt_sector_aes_128(pctx, (PBYTE)sector, key, sector_offset, sector_size, encrypted);
}

void encrypt_sector_aes_256(EVP_CIPHER_CTX* pctx, PBYTE sector, PBYTE key, DWORD64 sector_offset, DWORD sector_size, PBYTE encrypted)
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

	EVP_EncryptInit(pctx, EVP_aes_256_cbc(), key, iv.data);
	EVP_CIPHER_CTX_set_padding(pctx, 0);
	EVP_EncryptUpdate(pctx, encrypted, &len, sector, sector_size);
	EVP_EncryptFinal(pctx, encrypted + len, &len);
	EVP_CIPHER_CTX_cleanup(pctx);
}

void encrypt_sector_aes_256_diffuser(EVP_CIPHER_CTX* pctx,
	PBYTE sector, PBYTE key, DWORD64 sector_offset, DWORD sector_size, PBYTE encrypted)
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

	utils::crypto::xor_buffer(sector, sector_size, sector_key, 32);
	diffuser_a_encrypt(sector_size & 0xffff, (uint32_t*)sector);
	diffuser_b_encrypt(sector_size & 0xffff, (uint32_t*)sector);

	encrypt_sector_aes_256(pctx, (PBYTE)sector, key, sector_offset, sector_size, encrypted);
}

void encrypt_sector_xts_128(EVP_CIPHER_CTX* pctx, PBYTE sector, PBYTE key, DWORD64 sector_offset, DWORD sector_size, PBYTE encrypted)
{
	int len = 0;
	union {
		unsigned char data[16] = { 0 };
		DWORD64 sector;
	} iv;
	iv.sector = sector_offset / sector_size;
	EVP_EncryptInit(pctx, EVP_aes_128_xts(), key, iv.data);
	EVP_EncryptUpdate(pctx, encrypted, &len, sector, sector_size);
	EVP_CIPHER_CTX_cleanup(pctx);
}

void encrypt_sector_xts_256(EVP_CIPHER_CTX* pctx, PBYTE sector, PBYTE key, DWORD64 sector_offset, DWORD sector_size, PBYTE encrypted)
{
	int len = 0;
	union {
		unsigned char data[16] = { 0 };
		DWORD64 sector;
	} iv;
	iv.sector = sector_offset / sector_size;
	EVP_EncryptInit(pctx, EVP_aes_256_xts(), key, iv.data);
	EVP_EncryptUpdate(pctx, encrypted, &len, sector, sector_size);
	EVP_CIPHER_CTX_cleanup(pctx);
}
