#pragma once


#include <Windows.h>

#include <openssl/aes.h>
#include <openssl/evp.h>

#define ROTATE_LEFT(a,n)  (((a) << (n)) | ((a) >> ((sizeof(a) * 8)-(n))))

typedef void (*decrypt_fn)(EVP_CIPHER_CTX* pctx, PBYTE sector, PBYTE key, DWORD64 sector_offset, DWORD sector_size, PBYTE decrypted);

void diffuser_a_decrypt(uint8_t* sector, uint16_t sector_size, uint32_t* buffer);

void diffuser_b_decrypt(uint8_t* sector, uint16_t sector_size, uint32_t* buffer);

void decrypt_sector_aes_128(EVP_CIPHER_CTX* pctx, PBYTE sector, PBYTE key, DWORD64 sector_offset, DWORD sector_size, PBYTE decrypted);

void decrypt_sector_aes_128_diffuser(EVP_CIPHER_CTX* pctx, PBYTE sector, PBYTE key, DWORD64 sector_offset, DWORD sector_size, PBYTE decrypted);

void decrypt_sector_aes_256(EVP_CIPHER_CTX* pctx, PBYTE sector, PBYTE key, DWORD64 sector_offset, DWORD sector_size, PBYTE decrypted);

void decrypt_sector_aes_256_diffuser(EVP_CIPHER_CTX* pctx, PBYTE sector, PBYTE key, DWORD64 sector_offset, DWORD sector_size, PBYTE decrypted);

void decrypt_sector_xts_256(EVP_CIPHER_CTX* pctx, PBYTE sector, PBYTE key, DWORD64 sector_offset, DWORD sector_size, PBYTE decrypted);

void decrypt_sector_xts_128(EVP_CIPHER_CTX* pctx, PBYTE sector, PBYTE key, DWORD64 sector_offset, DWORD sector_size, PBYTE decrypted);