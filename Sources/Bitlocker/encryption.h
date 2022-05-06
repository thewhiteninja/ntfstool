#pragma once

#include "../Utils/utils.h"
#include "openssl/evp.h"

#include <stdint.h>
#include <windows.h>
#include <iostream>
using namespace std;



#define ROTATE_LEFT(a,n)  (((a) << (n)) | ((a) >> ((sizeof(a) * 8)-(n))))

typedef void (*encrypt_fn)(EVP_CIPHER_CTX* pctx, PBYTE sector, PBYTE key, DWORD64 sector_offset, DWORD sector_size, PBYTE decrypted);

void diffuser_b_encrypt(size_t sector_size, uint32_t* buffer);

void diffuser_a_encrypt(size_t sector_size, uint32_t* buffer);

void encrypt_sector_aes_128(EVP_CIPHER_CTX* pctx, PBYTE sector, PBYTE key, DWORD64 sector_offset, DWORD sector_size, PBYTE encrypted);

void encrypt_sector_aes_128_diffuser(EVP_CIPHER_CTX* pctx,
	PBYTE sector, PBYTE key, DWORD64 sector_offset, DWORD sector_size, PBYTE encrypted);

void encrypt_sector_aes_256(EVP_CIPHER_CTX* pctx, PBYTE sector, PBYTE key, DWORD64 sector_offset, DWORD sector_size, PBYTE encrypted);

void encrypt_sector_aes_256_diffuser(EVP_CIPHER_CTX* pctx, 
	PBYTE sector, PBYTE key, DWORD64 sector_offset, DWORD sector_size, PBYTE encrypted);

void encrypt_sector_xts_128(EVP_CIPHER_CTX* pctx, PBYTE sector, PBYTE key, DWORD64 sector_offset, DWORD sector_size, PBYTE encrypted);

void encrypt_sector_xts_256(EVP_CIPHER_CTX* pctx, PBYTE sector, PBYTE key, DWORD64 sector_offset, DWORD sector_size, PBYTE encrypted);
