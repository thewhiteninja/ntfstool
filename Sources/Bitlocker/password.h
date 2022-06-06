#pragma once


#include <Windows.h>

#include <string>
#include <memory>

#include "Utils/buffer.h"
#include "Utils/utils.h"

void get_vmk_from_password(ULONG64 nonce_time, ULONG32 nonce_ctr, PBYTE mac_val, PBYTE enc_vmk, ULONG32 enc_size, PBYTE salt, const std::string& password, PBYTE vmk, ULONG32 vmk_len);

bool test_bitlocker_password(ULONG64 nonce_time, ULONG32 nonce_ctr, PBYTE mac_val, PBYTE enc_vmk, ULONG32 enc_size, PBYTE salt, const std::string& password);
std::shared_ptr<Buffer<PBYTE>> read_bek_file(std::wstring filename);

void bitlocker_prepare_password(std::string password, unsigned char* password_hash);