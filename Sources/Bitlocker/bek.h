#pragma once

#include <Windows.h>

#include <string>
#include <memory>

#include "Utils/buffer.h"

std::shared_ptr<Buffer<PBYTE>> read_bek_file(std::wstring filename);

bool test_bitlocker_bek(ULONG64 nonce_time, ULONG32 nonce_ctr, PBYTE mac_val, PBYTE enc_vmk, ULONG32 enc_size, PBYTE salt, std::string bek_file);

void get_vmk_from_bek(ULONG64 nonce_time, ULONG32 nonce_ctr, PBYTE mac_val, PBYTE enc_vmk, ULONG32 enc_size, PBYTE salt, std::string bekfile, PBYTE vmk, ULONG32 vmk_len);