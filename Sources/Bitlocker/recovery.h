#pragma once


#include <Windows.h>

#include <string>
#include <memory>

#include "Utils/buffer.h"
#include "Utils/utils.h"

bool bitlocker_check_recovery_key(std::string recovery);

void bitlocker_prepare_recovery_key(std::string recovery, unsigned char* recovery_hash);

bool test_bitlocker_recovery(ULONG64 nonce_time, ULONG32 nonce_ctr, PBYTE mac_val, PBYTE enc_vmk, ULONG32 enc_size, PBYTE salt, const std::string& recovery);

void get_vmk_from_recovery(ULONG64 nonce_time, ULONG32 nonce_ctr, PBYTE mac_val, PBYTE enc_vmk, ULONG32 enc_size, PBYTE salt, const std::string& recovery, PBYTE vmk, ULONG32 vmk_len);
