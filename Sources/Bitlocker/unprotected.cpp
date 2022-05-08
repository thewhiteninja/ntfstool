#include <Bitlocker/bitlocker.h>
#include "Bitlocker/unprotected.h"


void get_vmk_from_unprotected_key(ULONG64 nonce_time, ULONG32 nonce_ctr, PBYTE mac_val, PBYTE enc_vmk, ULONG32 enc_size, PBYTE cleartext, PBYTE vmk, ULONG32 vmk_len)
{
	unsigned char nonce[12] = { 0 };
	*((PULONG64)nonce) = nonce_time;
	*((PULONG32)(nonce + 8)) = nonce_ctr;

	bitlocker_decrypt_data(enc_vmk, enc_size, cleartext, mac_val, nonce, vmk, vmk_len);
}