#pragma once


#include <Windows.h>

#include <memory>
#include <string>

#include "openssl/sha.h"
#include "openssl/aes.h"

#include "Utils/buffer.h"
#include "Utils/utils.h"

#include "Bitlocker/fve.h"

#pragma pack(push, 1)

typedef struct _FVE_BLOCK_HEADER
{
	CHAR		signature[8];
	WORD		size;
	WORD		version;
	WORD		curr_state;
	WORD		next_state;
	DWORD64		encrypted_volume_size;
	DWORD convert_size;
	DWORD nb_sectors;
	DWORD64		block_header_offsets[3];
	DWORD64		backup_sector_offset;
} FVE_BLOCK_HEADER, * PFVE_BLOCK_HEADER;

typedef struct _FVE_HEADER
{
	DWORD		size;
	DWORD		version;
	DWORD		header_size;
	DWORD		copy_size;
	GUID		volume_guid;
	DWORD		next_counter;
	WORD		algorithm;
	WORD		algorithm_unused;
	FILETIME	timestamp;
} FVE_HEADER, * PFVE_HEADER;

typedef struct _FVE_ENTRY
{
	WORD		size;
	WORD		entry_type;
	WORD		value_type;
	WORD		version;
	CHAR		data[1];
} FVE_ENTRY, * PFVE_ENTRY;

typedef struct _FVE_ENTRY_KEY
{
	DWORD		encryption_method;
	BYTE		key[1];
} FVE_ENTRY_KEY, * PFVE_ENTRY_KEY;

typedef struct _FVE_ENTRY_UNICODE
{
	WCHAR string[1];
} FVE_ENTRY_UNICODE, * PFVE_ENTRY_UNICODE;

typedef struct _FVE_ENTRY_STRETCH_KEY
{
	ULONG32		encryption_method;
	BYTE		salt[16];
	BYTE		subentries[1];
} FVE_ENTRY_STRETCH_KEY, * PFVE_ENTRY_STRETCH_KEY;

typedef struct _FVE_ENTRY_USE_KEY
{
	ULONG32		encryption_method;
	BYTE		subentries[1];
} FVE_ENTRY_USE_KEY, * PFVE_ENTRY_USE_KEY;

typedef struct _FVE_ENTRY_AES_CCM
{
	FILETIME	nonce_time;
	ULONG32		nonce_counter;
	BYTE		mac[16];
	BYTE		key[1];
} FVE_ENTRY_AES_CCM, * PFVE_ENTRY_AES_CCM;

typedef struct _FVE_ENTRY_VMK
{
	GUID		key_id;
	FILETIME	last_change;
	WORD		unknown;
	WORD		protection_type;
	BYTE		subentries[1];
} FVE_ENTRY_VMK, * PFVE_ENTRY_VMK;

typedef struct _FVE_ENTRY_EXTERNAL_KEY
{
	GUID		key_id;
	FILETIME	last_change;
	BYTE		key[1];
} FVE_ENTRY_EXTERNAL_KEY, * PFVE_ENTRY_EXTERNAL_KEY;

typedef struct _FVE_ENTRY_OFFSET_SIZE
{
	DWORD64		offset;
	DWORD64		size;
	BYTE		data[1];
} FVE_ENTRY_OFFSET_SIZE, * PFVE_ENTRY_OFFSET_SIZE;

typedef struct _FVE_ENTRY_RECOVERY_BACKUP
{
	FILETIME	timestamp0;
	FILETIME	timestamp1;
	WORD		location;
	WORD		unknown;
	FVE_ENTRY	next_entry_header;
} FVE_ENTRY_RECOVERY_BACKUP, * PFVE_ENTRY_RECOVERY_BACKUP;

typedef struct _FVE_KEY_DATA
{
	BYTE last_sha256_hash[32];
	BYTE initial_sha256_hash[32];
	BYTE salt[16];
	ULONG64 iteration_count;
} FVE_KEY_DATA, * PFVE_KEY_DATA;

typedef struct _FVE_VMK
{
	BYTE		mac[16];
	DWORD		size;
	DWORD		version;
	DWORD		algorithm;
	BYTE		vmk[1];
} FVE_VMK, * PFVE_VMK;

typedef struct _FVE_FVEK
{
	BYTE		mac[16];
	DWORD		size;
	DWORD		version;
	DWORD		algorithm;
	BYTE		fvek[1];
} FVE_FVEK, * PFVE_FVEK;

typedef struct
{
	DWORD		metadata_size;
	DWORD		version;
	DWORD		metadata_header_size;
	DWORD		metadata_size_backup;
	GUID		key_id;
	DWORD		next_nonce;
	DWORD		encryption_method;
	FILETIME	creation;
	BYTE		entries[1];
} EXTERNAL_KEY_FILE, * PEXTERNAL_KEY_FILE;

#pragma pack(pop)

void bitlocker_derive_key(unsigned char* password_hash, unsigned char* password_salt, unsigned int iterations, unsigned char* key);

void bitlocker_decrypt_data(PBYTE encrypted_data, ULONG32 encrypted_data_size, PBYTE key, PBYTE mac, PBYTE nonce, PBYTE decrypted_data, ULONG32 decrypted_data_len);

bool bitlocker_mac_check(PBYTE clear_mac, PBYTE key, PBYTE nonce, PBYTE data, ULONG32 data_size);

void get_fvek_from_vmk(ULONG64 nonce_time, ULONG32 nonce_ctr, PBYTE mac_val, PBYTE enc_fvek, ULONG32 enc_size, PBYTE vmk, PBYTE fvek, ULONG32 fvek_len);