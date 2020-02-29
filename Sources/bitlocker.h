#pragma once

#include <Windows.h>

#define FVE_METADATA_ENTRY_VALUE_TYPE_ERASED				0x0000
#define FVE_METADATA_ENTRY_VALUE_TYPE_KEY					0x0001
#define FVE_METADATA_ENTRY_VALUE_TYPE_UNICODE_STRING		0x0002
#define FVE_METADATA_ENTRY_VALUE_TYPE_STRETCH_KEY			0x0003
#define FVE_METADATA_ENTRY_VALUE_TYPE_USE_KEY				0x0004
#define FVE_METADATA_ENTRY_VALUE_TYPE_AES_CCM_ENCRYPTED_KEY 0x0005
#define FVE_METADATA_ENTRY_VALUE_TYPE_TPM_ENCODED_KEY		0x0006
#define FVE_METADATA_ENTRY_VALUE_TYPE_VALIDATION			0x0007
#define FVE_METADATA_ENTRY_VALUE_TYPE_VOLUME_MASTER_KEY		0x0008
#define FVE_METADATA_ENTRY_VALUE_TYPE_EXTERNAL_KEY			0x0009
#define FVE_METADATA_ENTRY_VALUE_TYPE_UPDATE				0x000a
#define FVE_METADATA_ENTRY_VALUE_TYPE_ERROR					0x000b
#define FVE_METADATA_ENTRY_VALUE_TYPE_ASYMMETRIC_ENCRYPTION	0x000c
#define FVE_METADATA_ENTRY_VALUE_TYPE_EXPORTED_KEY			0x000d
#define FVE_METADATA_ENTRY_VALUE_TYPE_PUBLIC_KEY			0x000e
#define FVE_METADATA_ENTRY_VALUE_TYPE_OFFSET_AND_SIZE		0x000f
#define FVE_METADATA_ENTRY_VALUE_TYPE_CONCAT_HASH_KEY		0x0012

#define FVE_METADATA_ENTRY_TYPE_PROPERTY					0x0000
#define FVE_METADATA_ENTRY_TYPE_VMK							0x0002
#define FVE_METADATA_ENTRY_TYPE_FKEV						0x0003
#define FVE_METADATA_ENTRY_TYPE_VALIDATION					0x0004
#define FVE_METADATA_ENTRY_TYPE_STARTUP_KEY					0x0006
#define FVE_METADATA_ENTRY_TYPE_DRIVE_LABEL					0x0007
#define FVE_METADATA_ENTRY_TYPE_UNKNOWN						0x000b
#define FVE_METADATA_ENTRY_TYPE_VOLUME_HEADER_BLOCK			0x000f

#define FVE_METADATA_KEY_PROTECTION_TYPE_CLEARTEXT			0x0000
#define FVE_METADATA_KEY_PROTECTION_TYPE_TPM				0x0100
#define FVE_METADATA_KEY_PROTECTION_TYPE_STARTUP_KEY		0x0200
#define FVE_METADATA_KEY_PROTECTION_TYPE_TPM_PIN			0x0500
#define FVE_METADATA_KEY_PROTECTION_TYPE_RECOVERY_PASSWORD	0x0800
#define FVE_METADATA_KEY_PROTECTION_TYPE_PASSWORD			0x2000

#define FVE_METADATA_MAC_LEN								16
#define FVE_METADATA_NONCE_LEN								12


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