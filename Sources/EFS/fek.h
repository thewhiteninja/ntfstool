#pragma once


#include <Windows.h>

#pragma pack(push, 1)

typedef struct {
	DWORD	KeyLength;
	DWORD	Entropy;
	ALG_ID	Algorithm;
	DWORD	Reserved;
	BYTE	Key[1];
} EFS_FEK, * PEFS_FEK;

#pragma pack(pop)
