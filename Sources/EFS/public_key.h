#pragma once

#include <Windows.h>

#include <memory>
#include <string>

#include "Utils/utils.h"

#pragma pack(push, 1)

typedef struct {
	DWORD	Magic;
	DWORD	ModulusLen;
	DWORD	Bitsize;
	DWORD	Permissions;
	DWORD	Exponent;
	BYTE	Modulus[1];
} PUBLICKEY_BLOB, * PPUBLICKEY_BLOB;

#pragma pack(pop)

class PublicKey
{
private:
	PUBLICKEY_BLOB _header;
	std::shared_ptr<Buffer<PBYTE>> _modulus = nullptr;
public:
	PublicKey(PBYTE data, DWORD size);

	PPUBLICKEY_BLOB header() { return &_header; }

	std::shared_ptr<Buffer<PBYTE>> modulus() { return _modulus; }

	int export_to_PEM(std::string filename);
};