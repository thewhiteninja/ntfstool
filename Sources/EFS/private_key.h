#pragma once
#include <WinSock2.h>
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
	BYTE	Data[1];
} PRIVATEKEY_BLOB, * PPRIVATEKEY_BLOB;


#pragma pack(pop)

class PrivateKey
{
private:
	PRIVATEKEY_BLOB _header;

	std::shared_ptr<Buffer<PBYTE>> _modulus = nullptr;
	std::shared_ptr<Buffer<PBYTE>> _prime1 = nullptr;
	std::shared_ptr<Buffer<PBYTE>> _prime2 = nullptr;
	std::shared_ptr<Buffer<PBYTE>> _exponent1 = nullptr;
	std::shared_ptr<Buffer<PBYTE>> _exponent2 = nullptr;
	std::shared_ptr<Buffer<PBYTE>> _coefficient = nullptr;
	std::shared_ptr<Buffer<PBYTE>> _private_exponent = nullptr;

public:
	PrivateKey(PBYTE data, DWORD size);

	PPRIVATEKEY_BLOB header() { return &_header; }

	std::shared_ptr<Buffer<PBYTE>> modulus() { return _modulus; }

	std::shared_ptr<Buffer<PBYTE>> prime1() { return _prime1; }

	std::shared_ptr<Buffer<PBYTE>> prime2() { return _prime2; }

	std::shared_ptr<Buffer<PBYTE>> exponent1() { return _exponent1; }

	std::shared_ptr<Buffer<PBYTE>> exponent2() { return _exponent2; }

	std::shared_ptr<Buffer<PBYTE>> coefficient() { return _coefficient; }

	std::shared_ptr<Buffer<PBYTE>> private_exponent() { return _private_exponent; }

	int export_private_to_PEM(std::string filename);

	int export_public_to_PEM(std::string filename);

	EVP_PKEY* export_private();
};