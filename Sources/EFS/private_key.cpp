#include "EFS/private_key.h"

PrivateKey::PrivateKey(PBYTE data, DWORD size)
{
	memcpy_s(&_header, 20, data, 20);

	unsigned int offset = 20;
	_modulus = std::make_shared<Buffer<PBYTE>>(data + offset, _header.Bitsize / 8);
	_modulus->reverse_bytes();
	offset += _header.ModulusLen;

	_prime1 = std::make_shared<Buffer<PBYTE>>(data + offset, _header.Bitsize / 16);
	_prime1->reverse_bytes();
	offset += _header.Bitsize / 16 + 4;

	_prime2 = std::make_shared<Buffer<PBYTE>>(data + offset, _header.Bitsize / 16);
	_prime2->reverse_bytes();
	offset += _header.Bitsize / 16 + 4;

	_exponent1 = std::make_shared<Buffer<PBYTE>>(data + offset, _header.Bitsize / 16);
	_exponent1->reverse_bytes();
	offset += _header.Bitsize / 16 + 4;

	_exponent2 = std::make_shared<Buffer<PBYTE>>(data + offset, _header.Bitsize / 16);
	_exponent2->reverse_bytes();
	offset += _header.Bitsize / 16 + 4;

	_coefficient = std::make_shared<Buffer<PBYTE>>(data + offset, _header.Bitsize / 16);
	_coefficient->reverse_bytes();
	offset += _header.Bitsize / 16 + 4;

	_private_exponent = std::make_shared<Buffer<PBYTE>>(data + offset, _header.Bitsize / 8);
	_private_exponent->reverse_bytes();
	offset += _header.Bitsize / 8 + 4;
}