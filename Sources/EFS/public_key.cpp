
#include "EFS/public_key.h"

PublicKey::PublicKey(PBYTE data, DWORD size)
{
	memcpy_s(&_header, 20, data, 20);
	_modulus = std::make_shared<Buffer<PBYTE>>(data + 20, _header.ModulusLen);
	_modulus->shrink(_header.Bitsize / 8);
	_modulus->reverse_bytes();
}