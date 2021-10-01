
#include "EFS/public_key.h"
#include <openssl/rsa.h>
#include <openssl/pem.h>

PublicKey::PublicKey(PBYTE data, DWORD size)
{
	memcpy_s(&_header, 20, data, 20);
	_modulus = std::make_shared<Buffer<PBYTE>>(data + 20, _header.ModulusLen);
	_modulus->shrink(_header.Bitsize / 8);
	_modulus->reverse_bytes();
}

int PublicKey::export_to_PEM(std::string filename)
{
	RSA* rsa = RSA_new();
	BIGNUM* n, * e;

	if (rsa != nullptr)
	{
		n = BN_new();
		e = BN_new();

		auto rev_e = _byteswap_ulong(_header.Exponent);
		BN_bin2bn((unsigned char*)&rev_e, 4, e);
		BN_bin2bn(_modulus->data(), _modulus->size(), n);

		RSA_set0_key(rsa, n, e, 0);

		FILE* fp = nullptr;
		fopen_s(&fp, (filename + ".pub.pem").c_str(), "wb");
		if (!fp)
		{
			return 1;
		}
		else
		{
			if (!PEM_write_RSA_PUBKEY(fp, rsa))
			{
				return 2;
			}
			fclose(fp);
		}
		RSA_free(rsa);
	}
	else
	{
		return 3;
	}
	return 0;
}
