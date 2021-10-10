
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
	int ret = 1;

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

		BIO* out = BIO_new_file((filename + ".pub.pem").c_str(), "wb");
		if (out)
		{
			if (!PEM_write_bio_RSA_PUBKEY(out, rsa))
			{
				ret = 3;
			}
			else
			{
				ret = 0;
			}
			BIO_free(out);
		}
		else
		{
			ret = 2;
		}
		RSA_free(rsa);
	}

	return ret;
}
