#include "EFS/private_key.h"
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/provider.h>
#include <openssl/param_build.h>
#include <openssl/core_names.h>

PrivateKey::PrivateKey(PBYTE data, DWORD size)
{
	memcpy_s(&_header, 20, data, 20);

	unsigned int offset = 20;
	_modulus = std::make_shared<Buffer<PBYTE>>(data + offset, _header.Bitsize / 8);
	offset += _header.ModulusLen;

	_prime1 = std::make_shared<Buffer<PBYTE>>(data + offset, _header.Bitsize / 16);
	offset += _header.Bitsize / 16 + 4;

	_prime2 = std::make_shared<Buffer<PBYTE>>(data + offset, _header.Bitsize / 16);
	offset += _header.Bitsize / 16 + 4;

	_exponent1 = std::make_shared<Buffer<PBYTE>>(data + offset, _header.Bitsize / 16);
	offset += _header.Bitsize / 16 + 4;

	_exponent2 = std::make_shared<Buffer<PBYTE>>(data + offset, _header.Bitsize / 16);
	offset += _header.Bitsize / 16 + 4;

	_coefficient = std::make_shared<Buffer<PBYTE>>(data + offset, _header.Bitsize / 16);
	offset += _header.Bitsize / 16 + 4;

	_private_exponent = std::make_shared<Buffer<PBYTE>>(data + offset, _header.Bitsize / 8);
	offset += _header.Bitsize / 8 + 4;
}

int PrivateKey::export_private_to_PEM(std::string filename)
{
	int ret = 1;

	EVP_PKEY* pkey = export_private();
	if (pkey != nullptr)
	{
		BIO* out = BIO_new_file((filename + ".priv.pem").c_str(), "wb");
		if (out)
		{
			if (!PEM_write_bio_PrivateKey(out, pkey, NULL, NULL, 0, 0, NULL))
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
	}
	return ret;
}

int PrivateKey::export_public_to_PEM(std::string filename)
{
	int ret = 1;

	EVP_PKEY* pkey = export_private();
	if (pkey != nullptr)
	{
		BIO* out = BIO_new_file((filename + ".pub.pem").c_str(), "wb");
		if (out)
		{
			if (!PEM_write_bio_PUBKEY(out, pkey))
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
	}
	return ret;
}

EVP_PKEY* PrivateKey::export_private()
{
	EVP_PKEY* ret = nullptr;

	EVP_PKEY* pkey = nullptr;
	EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);

	if (pctx)
	{
#pragma warning( push )
#pragma warning( disable : 4838 )
		OSSL_PARAM params[9] = {
			OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_FACTOR1, _prime1->data(), _prime1->size()),
			OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_FACTOR2, _prime2->data(), _prime2->size()),
			OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_N, _modulus->data(), _modulus->size()),
			OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_E, &_header.Exponent, 4),
			OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_D, _private_exponent->data(), _private_exponent->size()),
			OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_EXPONENT1, _exponent1->data(), _exponent1->size()),
			OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_EXPONENT2, _exponent2->data(), _exponent2->size()),
			OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_COEFFICIENT1, _coefficient->data(), _coefficient->size()),
			OSSL_PARAM_END
		};
#pragma warning( pop )
		if (EVP_PKEY_fromdata_init(pctx))
		{
			if (EVP_PKEY_fromdata(pctx, &pkey, EVP_PKEY_KEYPAIR, params))
			{
				ret = pkey;
			}
		}

		EVP_PKEY_CTX_free(pctx);
	}

	return ret;
}
