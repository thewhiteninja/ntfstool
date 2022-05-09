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

int PrivateKey::export_private_to_PEM(std::string filename)
{
	int ret = 1;

	EVP_PKEY* pkey = export_private();
	if (pkey != nullptr)
	{
		BIO* out = BIO_new_file((filename + ".priv.pem").c_str(), "wb");
		if (out)
		{
			if (!PEM_write_bio_PrivateKey(out, pkey, EVP_des_ede3_cbc(), NULL, 0, 0, NULL))
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
		BIGNUM* p = BN_new();
		BIGNUM* q = BN_new();
		BIGNUM* n = BN_new();
		BIGNUM* e = BN_new();
		BIGNUM* d = BN_new();
		BIGNUM* dmp1 = BN_new();
		BIGNUM* dmq1 = BN_new();
		BIGNUM* iqmp = BN_new();

		if (p && q && n && e && d && dmp1 && dmq1 && iqmp)
		{
			auto rev_e = _byteswap_ulong(_header.Exponent);
			BN_bin2bn((unsigned char*)&rev_e, 4, e);
			BN_bin2bn(_modulus->data(), _modulus->size(), n);
			BN_bin2bn(_prime1->data(), _prime1->size(), p);
			BN_bin2bn(_prime2->data(), _prime2->size(), q);
			BN_bin2bn(_private_exponent->data(), _private_exponent->size(), d);
			BN_bin2bn(_exponent1->data(), _exponent1->size(), dmp1);
			BN_bin2bn(_exponent2->data(), _exponent2->size(), dmq1);
			BN_bin2bn(_coefficient->data(), _coefficient->size(), iqmp);

#pragma warning( push )
#pragma warning( disable : 4838 )
			OSSL_PARAM params[9] = {
				OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_FACTOR, p, BN_num_bytes(p)),
				OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_FACTOR1, q, BN_num_bytes(q)),
				OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_N, n, BN_num_bytes(n)),
				OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_E, e, BN_num_bytes(e)),
				OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_D, d, BN_num_bytes(d)),
				OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_EXPONENT, dmp1, BN_num_bytes(dmp1)),
				OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_EXPONENT1, dmq1, BN_num_bytes(dmq1)),
				OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_COEFFICIENT, iqmp, BN_num_bytes(iqmp)),
				OSSL_PARAM_END
			};
#pragma warning( pop )
			if (EVP_PKEY_fromdata_init(pctx))
			{
				if (EVP_PKEY_fromdata(pctx, &pkey, EVP_PKEY_KEY_PARAMETERS, params))
				{
					ret = pkey;
				}
			}

			BN_free(p);
			BN_free(q);
			BN_free(n);
			BN_free(e);
			BN_free(d);
			BN_free(dmp1);
			BN_free(dmq1);
			BN_free(iqmp);
		}
		EVP_PKEY_CTX_free(pctx);
	}

	return ret;
}
