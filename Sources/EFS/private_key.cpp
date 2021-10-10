#include "EFS/private_key.h"
#include <openssl/rsa.h>
#include <openssl/pem.h>

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

	RSA* rsa = RSA_new();
	if (rsa != nullptr)
	{
		BIGNUM* p, * q, * n, * e, * d, * dmp1, * dmq1, * iqmp;

		p = BN_new();
		q = BN_new();
		n = BN_new();
		e = BN_new();
		d = BN_new();
		dmp1 = BN_new();
		dmq1 = BN_new();
		iqmp = BN_new();

		auto rev_e = _byteswap_ulong(_header.Exponent);
		BN_bin2bn((unsigned char*)&rev_e, 4, e);
		BN_bin2bn(_modulus->data(), _modulus->size(), n);
		BN_bin2bn(_prime1->data(), _prime1->size(), p);
		BN_bin2bn(_prime2->data(), _prime2->size(), q);
		BN_bin2bn(_private_exponent->data(), _private_exponent->size(), d);
		BN_bin2bn(_exponent1->data(), _exponent1->size(), dmp1);
		BN_bin2bn(_exponent2->data(), _exponent2->size(), dmq1);
		BN_bin2bn(_coefficient->data(), _coefficient->size(), iqmp);

		RSA_set0_factors(rsa, p, q);
		RSA_set0_key(rsa, n, e, d);
		RSA_set0_crt_params(rsa, dmp1, dmq1, iqmp);

		BIO* out = BIO_new_file((filename + ".priv.pem").c_str(), "wb");
		if (out)
		{
			if (!PEM_write_bio_RSAPrivateKey(out, rsa, nullptr, nullptr, 0, nullptr, nullptr))
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

int PrivateKey::export_public_to_PEM(std::string filename)
{
	int ret = 1;

	RSA* rsa = RSA_new();
	if (rsa != nullptr)
	{
		BIGNUM* n, * e;

		n = BN_new();
		e = BN_new();

		auto rev_e = _byteswap_ulong(_header.Exponent);
		BN_bin2bn((unsigned char*)&rev_e, 4, e);
		BN_bin2bn(_modulus->data(), _modulus->size(), n);

		RSA_set0_key(rsa, n, e, nullptr);

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

RSA* PrivateKey::export_private_to_RSA()
{
	RSA* rsa = RSA_new();

	if (rsa != nullptr)
	{
		BIGNUM* p, * q, * n, * e, * d, * dmp1, * dmq1, * iqmp;

		p = BN_new();
		q = BN_new();
		n = BN_new();
		e = BN_new();
		d = BN_new();
		dmp1 = BN_new();
		dmq1 = BN_new();
		iqmp = BN_new();

		auto rev_e = _byteswap_ulong(_header.Exponent);
		BN_bin2bn((unsigned char*)&rev_e, 4, e);
		BN_bin2bn(_modulus->data(), _modulus->size(), n);
		BN_bin2bn(_prime1->data(), _prime1->size(), p);
		BN_bin2bn(_prime2->data(), _prime2->size(), q);
		BN_bin2bn(_private_exponent->data(), _private_exponent->size(), d);
		BN_bin2bn(_exponent1->data(), _exponent1->size(), dmp1);
		BN_bin2bn(_exponent2->data(), _exponent2->size(), dmq1);
		BN_bin2bn(_coefficient->data(), _coefficient->size(), iqmp);

		RSA_set0_factors(rsa, p, q);
		RSA_set0_key(rsa, n, e, d);
		RSA_set0_crt_params(rsa, dmp1, dmq1, iqmp);

		return rsa;
	}
	return nullptr;
}
