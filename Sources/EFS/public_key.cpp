
#include "EFS/public_key.h"
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/provider.h>
#include <openssl/param_build.h>
#include <openssl/core_names.h>


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

	EVP_PKEY* pkey = NULL;
	EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);

	if (pctx)
	{
		BIGNUM* n = BN_new();
		BIGNUM* exp = BN_new();

		if (n && exp)
		{
			auto rev_e = _byteswap_ulong(_header.Exponent);
			BN_bin2bn((unsigned char*)&rev_e, 4, exp);
			BN_bin2bn(_modulus->data(), _modulus->size(), n);

#pragma warning( push )
#pragma warning( disable : 4838 )
			OSSL_PARAM params[3] = {
				OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_E, exp, BN_num_bytes(exp)),
				OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_N, n, BN_num_bytes(n)),
				OSSL_PARAM_END
			};
#pragma warning( pop )
			if (EVP_PKEY_fromdata_init(pctx))
			{
				if (EVP_PKEY_fromdata(pctx, &pkey, EVP_PKEY_PUBLIC_KEY, params))
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
					EVP_PKEY_free(pkey);
				}
			}

			BN_free(exp);
			BN_free(n);
		}
		EVP_PKEY_CTX_free(pctx);
	}

	return ret;
}
