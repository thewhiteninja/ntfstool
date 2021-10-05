
#include <memory>
#include <openssl/pkcs12.h>


#include <EFS/private_key.h>
#include <EFS/certificate_file.h>

class PKCS12Backup
{
private:
	std::shared_ptr<CertificateFile> _cert = nullptr;
	std::shared_ptr<PrivateKey> _private_key = nullptr;

	EVP_PKEY* _build_evp_key()
	{
		if (_private_key)
		{
			EVP_PKEY* key = EVP_PKEY_new();
			RSA* rsa_key = _private_key->export_private_to_RSA();
			if (rsa_key)
			{
				if (EVP_PKEY_assign_RSA(key, rsa_key))
				{
					EVP_PKEY_add1_attr_by_NID(key, NID_ms_csp_name, MBSTRING_ASC, (const unsigned char*)"Microsoft Enhanced Cryptographic Provider v1.0", -1);
					return key;
				}
			}
			if (key)
			{
				EVP_PKEY_free(key);
			}
		}
		return nullptr;
	}

	X509* _build_x509_cert()
	{
		if (_cert)
		{
			X509* cert = _cert->export_to_X509();
			if (cert)
			{
				return cert;
			}
		}
		return nullptr;
	}

public:
	PKCS12Backup(std::shared_ptr<CertificateFile> cert, std::shared_ptr<PrivateKey> private_key)
	{
		_cert = cert;
		_private_key = private_key;
	}

	int export_to_pfx(std::string filename, std::string password)
	{
		int err = 0;

		if (_cert && _private_key)
		{
			X509* cert = _build_x509_cert();
			if (cert)
			{
				EVP_PKEY* key = _build_evp_key();
				if (key)
				{
					if (X509_check_private_key(cert, key))
					{
						X509_keyid_set1(cert, NULL, 0);
						X509_alias_set1(cert, NULL, 0);

						PKCS12* p12 = PKCS12_create(password.c_str(), NULL, key, cert, sk_X509_new_null(), NID_undef, NID_undef, 0, -1, KEY_EX);
						if (p12)
						{
							BIO* out = BIO_new_file(filename.c_str(), "wb");
							if (out)
							{
								i2d_PKCS12_bio(out, p12);
								BIO_free(out);
							}
							else
							{
								err = 4;
							}
							PKCS12_free(p12);
						}
						else
						{
							err = 3;
						}
					}
					else
					{
						err = 2;
					}

					EVP_PKEY_free(key);
				}
				X509_free(cert);
			}
		}
		else
		{
			err = 1;
		}

		return err;
	}
};