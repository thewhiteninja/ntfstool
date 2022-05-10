#include "EFS/pkcs12_archive.h"

int parse_bag(PKCS12_SAFEBAG* bag, const char* pass, int passlen,
	EVP_PKEY** pkey, STACK_OF(X509)* ocerts);

int parse_bags(const STACK_OF(PKCS12_SAFEBAG)* bags, const char* pass,
	int passlen, EVP_PKEY** pkey, STACK_OF(X509)* ocerts);

int parse_pk12(PKCS12* p12, const char* pass, int passlen,
	EVP_PKEY** pkey, STACK_OF(X509)* ocerts);

PKCS12Archive::PKCS12Archive(std::shared_ptr<CertificateFile> cert, std::shared_ptr<PrivateKey> private_key)
{
	_cert = _build_x509_cert(cert);
	_key = _build_evp_key(private_key);
}

int parse_bag(PKCS12_SAFEBAG* bag, const char* pass, int passlen,
	EVP_PKEY** pkey, STACK_OF(X509)* ocerts)
{
	PKCS8_PRIV_KEY_INFO* p8;
	X509* x509;
	const ASN1_TYPE* attrib;
	ASN1_BMPSTRING* fname = NULL;
	ASN1_OCTET_STRING* lkid = NULL;

	if ((attrib = PKCS12_SAFEBAG_get0_attr(bag, NID_friendlyName)))
		fname = attrib->value.bmpstring;

	if ((attrib = PKCS12_SAFEBAG_get0_attr(bag, NID_localKeyID)))
		lkid = attrib->value.octet_string;

	switch (PKCS12_SAFEBAG_get_nid(bag)) {
	case NID_keyBag:
		if (pkey == NULL || *pkey != NULL)
			return 1;
		*pkey = EVP_PKCS82PKEY(PKCS12_SAFEBAG_get0_p8inf(bag));
		if (*pkey == NULL)
			return 0;
		break;

	case NID_pkcs8ShroudedKeyBag:
		if (pkey == NULL || *pkey != NULL)
			return 1;
		if ((p8 = PKCS12_decrypt_skey(bag, pass, passlen)) == NULL)
			return 0;
		*pkey = EVP_PKCS82PKEY(p8);
		PKCS8_PRIV_KEY_INFO_free(p8);
		if (!(*pkey))
			return 0;
		break;

	case NID_certBag:
		if (ocerts == NULL
			|| PKCS12_SAFEBAG_get_bag_nid(bag) != NID_x509Certificate)
			return 1;
		if ((x509 = PKCS12_SAFEBAG_get1_cert(bag)) == NULL)
			return 0;
		if (lkid && !X509_keyid_set1(x509, lkid->data, lkid->length)) {
			X509_free(x509);
			return 0;
		}
		if (fname) {
			int len, r;
			unsigned char* data;

			len = ASN1_STRING_to_UTF8(&data, fname);
			if (len >= 0) {
				r = X509_alias_set1(x509, data, len);
				OPENSSL_free(data);
				if (!r) {
					X509_free(x509);
					return 0;
				}
			}
		}

		if (!sk_X509_push(ocerts, x509)) {
			X509_free(x509);
			return 0;
		}

		break;

	case NID_safeContentsBag:
		return parse_bags(PKCS12_SAFEBAG_get0_safes(bag), pass, passlen, pkey,
			ocerts);

	default:
		return 1;
	}
	return 1;
}

int parse_bags(const STACK_OF(PKCS12_SAFEBAG)* bags, const char* pass,
	int passlen, EVP_PKEY** pkey, STACK_OF(X509)* ocerts)
{
	int i;
	for (i = 0; i < sk_PKCS12_SAFEBAG_num(bags); i++) {
		if (!parse_bag(sk_PKCS12_SAFEBAG_value(bags, i),
			pass, passlen, pkey, ocerts))
			return 0;
	}
	return 1;
}

int parse_pk12(PKCS12* p12, const char* pass, int passlen,
	EVP_PKEY** pkey, STACK_OF(X509)* ocerts)
{
	STACK_OF(PKCS7)* asafes;
	STACK_OF(PKCS12_SAFEBAG)* bags;
	int i, bagnid;
	PKCS7* p7;

	if ((asafes = PKCS12_unpack_authsafes(p12)) == NULL)
		return 0;
	for (i = 0; i < sk_PKCS7_num(asafes); i++) {
		p7 = sk_PKCS7_value(asafes, i);
		bagnid = OBJ_obj2nid(p7->type);
		if (bagnid == NID_pkcs7_data) {
			bags = PKCS12_unpack_p7data(p7);
		}
		else if (bagnid == NID_pkcs7_encrypted) {
			bags = PKCS12_unpack_p7encdata(p7, pass, passlen);
		}
		else
			continue;
		if (!bags) {
			sk_PKCS7_pop_free(asafes, PKCS7_free);
			return 0;
		}
		if (!parse_bags(bags, pass, passlen, pkey, ocerts)) {
			sk_PKCS12_SAFEBAG_pop_free(bags, PKCS12_SAFEBAG_free);
			sk_PKCS7_pop_free(asafes, PKCS7_free);
			return 0;
		}
		sk_PKCS12_SAFEBAG_pop_free(bags, PKCS12_SAFEBAG_free);
	}
	sk_PKCS7_pop_free(asafes, PKCS7_free);
	return 1;
}

EVP_PKEY* PKCS12Archive::_build_evp_key(std::shared_ptr<PrivateKey> privatekey_file)
{
	if (privatekey_file)
	{
		EVP_PKEY* pkey = privatekey_file->export_private();
		if (pkey)
		{
			EVP_PKEY_add1_attr_by_NID(pkey, NID_ms_csp_name, MBSTRING_ASC, (const unsigned char*)"Microsoft Enhanced Cryptographic Provider v1.0", -1);
			return pkey;
		}
	}
	return nullptr;
}

X509* PKCS12Archive::_build_x509_cert(std::shared_ptr<CertificateFile> certfile)
{
	if (certfile)
	{
		X509* cert = certfile->export_to_X509();
		if (cert)
		{
			return cert;
		}
	}
	return nullptr;
}

PKCS12Archive::PKCS12Archive(std::string filename, std::string password)
{
	bool err = true;

	PKCS12* p12 = NULL;
	BIO* in = BIO_new_file(filename.c_str(), "rb");
	if (in)
	{
		p12 = d2i_PKCS12_bio(in, &p12);
		if (p12)
		{
			STACK_OF(X509)* _ca = sk_X509_new_null();
			STACK_OF(X509)* ocerts = sk_X509_new_null();
			if (parse_pk12(p12, password.c_str(), static_cast<int>(password.size()), &_key, ocerts))
			{
				X509* x = NULL;
				while ((x = sk_X509_shift(ocerts)) != NULL)
				{
					if (_key != NULL && _cert == NULL)
					{
						if (X509_check_private_key(x, _key))
						{
							_cert = x;
							continue;
						}
					}
				}
				if (_ca)
				{
					sk_X509_push(_ca, x);
				}
				sk_X509_free(ocerts);

				err = false;
			}
			PKCS12_free(p12);
		}

		BIO_free(in);
	}

	if (err)
	{
		if (_key)
		{
			EVP_PKEY_free(_key);
			_key = nullptr;
		}
		if (_cert)
		{
			X509_free(_cert);
			_cert = nullptr;
		}
		if (_ca_chain)
		{
			sk_X509_free(_ca_chain);
			_ca_chain = nullptr;
		}
	}
}

int PKCS12Archive::export_to_pfx(std::string filename, std::string password)
{
	int err = 0;

	if (_cert && _key)
	{
		if (X509_check_private_key(_cert, _key))
		{
			X509_keyid_set1(_cert, NULL, 0);
			X509_alias_set1(_cert, NULL, 0);

			PKCS12* p12 = PKCS12_create(password.c_str(), NULL, _key, _cert, sk_X509_new_null(), NID_undef, NID_undef, 0, -1, KEY_EX);
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
	}
	else
	{
		err = 1;
	}

	return err;
}

std::string PKCS12Archive::certificate_hash()
{
	if (_cert)
	{
		unsigned int fprint_size;
		auto fprint_type = EVP_sha1();
		unsigned char fprint[EVP_MAX_MD_SIZE];

		X509_digest(_cert, fprint_type, fprint, &fprint_size);
		return utils::strings::lower(utils::convert::to_hex(fprint, fprint_size));
	}
	return "";
}
