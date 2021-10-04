#include "EFS/certificate.h"
#include <Utils/utils.h>
#include <Utils/constant_names.h>

#include <openssl/x509.h>
#include <openssl/pem.h>

CertificateFile::CertificateFile(PBYTE data, DWORD size)
{
	DER_ELEMENT e;
	unsigned int pos = 0;

	while (pos < size - 12)
	{
		memcpy_s(&e, 12, data + pos, 12);
		_fields.insert(std::pair(e.Type, std::make_shared<Buffer<PBYTE>>(data + pos + 12, e.Size * e.Count)));
		pos += 12 + e.Size * e.Count;
	}

	if (pos == size)
	{
		_loaded = true;

		for (auto element : _fields)
		{
			DWORD prop_id = std::get<0>(element);

			if (prop_id == CERT_KEY_PROV_INFO_PROP_ID)
			{
				PMY_CRYPT_KEY_PROV_INFO info = reinterpret_cast<PMY_CRYPT_KEY_PROV_INFO>(std::get<1>(element)->data());

				_info.container_name = utils::strings::to_utf8(POINTER_ADD(wchar_t*, info, info->ContainerNameOffset));
				_info.provider_name = utils::strings::to_utf8(POINTER_ADD(wchar_t*, info, info->ProvNameOffset));
				_info.provider_type = constants::efs::cert_prop_provider_type(info->ProvType);
				_info.keyspec = constants::efs::cert_prop_keyspec(info->KeySpec);
			}
			else if (prop_id == CERT_FRIENDLY_NAME_PROP_ID)
			{
				_info.friendly_name = utils::strings::to_utf8(reinterpret_cast<wchar_t*>(std::get<1>(element)->data()));
			}
		}
	}
}

int CertificateFile::export_to_PEM(std::string name)
{
	for (auto element : _fields)
	{
		DWORD prop_id = std::get<0>(element);

		if (prop_id == CERT_CERTIFICATE_FILE)
		{
			const unsigned char* bufder = std::get<1>(element)->data();
			X509* x = d2i_X509(NULL, &bufder, std::get<1>(element)->size());
			if (x)
			{
				FILE* fp = nullptr;
				fopen_s(&fp, (name + ".pem").c_str(), "wb");
				if (!fp)
				{
					return 1;
				}
				else
				{
					if (!PEM_write_X509(fp, x))
					{
						return 2;
					}
					fclose(fp);
				}
				X509_free(x);
			}
		}
	}
	return 0;
}

std::vector<std::string> CertificateFile::certificate_ossl_description()
{
	std::vector<std::string> ret;

	for (auto element : _fields)
	{
		DWORD prop_id = std::get<0>(element);

		if (prop_id == CERT_CERTIFICATE_FILE)
		{
			const unsigned char* bufder = std::get<1>(element)->data();
			X509* x = d2i_X509(NULL, &bufder, std::get<1>(element)->size());
			if (x)
			{
				BIO* bio = BIO_new(BIO_s_mem());
				if (bio)
				{
					X509_print(bio, x);

					char* pp;
					unsigned int size = BIO_get_mem_data(bio, &pp);
					pp[size] = '\0';
					auto lines = utils::strings::split(pp, '\n');
					lines.erase(lines.begin(), lines.begin() + 1);
					lines.erase(
						std::remove_if(
							lines.begin(),
							lines.end(),
							[](std::string const& s) { return s.size() < 4; }),
						lines.end());
					for (auto& line : lines)
					{
						line = line.substr(4);
					}
					ret = lines;

					BIO_free(bio);
				}
				X509_free(x);
			}
		}
	}

	return ret;
}


