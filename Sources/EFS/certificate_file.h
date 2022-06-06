#pragma once

#include <Windows.h>

#include <memory>
#include <map>
#include <vector>

#include <openssl/x509.h>

#include "Utils/buffer.h"

#define CERT_CERTIFICATE_FILE 32
#define CERT_CERTIFICATE_REVOCATION_LIST 33
#define CERT_CERTIFICATE_TRUST_LIST 34
#define CERT_KEY_ID	35

#pragma pack(push, 1)

typedef struct {
	DWORD	Type;
	DWORD	Size;
	DWORD	Count;
	BYTE	Data[1];
} DER_ELEMENT, * PDER_ELEMENT;

typedef struct {
	DWORD	dwParam;
	DWORD	pbDataOffset;
	DWORD	cbData;
	DWORD	dwFlags;
} MY_CRYPT_KEY_PROV_PARAM, * PMY_CRYPT_KEY_PROV_PARAM;

typedef struct {
	DWORD	ContainerNameOffset;
	DWORD	ProvNameOffset;
	DWORD	ProvType;
	DWORD	Flags;
	DWORD	ProvParam;
	DWORD	ProvParamOffset;
	DWORD	KeySpec;
} MY_CRYPT_KEY_PROV_INFO, * PMY_CRYPT_KEY_PROV_INFO;

typedef struct {
	std::string container_name;
	std::string provider_name;
	std::string provider_type;
	std::string keyspec;
	std::string friendly_name;
} MY_CERT_INFO, * PMY_CERT_INFO;

#pragma pack(pop)

class CertificateFile
{
private:
	bool _loaded = false;

	MY_CERT_INFO _info;

	std::map<DWORD, std::shared_ptr<Buffer<PBYTE>>> _fields;

public:
	CertificateFile(PBYTE data, DWORD size);

	bool is_loaded() { return _loaded; }

	std::map<DWORD, std::shared_ptr<Buffer<PBYTE>>> fields() { return _fields; }

	PMY_CERT_INFO info() { return &_info; }

	std::vector<std::string> certificate_ossl_description();

	std::string hash();

	int export_to_PEM(std::string name);

	X509* export_to_X509();
};
