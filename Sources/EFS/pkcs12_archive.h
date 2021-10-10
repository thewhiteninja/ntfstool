#pragma once
#include <memory>
#include <openssl/pkcs12.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/x509.h>

#include <EFS/private_key.h>
#include <EFS/certificate_file.h>


class PKCS12Archive
{
private:
	EVP_PKEY* _key = nullptr;
	X509* _cert = nullptr;
	STACK_OF(X509)* _ca_chain = nullptr;

	EVP_PKEY* _build_evp_key(std::shared_ptr<PrivateKey> privatekey_file);

	X509* _build_x509_cert(std::shared_ptr<CertificateFile> certfile);

public:
	explicit PKCS12Archive(std::shared_ptr<CertificateFile> cert, std::shared_ptr<PrivateKey> private_key);

	PKCS12Archive(std::string filename, std::string password);

	int export_to_pfx(std::string filename, std::string password);

	std::string certificate_hash();

	X509* certificate() { return _cert; }

	EVP_PKEY* key() { return _key; }

	STACK_OF(X509)* certs_chain() { return _ca_chain; }
};