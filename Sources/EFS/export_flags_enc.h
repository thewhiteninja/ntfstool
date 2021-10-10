#pragma once

#include "EFS/private_key.h"
#include "EFS/private_key_enc.h"
#include <EFS/export_flags.h>

#include <memory>

#define EXPORTFLAGS_ENTROPY	"Hj1diQ6kpUx7VC4m"

class ExportFlagsEnc : public PrivateKeyEnc
{
private:
public:
	ExportFlagsEnc(PBYTE data, DWORD size) : PrivateKeyEnc(data, size) {}

	std::shared_ptr<ExportFlags> decrypt_with_masterkey(std::shared_ptr<Buffer<PBYTE>> masterkey);
};