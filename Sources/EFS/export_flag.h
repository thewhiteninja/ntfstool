#pragma once

#include "EFS/private_key_enc.h"

class ExportFlagEnc : public PrivateKeyEnc
{
private:
public:
	ExportFlagEnc(PBYTE data, DWORD size) : PrivateKeyEnc(data, size)
	{
	}
};