#include "EFS/certificate.h"

Certificate::Certificate(PBYTE data, DWORD size)
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
	}
}


