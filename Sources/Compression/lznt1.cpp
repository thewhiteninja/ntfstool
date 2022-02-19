#include "lznt1.h"

#include <Compression/ntdll_defs.h>
#include <Utils/utils.h>

int decompress_lznt1(std::shared_ptr<Buffer<PBYTE>> compressed, std::shared_ptr<Buffer<PBYTE>> decompressed, PDWORD final_size)
{
	_RtlDecompressBuffer RtlDecompressBuffer = nullptr;

	utils::dll::ntdll::load_compression_functions(&RtlDecompressBuffer, nullptr, nullptr);

	if (!RtlDecompressBuffer)
	{
		return 1;
	}

	*final_size = 0;
	NTSTATUS status;
	if (status = RtlDecompressBuffer(COMPRESSION_FORMAT_LZNT1, decompressed->data(), decompressed->size(), compressed->data(), compressed->size(), final_size))
	{
		return 2;
	}

	if (*final_size == 0)
	{
		return 3;
	}

	return 0;
}
