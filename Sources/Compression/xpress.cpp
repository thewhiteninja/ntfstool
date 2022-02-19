#include "xpress.h"
#include <Compression/ntdll_defs.h>
#include <Utils/utils.h>

int decompress_xpress(std::shared_ptr<Buffer<PBYTE>> compressed, std::shared_ptr<Buffer<PBYTE>> decompressed, DWORD windows_size, DWORD final_size)
{
	_RtlDecompressBuffer RtlDecompressBuffer = nullptr;
	_RtlDecompressBufferEx RtlDecompressBufferEx = nullptr;
	_RtlGetCompressionWorkSpaceSize RtlGetCompressionWorkSpaceSize = nullptr;

	utils::dll::ntdll::load_compression_functions(&RtlDecompressBuffer, &RtlDecompressBufferEx, &RtlGetCompressionWorkSpaceSize);

	if (!RtlDecompressBuffer || !RtlDecompressBufferEx || !RtlGetCompressionWorkSpaceSize)
	{
		return 1;
	}

	std::vector<DWORD> chunks_sizes;
	for (DWORD chunk_index = 0; chunk_index < final_size / windows_size; chunk_index++)
	{
		DWORD current_chunk_size = compressed->read_at<DWORD>(sizeof(DWORD) * chunk_index);
		chunks_sizes.push_back(current_chunk_size);
	}

	ULONG comp_block = 0, comp_frag = 0;
	RtlGetCompressionWorkSpaceSize(COMPRESSION_FORMAT_XPRESS_HUFF, &comp_block, &comp_frag);
	LPVOID workspace = LocalAlloc(LMEM_FIXED, comp_block);

	PBYTE compressed_data = POINTER_ADD(PBYTE, compressed->data(), sizeof(DWORD) * chunks_sizes.size());
	PBYTE decompressed_data = decompressed->data();

	DWORD prev_chunk_size = 0;
	for (auto& chunk_size : chunks_sizes)
	{
		NTSTATUS status;
		ULONG chunk_final_size = 0;
		if (status = RtlDecompressBufferEx(COMPRESSION_FORMAT_XPRESS_HUFF, decompressed_data, windows_size, compressed_data, chunk_size - prev_chunk_size, &chunk_final_size, workspace))
		{
			LocalFree(workspace);
			return 2;
		}
		else
		{
			decompressed_data = POINTER_ADD(PBYTE, decompressed_data, chunk_final_size);
			compressed_data = POINTER_ADD(PBYTE, compressed_data, chunk_size - prev_chunk_size);
			prev_chunk_size = chunk_size;
		}
	}

	DWORD remaining_chunk_size = compressed->address() + compressed->size() - compressed_data;
	if (remaining_chunk_size)
	{
		ULONG chunk_final_size = 0;
		RtlDecompressBufferEx(COMPRESSION_FORMAT_XPRESS_HUFF, decompressed_data, windows_size, compressed_data, remaining_chunk_size, &chunk_final_size, workspace);
	}

	LocalFree(workspace);

	if (decompressed->size() > final_size)
	{
		decompressed->shrink(final_size);
	}

	return 0;
}
