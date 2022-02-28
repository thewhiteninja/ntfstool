#include "xpress.h"
#include <Compression/ntdll_defs.h>
#include <Utils/utils.h>

static bool parse_chunk_table(std::shared_ptr<Buffer<PBYTE>> compressed, DWORD windows_size, PBYTE* data_start, std::vector<DWORD>& chunks_sizes)
{
	chunks_sizes.clear();
	DWORD last_chunk_offset = 0;
	DWORD current_chunk_offset = 1;
	DWORD chunk_index = 0;
	int64_t remaining_bytes = compressed->size();

	while (remaining_bytes > 0)
	{
		current_chunk_offset = compressed->read_at<DWORD>(sizeof(DWORD) * chunk_index++);
		if (current_chunk_offset < last_chunk_offset || current_chunk_offset > compressed->size() || (current_chunk_offset - last_chunk_offset) > windows_size)
		{
			break;
		}
		else
		{
			chunks_sizes.push_back(current_chunk_offset - last_chunk_offset);
			last_chunk_offset = current_chunk_offset;
			remaining_bytes -= sizeof(DWORD) + (current_chunk_offset - last_chunk_offset);
		}
	}

	if (data_start)
	{
		*data_start = POINTER_ADD(PBYTE, compressed->data(), sizeof(DWORD) * chunks_sizes.size());
	}

	return true;
}


int decompress_xpress(std::shared_ptr<Buffer<PBYTE>> compressed, std::shared_ptr<Buffer<PBYTE>> decompressed, DWORD windows_size, DWORD final_size)
{
	_RtlDecompressBufferEx RtlDecompressBufferEx = nullptr;
	_RtlGetCompressionWorkSpaceSize RtlGetCompressionWorkSpaceSize = nullptr;

	utils::dll::ntdll::load_compression_functions(nullptr, &RtlDecompressBufferEx, &RtlGetCompressionWorkSpaceSize);

	if (!RtlDecompressBufferEx || !RtlGetCompressionWorkSpaceSize)
	{
		return 1;
	}

	ULONG comp_block = 0, comp_frag = 0;
	RtlGetCompressionWorkSpaceSize(COMPRESSION_FORMAT_XPRESS_HUFF, &comp_block, &comp_frag);
	std::shared_ptr<Buffer<LPVOID>> workspace = std::make_shared<Buffer<LPVOID>>(comp_block);

	std::vector<DWORD> chunks_sizes;
	PBYTE decompressed_data = decompressed->data();
	PBYTE compressed_data = nullptr;

	if (parse_chunk_table(compressed, windows_size, &compressed_data, chunks_sizes))
	{
		for (auto& chunk_size : chunks_sizes)
		{
			NTSTATUS status;
			ULONG chunk_final_size = 0;
			if (status = RtlDecompressBufferEx(COMPRESSION_FORMAT_XPRESS_HUFF, decompressed_data, windows_size, compressed_data, chunk_size, &chunk_final_size, workspace->data()))
			{
				return 2;
			}
			else
			{
				decompressed_data = POINTER_ADD(PBYTE, decompressed_data, chunk_final_size);
				compressed_data = POINTER_ADD(PBYTE, compressed_data, chunk_size);
			}
		}

		DWORD remaining_chunk_size = compressed->size() - static_cast<DWORD>(compressed_data - compressed->address());
		if (remaining_chunk_size)
		{
			ULONG chunk_final_size = 0;
			RtlDecompressBufferEx(COMPRESSION_FORMAT_XPRESS_HUFF, decompressed_data, windows_size, compressed_data, remaining_chunk_size, &chunk_final_size, workspace->data());
		}
	}

	if (decompressed->size() > final_size)
	{
		decompressed->shrink(final_size);
	}

	return 0;
}
