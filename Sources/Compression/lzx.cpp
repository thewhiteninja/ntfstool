#include "lzx.h"
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

int decompress_lzx(std::shared_ptr<Buffer<PBYTE>> compressed, std::shared_ptr<Buffer<PBYTE>> decompressed, DWORD windows_size)
{
	std::vector<DWORD> chunks_sizes;
	PBYTE decompressed_data = decompressed->data();
	PBYTE compressed_data = nullptr;

	if (parse_chunk_table(compressed, windows_size, &compressed_data, chunks_sizes))
	{
		memcpy_s(decompressed->data(), decompressed->size(), decompressed->data(), decompressed->size());
		std::cout << "[!] LZX compressed files is not supported yet" << std::endl;
	}

	return 0;
}
