#pragma once

#include <memory>
#include "Utils/buffer.h"

int decompress_xpress(std::shared_ptr<Buffer<PBYTE>> compressed, std::shared_ptr<Buffer<PBYTE>> decompressed, DWORD windows_size, DWORD final_size);