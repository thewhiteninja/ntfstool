#pragma once

#include <memory>
#include "Utils/buffer.h"

int decompress_lznt1(std::shared_ptr<Buffer<PBYTE>> compressed, std::shared_ptr<Buffer<PBYTE>> decompressed, PDWORD final_size);