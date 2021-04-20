#include "Drive/disk.h"
#include "Utils/utils.h"
#include "options.h"
#include "Commands/commands.h"
#include "NTFS/ntfs.h"
#include "NTFS/ntfs_explorer.h"
#include "Utils/constant_names.h"
#include "Utils/table.h"

#include <cstdint>
#include <string>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <memory>
#include <iterator>
#include <Utils\progress_bar.h>
#include <future>

#define IMAGE_BLOCK_SIZE (4096)

int create_image(std::shared_ptr<Disk> disk, std::shared_ptr<Volume> vol, const std::string& format, std::string output)
{
	std::shared_ptr<Buffer<PBYTE>> buffer = std::make_shared<Buffer<PBYTE>>(IMAGE_BLOCK_SIZE);

	HANDLE input = INVALID_HANDLE_VALUE;
	DWORD64 size = 0;

	if (vol == nullptr)
	{
		utils::ui::title("Image from " + disk->name());
		std::cout << "[+] Opening " << disk->name() << std::endl;
		input = disk->open();
		size = disk->size();
	}
	else
	{
		utils::ui::title("Image from " + disk->name() + " > Volume:" + std::to_string(vol->index()));
		std::cout << "[+] Opening " << vol->name() << std::endl;
		input = disk->open();
		size = vol->size();

		LARGE_INTEGER result;
		LARGE_INTEGER pos;
		pos.QuadPart = vol->offset();

		SetFilePointerEx(input, pos, &result, SEEK_SET);
	}

	if (input != INVALID_HANDLE_VALUE)
	{
		DWORD64 read = 0;

		std::cout << "[-] Size     : " << size << " (" << utils::format::size(size) << ")" << std::endl;
		std::cout << "[-] BlockSize: " << IMAGE_BLOCK_SIZE << std::endl;

		HANDLE houtput = CreateFileA(output.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
		if (houtput != INVALID_HANDLE_VALUE)
		{
			auto progress_bar = std::make_shared<ProgressBar>(100, 32, L"[+] Copying  : ");
			progress_bar->set_display_time(true);

			std::future<void> consumer = std::async(std::launch::async,
				[input, houtput, buffer, size, &read, &progress_bar]() {
					DWORD readBlock = 0;
					DWORD writeBlock = 0;

					for (DWORD64 pos = 0; pos < size; pos += IMAGE_BLOCK_SIZE)
					{
						progress_bar->set_progress(static_cast<int>(100 * pos / size));

						if (!ReadFile(input, buffer->data(), IMAGE_BLOCK_SIZE, &readBlock, NULL))
						{
							std::cerr << "[!] ReadFile failed" << std::endl;
							break;
						}
						else
						{
							if (!WriteFile(houtput, buffer->data(), readBlock, &writeBlock, NULL))
							{
								std::cerr << "[!] WriteFile failed" << std::endl;
								break;
							}
							else
							{
								read += readBlock;
							}
						}
					}
				});

			auto timeout = std::chrono::seconds(1);

			progress_bar->display(std::wcout);
			while (consumer.valid())
			{
				if (consumer.wait_for(timeout) == std::future_status::ready)
				{
					progress_bar->done(std::wcout);
					break;
				}
				progress_bar->display(std::wcout);
			}

			CloseHandle(houtput);
		}
		else
		{
			std::cerr << "[!] Create output file failed" << std::endl;
			return 1;
		}

		std::cout << "[+] Done" << std::endl;
		CloseHandle(input);
	}
	else
	{
		std::cerr << "[!] Opening source failed" << std::endl;
		return 1;
	}
	return 0;
}

namespace commands {
	namespace image {
		int create_image(std::shared_ptr<Options> opts)
		{
			std::ios_base::fmtflags flag_backup(std::cout.flags());

			std::shared_ptr<Disk> disk = nullptr;
			if (opts->disk != 0xffffffff && (disk = get_disk(opts)) != nullptr)
			{
				std::shared_ptr<Volume> volume = nullptr;
				if (opts->volume != 0xffffffff)
				{
					volume = disk->volumes(opts->volume);
					if (volume == nullptr)
					{
						std::cerr << "[!] Invalid volume option" << std::endl;
						return 1;
					}
				}
				create_image(disk, volume, opts->format, opts->out);
			}
			else
			{
				std::cerr << "[!] Invalid or missing disk option" << std::endl;
				return 1;
			}

			std::cout.flags(flag_backup);
			return 0;
		}
	}
}