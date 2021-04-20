#include <algorithm>
#include <cstdint>
#include <string>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <memory>
#include <stdexcept>

#include "Drive/disk.h"
#include "Drive/vbr.h"
#include "Drive/reader.h"
#include "Bitlocker/bitlocker.h"
#include "options.h"
#include "Utils/utils.h"
#include "Utils/constant_names.h"
#include "Utils/table.h"

#include <NTFS\ntfs_reader.h>
#include <Bitlocker\decryption.h>

int decrypt_volume(std::shared_ptr<Disk> disk, std::shared_ptr<Volume> vol, std::shared_ptr<Options> opts)
{
	std::cout << std::setfill('0');
	utils::ui::title("Decrypt Bitlocker Volume from " + disk->name() + " > Volume:" + std::to_string(vol->index()));

	DWORD sector_size = ((PBOOT_SECTOR_FAT32)vol->bootsector())->bytePerSector;

	std::cout << "[+] Opening " << vol->name() << std::endl;

	std::shared_ptr<Reader> reader = std::make_shared<Reader>(utils::strings::from_string(disk->name()));
	reader->seek(vol->offset());

	std::shared_ptr<Buffer<PBYTE>> fvek = utils::convert::from_hex(opts->fvek);

	PBOOT_SECTOR_COMMON pbsc = (PBOOT_SECTOR_COMMON)vol->bootsector();
	if (strncmp((char*)pbsc->oemID, "-FVE-FS-", 8) == 0)
	{
		std::cout << "[+] Reading Bitlocker VBR" << std::endl;
		std::cout << "[-]   Volume State   : " << constants::bitlocker::state(vol->bitlocker().metadata[0].block_header.curr_state) << std::endl;
		std::cout << "[-]   Size           : " << vol->size() << " (" << utils::format::size(vol->size()) << ")" << std::endl;
		std::cout << "[-]   Encrypted Size : " << vol->bitlocker().metadata[0].block_header.encrypted_volume_size << " (" << utils::format::size(vol->bitlocker().metadata[0].block_header.encrypted_volume_size) << ")" << std::endl;
		std::cout << "[-]   Algorithm      : " << constants::bitlocker::algorithm(vol->bitlocker().metadata[0].header.algorithm) << std::endl;

		decrypt_fn decrypt_sector_fn = nullptr;
		switch (vol->bitlocker().metadata[0].header.algorithm)
		{
		case 0x8000:
			decrypt_sector_fn = decrypt_sector_aes_128_diffuser;
			break;
		case 0x8001:
			decrypt_sector_fn = decrypt_sector_aes_256_diffuser;
			break;
		case 0x8002:
			decrypt_sector_fn = decrypt_sector_aes_128;
			break;
		case 0x8003:
			decrypt_sector_fn = decrypt_sector_aes_256;
			break;
		case 0x8004:
			decrypt_sector_fn = decrypt_sector_xts_128;
			break;
		case 0x8005:
			decrypt_sector_fn = decrypt_sector_xts_256;
			break;
		default:
			decrypt_sector_fn = nullptr;
			std::cerr << "[!] Decryption algorithm invalid or not implemented" << std::endl;
			return 1;
		}

		FVE_BLOCK_HEADER fve_bh = vol->bitlocker().metadata[0].block_header;

		HANDLE houtput = CreateFileA(opts->out.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
		if (houtput == INVALID_HANDLE_VALUE)
		{
			std::cout << "[!] Error creating output file" << std::endl;
			return 1;
		}

		ULONG64 processed_count = 0;
		DWORD64 total_size = vol->bitlocker().metadata[0].block_header.encrypted_volume_size;
		Buffer<PBYTE> sectorBuff(sector_size);
		Buffer<PBYTE> decSectorBuff(sector_size);
		EVP_CIPHER_CTX* pctx = EVP_CIPHER_CTX_new();

		auto prof_start = std::chrono::high_resolution_clock::now();

		reader->seek(vol->offset() + fve_bh.backup_sector_offset);

		DWORD64 sector_offset = fve_bh.backup_sector_offset;
		DWORD written = 0;
		for (DWORD i = 0; i < fve_bh.nb_sectors; i++)
		{
			reader->read(sectorBuff.data(), sector_size);
			decrypt_sector_fn(pctx, sectorBuff.data(), fvek->data(), sector_offset, sector_size, decSectorBuff.data());
			WriteFile(houtput, decSectorBuff.data(), sector_size, &written, NULL);

			sector_offset += sector_size;
			processed_count += sector_size;
		}

		std::cout << "[+] Decrypting sectors" << std::endl;

		sector_offset = (DWORD64)fve_bh.nb_sectors * sector_size;
		reader->seek(vol->offset() + sector_offset);

		DWORD64 sector_offset_max = 1 + ((total_size - 1) / sector_size);
		for (DWORD i = fve_bh.nb_sectors; i < sector_offset_max; i++)
		{
			reader->read(sectorBuff.data(), sector_size);
			decrypt_sector_fn(pctx, sectorBuff.data(), fvek->data(), sector_offset, sector_size, decSectorBuff.data());
			WriteFile(houtput, decSectorBuff.data(), sector_size, &written, NULL);

			sector_offset += sector_size;
			processed_count += sector_size;
			if ((processed_count & 0xfffff) == 0)
			{
				std::cout << "\r[-]   Processed data size : " << utils::format::size(processed_count) << " (" << std::to_string(100 * processed_count / total_size) << "%)";
			}
		}
		std::cout << "\r[-]   Processed data size : " << utils::format::size(processed_count) << " (" << std::to_string(100 * processed_count / total_size) << "%)";
		std::cout << std::endl << "[+] Duration : " << std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::high_resolution_clock::now() - prof_start).count() / 1000 << "ms" << std::endl;

		EVP_CIPHER_CTX_free(pctx);
		CloseHandle(houtput);
		std::cout << "[+] Closing Volume" << std::endl;
	}
	else
	{
		std::cout << "[!] Volume is not Bitlocked" << std::endl;
	}
	return 0;
}

namespace commands {
	namespace bitlocker {
		int decrypt_volume(std::shared_ptr<Options> opts)
		{
			std::ios_base::fmtflags flag_backup(std::cout.flags());

			std::shared_ptr<Disk> disk = get_disk(opts);
			if (disk != nullptr)
			{
				std::shared_ptr<Volume> volume = disk->volumes(opts->volume);
				if (volume != nullptr)
				{
					if (opts->out == "")
					{
						std::cerr << "[!] Invalid or missing output option" << std::endl;
						return 1;
					}
					if (opts->fvek == "")
					{
						std::cerr << "[!] Invalid or missing fvek option" << std::endl;
						return 1;
					}
					decrypt_volume(disk, volume, opts);
				}
			}

			std::cout.flags(flag_backup);
			return 0;
		}
	}
}