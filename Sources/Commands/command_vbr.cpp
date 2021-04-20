#include <algorithm>
#include <cstdint>
#include <string>
#include <iostream>
#include <iomanip>
#include <memory>
#include <stdexcept>
#include <distorm.h>

#include "Drive/disk.h"
#include "Drive/vbr.h"
#include "options.h"

#include "NTFS/ntfs.h"
#include "Utils/utils.h"

void print_jump(BYTE jump[3])
{
	UINT32 jmp = jump[0] << 16 | jump[1] << 8 | jump[2];
	std::cout << "        Jump             : " << std::hex << std::setfill('0') << std::setw(6) << jmp;

	_DecodeResult res;
	_DecodedInst decodedInstructions[3] = { 0 };
	unsigned int decodedInstructionsCount = 0;
	_OffsetType offset = 0x7c00;

	res = distorm_decode(offset, jump, 3, Decode16Bits, decodedInstructions, 3, &decodedInstructionsCount);
	if (res != DECRES_INPUTERR)
	{
		std::cout << " (" << utils::strings::lower(std::string((char*)decodedInstructions[0].mnemonic.p)) << " ";
		if (decodedInstructions[0].operands.length != 0)
		{
			std::cout << utils::strings::lower(std::string((char*)decodedInstructions[0].operands.p));
		}
		std::cout << ")";
	}
	std::cout << std::dec << std::endl;
}

void print_boot_code(PBYTE code, int size, _OffsetType offset) {
	std::cout << std::endl;
	if (utils::ui::ask_question("    Disassemble Bootstrap Code"))
	{
		if (size)
		{
			std::cout << std::endl;
			for (std::string& line : utils::disass::buffer(code, size, Decode16Bits, offset))
			{
				std::cout << "        " << line << std::endl;
			}
		}
		else {
			std::cout << "        Empty code" << std::endl;
		}
	}
}

void print_strings(PBYTE code, std::vector<unsigned long> offsets)
{
	std::cout << std::endl << "    Strings:" << std::endl;

	if (std::all_of(offsets.begin(), offsets.end(), [offsets](int x) { return x == 0; }))
	{
		std::cout << "        No strings found" << std::endl;
	}
	else
	{
		for (unsigned int i = 0; i < offsets.size(); i++)
		{
			std::string s = std::string((PCHAR)(&code[offsets[i]]));
			if (i < offsets.size() - 1)
			{
				s.resize(offsets[i + 1] - offsets[i]);
			}
			utils::strings::trim(s);
			utils::strings::replace(s, "\x0d\x0a", "\\n");
			std::cout << "        [" << utils::format::hex((BYTE)(offsets[i] & 0xff), false) << "] : " << utils::strings::str_to_utf8(s, CP_OEMCP) << std::endl;
		}
	}
}

void print_bootsector_ntfs(PBOOT_SECTOR_NTFS pbs)
{
	std::cout << "    Structure:" << std::endl;

	print_jump(pbs->jump);

	std::cout << "        OEM id           : " << std::string((char*)pbs->oemID) << std::endl;
	std::cout << "        BytePerSector    : " << pbs->bytePerSector << std::endl;
	std::cout << "        SectorPerCluster : " << (ULONG)pbs->sectorPerCluster << std::endl;
	std::cout << "        Reserved Sectors : " << pbs->reserved << std::endl;
	std::cout << "        Media descriptor : " << (ULONG)pbs->mediaDescriptor << std::endl;
	std::cout << "        SectorPerTrack   : " << pbs->sectorPerTrack << std::endl;
	std::cout << "        Head number      : " << pbs->headNumber << std::endl;
	std::cout << "        Hidden sector    : " << pbs->hiddenSector << std::endl;
	std::cout << "        Total sector     : " << pbs->totalSector << std::endl;
	std::cout << "        MFT cluster      : " << pbs->MFTCluster << std::endl;
	std::cout << "        MFT Mirr cluster : " << pbs->MFTMirrCluster << std::endl;
	std::cout << "        ClusterPerRecord : " << (int)pbs->clusterPerRecord << std::endl;
	std::cout << "        ClusterPerBlock  : " << (int)pbs->clusterPerBlock << std::endl;
	std::cout << "        Serial number    : " << std::hex << std::setfill('0') << std::setw(16) << pbs->serialNumber << std::endl;
	std::cout << "        Checksum         : " << std::hex << std::setfill('0') << std::setw(8) << pbs->checkSum << std::endl;
	std::cout << "        End marker       : " << std::hex << std::setfill('0') << std::setw(2) << (ULONG)pbs->endMarker[0] << (ULONG)pbs->endMarker[1] << std::endl;

	std::vector<unsigned long> string_offsets;
	std::string os = utils::os::short_version();
	if (os == "8" || os == "10")
	{
		for (int i = 0; i < 4; i++)
		{
			WORD offset = ((PWORD)((PBYTE)pbs + 0x1f6))[i];
			if (offset)	string_offsets.push_back(offset);
		}
	}
	else
	{
		for (int i = 0; i < 4; i++)
		{
			BYTE offset = (((PBYTE)(pbs)) + 0x1f8)[i];
			if (offset)	string_offsets.push_back((offset & 0xff) + 0x100);
		}
	}

	print_strings((PBYTE)pbs, string_offsets);

	unsigned int size_to_disass = min(*std::min_element(string_offsets.begin(), string_offsets.end()), 0x1f6);
	while (((PBYTE)pbs)[size_to_disass - 1] == 0 && size_to_disass > 0)
	{
		size_to_disass--;
	}

	print_boot_code(pbs->bootCode, size_to_disass, 0x7c54);
}

void print_bootsector_fat32(PBOOT_SECTOR_FAT32 pbs)
{
	std::cout << "    Structure :" << std::endl;

	print_jump(pbs->jump);

	std::cout << "        OEM id           : " << std::string((char*)pbs->oemID) << std::endl;
	std::cout << "        BytePerSector    : " << pbs->bytePerSector << std::endl;
	std::cout << "        SectorPerCluster : " << (ULONG)pbs->sectorPerCluster << std::endl;
	std::cout << "        Reserved Sectors : " << pbs->reserved0 << std::endl;
	std::cout << "        Number of FATs   : " << (ULONG)pbs->fatCount << std::endl;
	std::cout << "        Root Max Entries : " << pbs->rootMaxEntries << std::endl;
	std::cout << "        Total Sectors    : " << (pbs->totalSectorsSmall == 0 ? pbs->totalSectors : pbs->totalSectorsSmall) << std::endl;
	std::cout << "        Media Type       : " << utils::format::hex(pbs->mediaType, 1) << std::endl;
	std::cout << "        SectorPerFat     : " << (pbs->sectorsPerFatSmall == 0 ? pbs->sectorsPerFat : pbs->sectorsPerFatSmall) << std::endl;
	std::cout << "        SectorPerTrack   : " << pbs->sectorsPerTrack << std::endl;
	std::cout << "        Head Count       : " << pbs->headCount << std::endl;
	std::cout << "        FS Offset        : " << pbs->fsOffset << std::endl;
	std::cout << "        Total Sectors    : " << pbs->totalSectors << std::endl;
	std::cout << "        FAT Flags        : " << utils::format::hex(pbs->fatFlags) << std::endl;
	std::cout << "        FAT Version      : " << utils::format::hex(pbs->version) << std::endl;
	std::cout << "        Root Cluster     : " << pbs->rootCluster << std::endl;
	std::cout << "        FS Info Sector   : " << pbs->fsInfoSector << std::endl;
	std::cout << "        Backup BootSector: " << pbs->backupSector << std::endl;
	std::cout << "        Reserved         : " << utils::format::hex(pbs->reserved1[0]) << std::endl;
	std::cout << "        Reserved         : " << utils::format::hex(pbs->reserved1[1]) << std::endl;
	std::cout << "        Reserved         : " << utils::format::hex(pbs->reserved1[2]) << std::endl;
	std::cout << "        Drive Number     : " << utils::format::hex(pbs->driveNumber) << std::endl;
	std::cout << "        Reserved         : " << utils::format::hex(pbs->reserved2) << std::endl;
	std::cout << "        Ext. Boot Sign   : " << utils::format::hex(pbs->extSig) << std::endl;
	std::cout << "        Serial Nuumber   : " << utils::format::hex(pbs->volumeSerialNumber) << std::endl;
	std::string s = std::string((char*)pbs->label);
	s.resize(11);
	std::cout << "        Volume Name      : " << s << std::endl;
	s = std::string((char*)pbs->fsName);
	s.resize(8);
	std::cout << "        FileSystem Type  : " << s << std::endl;
	std::cout << "        End marker       : " << utils::format::hex(pbs->endMarker, 2) << std::endl;

	std::vector<unsigned long> string_offsets;
	for (int i = 0; i < 3; i++)
	{
		WORD offset = ((PWORD)(((PBYTE)pbs) + 0x1f8))[i];
		if (offset)	string_offsets.push_back(offset);
	}

	print_strings((PBYTE)pbs, string_offsets);

	unsigned int size_to_disass = min(*std::min_element(string_offsets.begin(), string_offsets.end()), 0x1f8);
	while (((PBYTE)pbs)[size_to_disass - 1] == 0 && size_to_disass > 0)
	{
		size_to_disass--;
	}

	print_boot_code((PBYTE)pbs, size_to_disass, 0x7c5a);
}

void print_bootsector_fat1x(PBOOT_SECTOR_FAT1X pbs)
{
	std::cout << "    Structure:" << std::endl;

	print_jump(pbs->jump);

	std::cout << "        OEM id           : " << std::string((char*)pbs->oemID) << std::endl;
	std::cout << "        BytePerSector    : " << pbs->bytesPerSector << std::endl;
	std::cout << "        SectorPerCluster : " << (ULONG)pbs->sectorsPerCluster << std::endl;
	std::cout << "        Reserved Sectors : " << pbs->reservedSectorCount << std::endl;
	std::cout << "        Number of FATs   : " << (ULONG)pbs->fatCount << std::endl;
	std::cout << "        Root Max Entries : " << pbs->rootDirEntryCount << std::endl;
	std::cout << "        Total Sectors    : " << (pbs->totalSectors16 == 0 ? pbs->totalSectors32 : pbs->totalSectors16) << std::endl;
	std::cout << "        Media Type       : " << utils::format::hex(pbs->mediaType) << std::endl;
	std::cout << "        SectorPerFat     : " << pbs->sectorsPerFat16 << std::endl;
	std::cout << "        SectorPerTrack   : " << pbs->sectorsPerTrack << std::endl;
	std::cout << "        Head Count       : " << pbs->headCount << std::endl;
	std::cout << "        Hidden Sectors   : " << pbs->hidddenSectors << std::endl;
	std::cout << "        Total Sectors    : " << pbs->totalSectors32 << std::endl;
	std::cout << "        Drive Number     : " << (ULONG)pbs->driveNumber << std::endl;
	std::cout << "        Reserved         : " << utils::format::hex(pbs->reserved1) << std::endl;
	std::cout << "        Ext. Boot Sign   : " << utils::format::hex(pbs->extSig) << std::endl;
	std::cout << "        Serial Nuumber   : " << utils::format::hex(pbs->volumeSerialNumber) << std::endl;
	std::string s = std::string((char*)pbs->label);
	s.resize(11);
	std::cout << "        Volume Name      : " << s << std::endl;
	s = std::string((char*)pbs->fsName);
	s.resize(8);
	std::cout << "        FileSystem Type  : " << s << std::endl;
	std::cout << "        End marker       : " << utils::format::hex(pbs->endMarker, 2) << std::endl;

	std::vector<unsigned long> string_offsets;
	for (int i = 0; i < 3; i++)
	{
		WORD offset = (((PBYTE)pbs) + 0x1fb)[i];
		if (offset)	string_offsets.push_back(offset + 0x100);
	}

	print_strings((PBYTE)pbs, string_offsets);

	unsigned int size_to_disass = min(*std::min_element(string_offsets.begin(), string_offsets.end()), 0x1fb);
	while (((PBYTE)pbs)[size_to_disass - 1] == 0 && size_to_disass > 0)
	{
		size_to_disass--;
	}

	print_boot_code((PBYTE)pbs, size_to_disass, 0x7c3e);
}

void print_bootsector_bitlocker(PBOOT_SECTOR_BITLOCKER pbs)
{
	std::cout << "    Structure :" << std::endl;

	print_jump(pbs->jump);

	std::cout << "        OEM id           : " << std::string((char*)pbs->oemID) << std::endl;
	std::cout << "        BytePerSector    : " << pbs->bytePerSector << std::endl;
	std::cout << "        SectorPerCluster : " << (ULONG)pbs->sectorPerCluster << std::endl;
	std::cout << "        Reserved Sectors : " << pbs->reserved0 << std::endl;
	std::cout << "        Number of FATs   : " << (ULONG)pbs->fatCount << std::endl;
	std::cout << "        Root Max Entries : " << pbs->rootMaxEntries << std::endl;
	std::cout << "        Total Sectors    : " << (pbs->totalSectorsSmall == 0 ? pbs->totalSectors : pbs->totalSectorsSmall) << std::endl;
	std::cout << "        Media Type       : " << utils::format::hex(pbs->mediaType) << std::endl;
	std::cout << "        SectorPerFat     : " << (pbs->sectorsPerFatSmall == 0 ? pbs->sectorsPerFat : pbs->sectorsPerFatSmall) << std::endl;
	std::cout << "        SectorPerTrack   : " << pbs->sectorsPerTrack << std::endl;
	std::cout << "        Head Count       : " << pbs->headCount << std::endl;
	std::cout << "        FS Offset        : " << pbs->fsOffset << std::endl;
	std::cout << "        Total Sectors    : " << pbs->totalSectors << std::endl;
	std::cout << "        FAT Flags        : " << utils::format::hex(pbs->fatFlags) << std::endl;
	std::cout << "        FAT Version      : " << utils::format::hex(pbs->version) << std::endl;
	std::cout << "        Root Cluster     : " << pbs->rootCluster << std::endl;
	std::cout << "        FS Info Sector   : " << pbs->fsInfoSector << std::endl;
	std::cout << "        Backup BootSector: " << pbs->backupSector << std::endl;
	std::cout << "        Reserved         : " << utils::format::hex(pbs->reserved1[0]) << std::endl;
	std::cout << "        Reserved         : " << utils::format::hex(pbs->reserved1[1]) << std::endl;
	std::cout << "        Reserved         : " << utils::format::hex(pbs->reserved1[2]) << std::endl;
	std::cout << "        Drive Number     : " << utils::format::hex(pbs->driveNumber) << std::endl;
	std::cout << "        Reserved         : " << utils::format::hex(pbs->reserved2) << std::endl;
	std::cout << "        Ext. Boot Sign   : " << utils::format::hex(pbs->extSig) << std::endl;
	std::cout << "        Serial Nuumber   : " << utils::format::hex(pbs->serial) << std::endl;
	std::string s = std::string((char*)pbs->label);
	s.resize(11);
	std::cout << "        Volume Name      : " << s << std::endl;
	s = std::string((char*)pbs->fsName);
	s.resize(8);
	std::cout << "        FileSystem Type  : " << s << std::endl;
	std::cout << "        Volume GUID      : " << utils::id::guid_to_string(pbs->partitionGUID) << std::endl;
	std::cout << "        FVE Block 1      : " << utils::format::hex(pbs->fveBlockOffset[0]) << std::endl;
	std::cout << "        FVE Block 2      : " << utils::format::hex(pbs->fveBlockOffset[1]) << std::endl;
	std::cout << "        FVE Block 3      : " << utils::format::hex(pbs->fveBlockOffset[2]) << std::endl;
	std::cout << "        End marker       : " << utils::format::hex(pbs->endMarker, 2) << std::endl;

	std::vector<unsigned long> string_offsets;
	for (int i = 0; i < 3; i++)
	{
		BYTE offset = pbs->stringOffsets[i];
		string_offsets.push_back(offset + 0x100);
	}

	print_strings((PBYTE)pbs, string_offsets);

	unsigned int size_to_disass = 0xa0;
	while (((PBYTE)pbs)[size_to_disass - 1] == 0 && size_to_disass > 0)
	{
		size_to_disass--;
	}

	print_boot_code((PBYTE)pbs, size_to_disass, 0x7c5a);
}

void print_bootsector(std::shared_ptr<Disk> disk, std::shared_ptr<Volume> vol) {
	std::cout << std::setfill('0');
	utils::ui::title("VBR from " + disk->name() + " > Volume:" + std::to_string(vol->index()));

	if (vol->filesystem() == "FAT32") print_bootsector_fat32((PBOOT_SECTOR_FAT32)vol->bootsector());
	else if (vol->filesystem() == "FAT16") print_bootsector_fat1x((PBOOT_SECTOR_FAT1X)vol->bootsector());
	else if (vol->filesystem() == "FAT12") print_bootsector_fat1x((PBOOT_SECTOR_FAT1X)vol->bootsector());
	else if (vol->filesystem() == "NTFS") print_bootsector_ntfs((PBOOT_SECTOR_NTFS)vol->bootsector());
	else if (vol->filesystem() == "Bitlocker") print_bootsector_bitlocker((PBOOT_SECTOR_BITLOCKER)vol->bootsector());
	else
	{
		std::cout << "[!] Unsupported BootSector: " << std::string((PCHAR)((PBOOT_SECTOR_COMMON)vol->bootsector())->oemID) << std::endl;
	}
}

namespace commands {
	namespace vbr {
		int print_vbr(std::shared_ptr<Options> opts)
		{
			std::ios_base::fmtflags flag_backup(std::cout.flags());

			std::shared_ptr<Disk> disk = get_disk(opts);
			if (disk != nullptr)
			{
				std::shared_ptr<Volume> volume = disk->volumes(opts->volume);
				if (volume != nullptr)
				{
					print_bootsector(disk, volume);
				}
			}

			std::cout.flags(flag_backup);
			return 0;
		}
	}
}