#pragma once

#include <Windows.h>

#pragma pack(push, 1)

typedef struct _BOOT_SECTOR_COMMON {
	BYTE        jump[3];
	BYTE        oemID[8];
	WORD        bytePerSector;
	BYTE        sectorPerCluster;
	WORD        reserved;
} BOOT_SECTOR_COMMON, * PBOOT_SECTOR_COMMON;

typedef struct _BOOT_SECTOR_BITLOCKER {
	BYTE        jump[3];
	BYTE        oemID[8];
	WORD        bytePerSector;
	BYTE        sectorPerCluster;
	WORD        reserved0;
	BYTE		fatCount;
	WORD		rootMaxEntries;
	WORD		totalSectorsSmall;
	BYTE		mediaType;
	WORD		sectorsPerFatSmall;
	WORD		sectorsPerTrack;
	WORD		headCount;
	DWORD		fsOffset;
	DWORD		totalSectors;
	DWORD		sectorsPerFat;
	WORD		fatFlags;
	WORD		version;
	DWORD		rootCluster;
	WORD		fsInfoSector;
	WORD		backupSector;
	ULONG32		reserved1[3];
	BYTE		driveNumber;
	BYTE		reserved2;
	BYTE		extSig;
	ULONG32		serial;
	CHAR		label[11];
	CHAR		fsName[8];
	CHAR	    bootCode[70];
	GUID		partitionGUID;
	DWORD64		fveBlockOffset[3];
	CHAR	    bootCode2[307];
	BYTE		stringOffsets[3];
	BYTE		endMarker[2];
} BOOT_SECTOR_BITLOCKER, * PBOOT_SECTOR_BITLOCKER;

typedef struct {
	BYTE	jump[3];
	char    oemID[8];
	WORD	bytesPerSector;
	BYTE	sectorsPerCluster;
	WORD	reservedSectorCount;
	BYTE	fatCount;
	WORD	rootDirEntryCount;
	WORD	totalSectors16;
	BYTE	mediaType;
	WORD	sectorsPerFat16;
	WORD	sectorsPerTrack;
	WORD	headCount;
	DWORD	hidddenSectors;
	DWORD	totalSectors32;
	BYTE	driveNumber;
	BYTE	reserved1;
	BYTE	extSig;
	DWORD	volumeSerialNumber;
	char    label[11];
	char    fsName[8];
	BYTE	bootCode[448];
	BYTE	endMarker[2];
} BOOT_SECTOR_FAT1X, * PBOOT_SECTOR_FAT1X;

typedef struct {
	BYTE        jump[3];
	BYTE        oemID[8];
	WORD        bytePerSector;
	BYTE        sectorPerCluster;
	WORD        reserved0;
	BYTE		fatCount;
	WORD		rootMaxEntries;
	WORD		totalSectorsSmall;
	BYTE		mediaType;
	WORD		sectorsPerFatSmall;
	WORD		sectorsPerTrack;
	WORD		headCount;
	DWORD		fsOffset;
	DWORD		totalSectors;
	DWORD		sectorsPerFat;
	WORD		fatFlags;
	WORD		version;
	DWORD		rootCluster;
	WORD		fsInfoSector;
	WORD		backupSector;
	ULONG32		reserved1[3];
	BYTE		driveNumber;
	BYTE		reserved2;
	BYTE		extSig;
	ULONG32		volumeSerialNumber;
	CHAR		label[11];
	CHAR		fsName[8];
	CHAR		bootCode[420];
	BYTE		endMarker[2];
} BOOT_SECTOR_FAT32, * PBOOT_SECTOR_FAT32;

#pragma pack(pop)