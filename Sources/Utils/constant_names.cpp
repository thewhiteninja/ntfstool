#include "Utils/constant_names.h"
#include "Utils/utils.h"
#include "Drive/mbr_gpt.h"
#include "Bitlocker/bitlocker.h"
#include "NTFS/ntfs.h"

#include <map>
#include <vss.h>



std::string constants::disk::smart::attribute_name(DWORD index)
{
	const std::map<DWORD, const PCHAR> attribute_name_map = {
		{0,    "Invalid"},
		{ 1,   "Read Error Rate" },
		{ 2,   "Throughput Performance" },
		{ 3,   "Spin Up Time" },
		{ 4,   "Start/Stop Count" },
		{ 5,   "Reallocated Sector Count" },
		{ 6,   "Read Channel Margin" },
		{ 7,   "Seek Error Rate" },
		{ 8,   "Seek Timer Performance" },
		{ 9,   "Power-On Hours Count" },
		{ 10,  "Spin Up Retry Count" },
		{ 11,  "Calibration Retry Count" },
		{ 12,  "Power Cycle Count" },
		{ 13,  "Soft Read Error Rate" },
		{ 22,  "Current Helium Level" },
		{ 160, "Uncorrectable Sector Count R/W" },
		{ 161, "Remaining Spare Block Percentage" },
		{ 164, "Total Erase Count" },
		{ 165, "Maximum Erase Count" },
		{ 166, "Minimum Erase Count" },
		{ 167, "Average Erase Count" },
		{ 168, "Max Nand Erase Count" },
		{ 169, "Remaining Life Percentage" },
		{ 170, "Available Reserved Space" },
		{ 171, "Ssd Program Fail Count" },
		{ 172, "Ssd Erase Fail Count" },
		{ 173, "Ssd Wear Leveling Count" },
		{ 174, "Unexpected Power Loss Count" },
		{ 175, "Power Loss Protection Failure" },
		{ 176, "Erase Fail Count" },
		{ 177, "Wear Range Delta" },
		{ 178, "Used Reserved Block Count (Chip)" },
		{ 179, "Used Reserved Block Count (Total)" },
		{ 180, "Unused Reserved Block Count Total" },
		{ 181, "Program Fail Count Total" },
		{ 182, "Erase Fail Count" },
		{ 183, "Sata Down Shift Error Count" },
		{ 184, "End-To-End Error" },
		{ 185, "Head Stability" },
		{ 186, "Induced Op Vibration Detection" },
		{ 187, "Reported Uncorrectable Errors" },
		{ 188, "Command Timeout" },
		{ 189, "High Fly Writes" },
		{ 190, "Temperature Difference From 100" },
		{ 191, "G-Sense Error Rate" },
		{ 192, "Power-Off Retract Count" },
		{ 193, "Load/Unload Cycle Count" },
		{ 194, "Temperature" },
		{ 195, "Hardware Ecc Recovered" },
		{ 196, "Reallocation Count" },
		{ 197, "Current Pending Sector Count" },
		{ 198, "Off-Line Scan Uncorrectable Count" },
		{ 199, "Udma Crc Error Rate" },
		{ 200, "Write Error Rate" },
		{ 201, "Soft Read Error Rate" },
		{ 202, "Data Address Mark Errors" },
		{ 203, "Run Out Cancel" },
		{ 204, "Soft Ecc Correction" },
		{ 205, "Thermal Asperity Rate (Tar)" },
		{ 206, "Flying Height" },
		{ 207, "Spin High Current" },
		{ 208, "Spin Buzz" },
		{ 209, "Off-Line Seek Performance" },
		{ 211, "Vibration During Write" },
		{ 212, "Shock During Write" },
		{ 220, "Disk Shift" },
		{ 221, "G-Sense Error Rate" },
		{ 222, "Loaded Hours" },
		{ 223, "Load/Unload Retry Count" },
		{ 224, "Load Friction" },
		{ 225, "Load/Unload Cycle Count" },
		{ 226, "Load-In Time" },
		{ 227, "Torque Amplification Count" },
		{ 228, "Power-Off Retract Count" },
		{ 230, "Life Curve Status" },
		{ 231, "Ssd Life Left" },
		{ 232, "Endurance Remaining" },
		{ 233, "Media Wear Out Indicator" },
		{ 234, "Average Erase Count And Maximum Erase Count" },
		{ 235, "Good Block Count And System Free Block Count" },
		{ 240, "Head Flying Hours" },
		{ 241, "Lifetime Writes From Host Gib" },
		{ 242, "Lifetime Reads From Host Gib" },
		{ 243, "Total Lbas Written Expanded" },
		{ 244, "Total Lbas Read Expanded" },
		{ 249, "Nand Writes Gib" },
		{ 250, "Read Error Retry Rate" },
		{ 251, "Minimum Spares Remaining" },
		{ 252, "Newly Added Bad Flash Block" },
		{ 254, "Free Fall Protection" }
	};

	if (attribute_name_map.find(index) != attribute_name_map.end())
	{
		return attribute_name_map.find(index)->second;
	}
	else
	{
		return "Unknown";
	}
}

std::string constants::disk::smart::devicemap_type(DWORD type)
{
	switch (type)
	{
	case 1 << 0:
		return TEXT("SATA/IDE Master on primary channel");
	case 1 << 1:
		return TEXT("IDE Subordinate on primary channel");
	case 1 << 2:
		return TEXT("IDE Master on secondary channel");
	case 1 << 3:
		return TEXT("IDE Subordinate on secondary channel");
	case 1 << 4:
		return TEXT("ATAPI Master on primary channel");
	case 1 << 5:
		return TEXT("ATAPI Subordinate on primary channel");
	case 1 << 6:
		return TEXT("ATAPI Master on secondary channel");
	case 1 << 7:
		return TEXT("ATAPI Subordinate on secondary channel");
	default:
		return TEXT("UNKNOWN");
	}
}

std::string constants::disk::smart::capabilities(DWORD cap)
{
	std::vector<std::string> ret;

	const std::map<DWORD, const PCHAR> capabilities_map = {
		{ CAP_ATA_ID_CMD, "ATA"},
		{ CAP_ATAPI_ID_CMD, "ATAPI"},
		{ CAP_SMART_CMD, "S.M.A.R.T"}
	};

	for (auto& c : capabilities_map)
	{
		if (cap & c.first) ret.push_back(c.second);
	}

	return utils::strings::join(ret, ", ");
}


std::string constants::disk::mft::file_record_filename_name_type(UCHAR t)
{
	switch (t)
	{
	case 0:
		return TEXT("POSIX");
	case 1:
		return TEXT("WIN32");
	case 2:
		return TEXT("DOS");
	case 3:
		return TEXT("DOS & WIN32");
	default:
		return TEXT("UNKNOWN");
	}
}


std::string constants::disk::partition_type(DWORD t)
{
	switch (t)
	{
	case PARTITION_STYLE_GPT:
		return TEXT("GPT");
	case PARTITION_STYLE_MBR:
		return TEXT("MBR");
	case PARTITION_STYLE_RAW:
		return TEXT("RAW");
	default:
		return TEXT("UNKNOWN");
	}
}

std::string constants::disk::drive_type(DWORD t)
{
	switch (t)
	{
	case DRIVE_UNKNOWN:
		return TEXT("UNKNOWN");
	case DRIVE_NO_ROOT_DIR:
		return TEXT("No mounted volume");
	case DRIVE_REMOVABLE:
		return TEXT("Removable");
	case DRIVE_FIXED:
		return TEXT("Fixed");
	case DRIVE_REMOTE:
		return TEXT("Remote");
	case DRIVE_CDROM:
		return TEXT("CD-ROM");
	case DRIVE_RAMDISK:
		return TEXT("RAM disk");
	default:
		return TEXT("UNKNOWN");
	}
}

std::string constants::disk::mbr_type(uint8_t type) {
	const char* mbr_types[] = {
		//		00							01								02							03							04					05					06							07								08								09					0A						0B									0C								0D						0E							0F
		/*00*/	"Unused",				"FAT12",						"XENIX root",				"XENIX usr",				"FAT16",			"DOS Extended",	"FAT16 (huge)",			"NTFS / exFAT",				"DELL (spanning) / AIX Boot",	"AIX Data",		"OS/2 Boot / OPUS",	"FAT32",							"FAT32 (LBA)",					NULL,					"FAT16 (LBA)",				"DOS Extended (LBA)",
		/*10*/	NULL,						"FAT12 (hidden)",				"Config / Diagnostics",	NULL,						"FAT16 (hidden)",	NULL,				"FAT16 (huge, hidden)",	"NTFS / exFAT (hidden)",		NULL,							NULL,				NULL,					"FAT32 (hidden)",					"FAT32 (LBA, hidden)",			NULL,					"FAT16 (LBA, hidden)",		NULL,
		/*20*/	NULL,						NULL,							NULL,						NULL,						NULL,				NULL,				NULL,						"Rescue (FAT32 or NTFS)",		NULL,							NULL,				"AFS",					"SylStor",							NULL,							NULL,					NULL,						NULL,
		/*30*/	NULL,						NULL,							NULL,						NULL,						NULL,				"JFS",				NULL,						NULL,							"THEOS",						"THEOS",			"THEOS",				"THEOS",							"PartitionMagic Recovery",		"Netware (hidden)",	NULL,						NULL,
		/*40*/	"Pick",					"PPC PReP / RISC Boot",		"LDM/SFS",					NULL,						"GoBack",			"Boot-US",			NULL,						NULL,							NULL,							NULL,				NULL,					NULL,								"Oberon",						"QNX4.x",				"QNX4.x",					"QNX4.x",
		/*50*/	"Lynx RTOS",				"Novell",						NULL,						"DM 6.0 Aux3",				"DM 6.0 DDO",		"EZ-Drive",		"FAT (AT&T MS-DOS)",		"DrivePro",					NULL,							NULL,				NULL,					NULL,								NULL,							NULL,					NULL,						NULL,
		/*60*/	NULL,						"SpeedStor",					NULL,						"UNIX",					"Netware 2",		"Netware 3/4",		"Netware SMS",				"Novell",						"Novell",						"Netware 5+, NSS",	NULL,					NULL,								NULL,							NULL,					NULL,						NULL,
		/*70*/	"DiskSecure Multi-Boot",	NULL,							"V7/x86",					NULL,						"Scramdisk",		"IBM PC/IX",		NULL,						"M2FS/M2CS",					"XOSL FS",						NULL,				NULL,					NULL,								NULL,							NULL,					NULL,						NULL,
		/*80*/	"NTFT",					"MINIX",						"Linux Swap / Solaris",	"Linux",					"Hibernation",		"Linux Extended",	"FAT16 (fault tolerant)",	"NTFS (fault tolerant)",		"Linux plaintext part tbl",	NULL,				"Linux Kernel",		"FAT32 (fault tolerant)",			"FAT32 (LBA, fault tolerant)",	"FAT12 (hidden, fd)",	"Linux LVM",				NULL,
		/*90*/	"FAT16 (hidden, fd)",		"DOS Extended (hidden, fd)",	"FAT16 (huge, hidden, fd)","Hidden Linux",			NULL,				NULL,				"CHRP ISO-9660",			"FAT32 (hidden, fd)",			"FAT32 (LBA, hidden, fd)",		NULL,				"FAT16 (hidden, fd)",	"DOS Extended (LBA, hidden, fd)",	NULL,							NULL,					"ForthOS",					"BSD/OS",
		/*A0*/	"Hibernation",				"Hibernation",					NULL,						NULL,						NULL,				"BSD",				"OpenBSD",					"NeXTStep",					"Mac OS-X",					"NetBSD",			NULL,					"Mac OS-X Boot",					NULL,							NULL,					NULL,						"MacOS X HFS",
		/*B0*/	"BootStar Dummy",			"QNX Neurtino Power-Safe",		"QNX Neurtino Power-Safe",	"QNX Neurtino Power-Safe",	NULL,				NULL,				"Corrupted FAT16",			"BSDI / Corrupted NTFS",		"BSDI Swap",					NULL,				NULL,					"Acronis Boot Wizard Hidden",		"Acronis Backup",				NULL,					"Solaris 8 Boot",			"Solaris",
		/*C0*/	"Valid NTFT",				NULL,							"Hidden Linux",			"Hidden Linux Swap",		NULL,				NULL,				"Corrupted FAT16",			"Syrinx Boot / Corrupted NTFS",NULL,							NULL,				NULL,					NULL,								NULL,							NULL,					NULL,						NULL,
		/*D0*/	NULL,						NULL,							NULL,						NULL,						NULL,				NULL,				NULL,						NULL,							"CP/M",						NULL,				"Powercopy Backup",	"CP/M",							NULL,							NULL,					"Dell PowerEdge Server",	"BootIt EMBRM",
		/*E0*/	NULL,						NULL,							NULL,						NULL,						NULL,				NULL,				NULL,						NULL,							"LUKS",						NULL,				NULL,					"BeOS BFS",						"SkyOS SkyFS",					NULL,					"EFI Header",				"EFI",
		/*F0*/	"Linux/PA-RISC Boot",		NULL,							NULL,						NULL,						NULL,				NULL,				NULL,						NULL,							NULL,							NULL,				"Bochs",				"VMware",							"VMware Swap",					"Linux RAID",			"Windows NT (hidden)",		"Xenix Bad Block Table",
	};
	return mbr_types[type];
}

std::string constants::disk::gpt_type(GUID type) {
	const GUID gpt_guids[] = {
		PARTITION_ENTRY_UNUSED_GUID, PARTITION_MBR_SCHEME_GUID, PARTITION_SYSTEM_GUID, PARTITION_BIOS_BOOT_GUID,
		PARTITION_MSFT_RESERVED_GUID, PARTITION_BASIC_DATA_GUID, PARTITION_LDM_METADATA_GUID, PARTITION_LDM_DATA_GUID, PARTITION_MSFT_RECOVERY_GUID, PARTITION_IBM_GPFS_GUID,
		PARTITION_HPUX_DATA_GUID, PARTITION_HPUX_SERVICE_GUID,
		/*PARTITION_LINUX_DATA_GUID,*/ PARTITION_LINUX_RAID_GUID, PARTITION_LINUX_SWAP_GUID, PARTITION_LINUX_LVM_GUID, PARTITION_LINUX_RESERVED_GUID,
		PARTITION_FREEBSD_BOOT_GUID, PARTITION_FREEBSD_DATA_GUID, PARTITION_FREEBSD_SWAP_GUID, PARTITION_FREEBSD_UFS_GUID, PARTITION_FREEBSD_VINUM_VM_GUID, PARTITION_FREEBSD_ZFS_GUID,
		PARTITION_APPLE_HFSP_GUID, PARTITION_APPLE_UFS_GUID, /*PARTITION_APPLE_ZFS_GUID,*/ PARTITION_APPLE_RAID_GUID, PARTITION_APPLE_RAID_OFFLINE_GUID, PARTITION_APPLE_BOOT_GUID, PARTITION_APPLE_LABEL_GUID, PARTITION_APPLE_TV_RECOVERY_GUID,
		PARTITION_SOLARIS_BOOT_GUID, PARTITION_SOLARIS_ROOT_GUID, PARTITION_SOLARIS_SWAP_GUID, PARTITION_SOLARIS_BACKUP_GUID, PARTITION_SOLARIS_USR_GUID, PARTITION_SOLARIS_VAR_GUID, PARTITION_SOLARIS_HOME_GUID, PARTITION_SOLARIS_ALTERNATE_GUID, PARTITION_SOLARIS_RESERVED_1_GUID, PARTITION_SOLARIS_RESERVED_2_GUID, PARTITION_SOLARIS_RESERVED_3_GUID, PARTITION_SOLARIS_RESERVED_4_GUID, PARTITION_SOLARIS_RESERVED_5_GUID,
		PARTITION_NETBSD_SWAP_GUID, PARTITION_NETBSD_FFS_GUID, PARTITION_NETBSD_LFS_GUID, PARTITION_NETBSD_RAID_GUID, PARTITION_NETBSD_CONCATENATED_GUID, PARTITION_NETBSD_ENCRYPTED_GUID,
		PARTITION_CHROME_KERNEL_GUID, PARTITION_CHROME_ROOTFS_GUID, PARTITION_CHROME_RESERVED_GUID,
	};

	const char* gpt_types[] = {
		"Entry Unused", "MBR Partition Scheme", "EFI System", "BIOS Boot",
		"Microsoft Reserved", "Basic Data", "LDM Metadata", "LDM Data", "WinRE", "IBM GPFS",
		"HPUX Data", "HPUX Service",
		/*"Linux Data",*/ "Linux RAID", "Linux Swap", "Linux LVM", "Linux Reserved",
		"FreeBSD Boot", "FreeBSD Data", "FreeBSD Swap", "FreeBSD UFS", "FreeBSD Vinum VM", "FreeBSD ZFS",
		"Apple HFS+", "Apple UFS", /*"Apple ZFS",*/ "Apple RAID", "Apple RAID Offline", "Apple Boot", "Apple Labe", "Apple TV Recovery",
		"Solaris Boot", "Solaris Root", "Solaris Swap", "Solaris Backup", "Solaris /usr", "Solaris /var", "Solaris /home", "Solaris Alternate", "Solaris Reserved", "Solaris Reserved", "Solaris Reserved", "Solaris Reserved", "Solaris Reserved",
		"NetBSD Swap", "NetBSD FFS", "NetBSD LFS", "NetBSD RAID", "NetBSD Concatenated", "NetBSD Encrypted",
		"ChromeOS Kerne", "ChromeOS rootfs", "ChromeOS Reserved",
	};

	size_t j;
	std::string ret = "Unknown";
	for (j = 0; j < ARRAYSIZE(gpt_guids); ++j) {
		if (IsEqualGUID(type, gpt_guids[j])) {
			ret = gpt_types[j];
			break;
		}
	}

	return ret;
}

std::string constants::disk::media_type(MEDIA_TYPE t)
{
	switch (t) {
	case FixedMedia:
		return "Fixed";
	case RemovableMedia:
		return TEXT("Removable");
	case Unknown:
		return TEXT("Unknown");
	case F5_1Pt2_512:
		return TEXT("5.25\", 1.2MB");
	case F3_1Pt44_512:
		return TEXT("3.5\", 1.44MB");
	case F3_2Pt88_512:
		return TEXT("3.5\", 2.88MB");
	case F3_20Pt8_512:
		return TEXT("3.5\", 20.8MB");
	case F3_720_512:
		return TEXT("3.5\", 720KB");
	case 	F5_360_512:
		return TEXT("5.25\", 360KB");
	case 	F5_320_512:
		return TEXT("5.25\", 320KB");
	case 	F5_320_1024:
		return TEXT("5.25\", 320KB");
	case 	F5_180_512:
		return TEXT("5.25\", 180KB");
	case 	F5_160_512:
		return TEXT("5.25\", 160KB");
	case 	F3_120M_512:
		return TEXT("3.5\", 120M");
	case 	F3_640_512:
		return TEXT("3.5\" , 640KB");
	case 	F5_640_512:
		return TEXT("5.25\", 640KB");
	case 	F5_720_512:
		return TEXT("5.25\", 720KB");
	case 	F3_1Pt2_512:
		return TEXT("3.5\" , 1.2Mb");
	case 	F3_1Pt23_1024:
		return TEXT("3.5\" , 1.23Mb");
	case 	F5_1Pt23_1024:
		return TEXT("5.25\", 1.23MB");
	case 	F3_128Mb_512:
		return TEXT("3.5\" MO 128Mb");
	case 	F3_230Mb_512:
		return TEXT("3.5\" MO 230Mb");
	case 	F8_256_128:
		return TEXT("8\", 256KB");
	case 	F3_200Mb_512:
		return TEXT("3.5\", 200M");
	case 	F3_240M_512:
		return TEXT("3.5\", 240Mb");
	case 	F3_32M_512:
		return TEXT("3.5\", 32Mb");
	default:
		return TEXT("Unknown");
	}
}

std::string constants::bitlocker::state(DWORD s)
{
	switch (s)
	{
	case 0: return "NULL";
	case 1: return "DECRYPTED";
	case 2: return "SWITCHING_ENCRYPTION";
	case 3: return "EOW_ACTIVATED";
	case 4: return "ENCRYPTED";
	case 5: return "SWITCH_ENCRYPTION_PAUSED";
	default:
		return "UNKNOWN";
	}
}

std::string constants::bitlocker::algorithm(DWORD a)
{
	switch (a)
	{
	case 0:
		return "NULL";
	case 0x1000:
	case 0x1001:
		return "STRETCH KEY";
	case 0x2000:
	case 0x2001:
	case 0x2002:
	case 0x2003:
	case 0x2004:
	case 0x2005:
		return "AES-CCM-256";
	case 0x8000:
		return "AES-CBC-128-DIFFUSER";
	case 0x8001:
		return "AES-CBC-256-DIFFUSER";
	case 0x8002:
		return "AES-CBC-128-NODIFFUSER";
	case 0x8003:
		return "AES-CBC-256-NODIFFUSER";
	case 0x8004:
		return "AES-XTS-128";
	case 0x8005:
		return "AES-XTS-256";
	default:
		return "UNKNOWN";
	}
}

std::string constants::bitlocker::fve_entry_type(ULONG32 t)
{
	switch (t)
	{
	case FVE_METADATA_ENTRY_TYPE_PROPERTY: return "Property";
	case FVE_METADATA_ENTRY_TYPE_VMK: return "VMK";
	case FVE_METADATA_ENTRY_TYPE_FKEV: return "FKEV";
	case FVE_METADATA_ENTRY_TYPE_VALIDATION: return "Validation";
	case FVE_METADATA_ENTRY_TYPE_STARTUP_KEY: return "Startup Key";
	case FVE_METADATA_ENTRY_TYPE_DRIVE_LABEL: return "Drive Label";
	case FVE_METADATA_ENTRY_TYPE_AUTO_UNLOCK: return "Auto Unlock";
	case FVE_METADATA_ENTRY_TYPE_VOLUME_HEADER_BLOCK: return "Volume Header Block";
	default:
		return "Unknown (" + utils::format::hex(t) + ")";
	}
}

std::string constants::bitlocker::fve_value_type(ULONG32 t)
{
	switch (t)
	{
	case FVE_METADATA_ENTRY_VALUE_TYPE_ERASED: return "Erased";
	case FVE_METADATA_ENTRY_VALUE_TYPE_KEY: return "Key";
	case FVE_METADATA_ENTRY_VALUE_TYPE_UNICODE_STRING: return "Unicode";
	case FVE_METADATA_ENTRY_VALUE_TYPE_STRETCH_KEY: return "Stretch Key";
	case FVE_METADATA_ENTRY_VALUE_TYPE_USE_KEY: return "Use key";
	case FVE_METADATA_ENTRY_VALUE_TYPE_AES_CCM_ENCRYPTED_KEY: return "AES-CCM";
	case FVE_METADATA_ENTRY_VALUE_TYPE_TPM_ENCODED_KEY: return "TPM Encoded";
	case FVE_METADATA_ENTRY_VALUE_TYPE_VALIDATION: return "Validation";
	case FVE_METADATA_ENTRY_VALUE_TYPE_VOLUME_MASTER_KEY: return "VMK";
	case FVE_METADATA_ENTRY_VALUE_TYPE_EXTERNAL_KEY: return "External Key";
	case FVE_METADATA_ENTRY_VALUE_TYPE_UPDATE: return "Update";
	case FVE_METADATA_ENTRY_VALUE_TYPE_ERROR: return "Error";
	case FVE_METADATA_ENTRY_VALUE_TYPE_ASYMMETRIC_ENCRYPTION: return "Asymmetric Encryption";
	case FVE_METADATA_ENTRY_VALUE_TYPE_EXPORTED_KEY: return "Exported Key";
	case FVE_METADATA_ENTRY_VALUE_TYPE_PUBLIC_KEY: return "Public Key";
	case FVE_METADATA_ENTRY_VALUE_TYPE_OFFSET_AND_SIZE: return "Offset and Size";
	case FVE_METADATA_ENTRY_VALUE_TYPE_CONCAT_HASH_KEY: return "Concat Hash Key";
	default:
		return "Unknown (" + std::to_string(t) + ")";
	}
}

std::string constants::bitlocker::fve_key_protection_type(ULONG32 t)
{
	switch (t)
	{
	case FVE_METADATA_KEY_PROTECTION_TYPE_CLEARTEXT: return "Unprotected";
	case FVE_METADATA_KEY_PROTECTION_TYPE_TPM: return "TPM";
	case FVE_METADATA_KEY_PROTECTION_TYPE_STARTUP_KEY: return "Startup Key";
	case FVE_METADATA_KEY_PROTECTION_TYPE_TPM_PIN: return "TPM and PIN";
	case FVE_METADATA_KEY_PROTECTION_TYPE_RECOVERY_PASSWORD: return "Recovery Password";
	case FVE_METADATA_KEY_PROTECTION_TYPE_PASSWORD: return "Password";
	default:
		return "Unknown (" + utils::format::hex(t) + ")";
	}
}

std::string constants::disk::mft::file_record_flags(ULONG32 f)
{
	switch (f)
	{
	case MFT_RECORD_IN_USE: return "In_use";
	case MFT_RECORD_IS_DIRECTORY: return "Directory";
	case MFT_RECORD_IN_USE | MFT_RECORD_IS_DIRECTORY: return "In_use | Directory";
	default:
		return "Unknown (" + utils::format::hex(f) + ")";
	}
}

std::string constants::disk::mft::file_record_attribute_type(ULONG32 a)
{
	switch (a)
	{
	case $STANDARD_INFORMATION: return "$STANDARD_INFORMATION";
	case $ATTRIBUTE_LIST: return "$ATTRIBUTE_LIST";
	case $FILE_NAME: return "$FILE_NAME";
	case $OBJECT_ID: return "$OBJECT_ID";
	case $SECURITY_DESCRIPTOR: return "$SECURITY_DESCRIPTOR";
	case $VOLUME_NAME: return "$VOLUME_NAME";
	case $VOLUME_INFORMATION: return "$VOLUME_INFORMATION";
	case $DATA: return "$DATA";
	case $INDEX_ROOT: return "$INDEX_ROOT";
	case $INDEX_ALLOCATION: return "$INDEX_ALLOCATION";
	case $BITMAP: return "$BITMAP";
	case $REPARSE_POINT: return "$REPARSE_POINT";
	case $EA_INFORMATION: return "$EA_INFORMATION";
	case $EA: return "$EA";
	case $LOGGED_UTILITY_STREAM: return "$LOGGED_UTILITY_STREAM";
	case $END: return "$END";
	default:
		return "Unknown (" + utils::format::hex(a) + ")";
	}
}

std::string constants::disk::mft::file_record_index_root_attribute_flag(ULONG32 f)
{
	switch (f)
	{
	case MFT_ATTRIBUTE_INDEX_ROOT_FLAG_SMALL: return "Small Index";
	case MFT_ATTRIBUTE_INDEX_ROOT_FLAG_LARGE: return "Large Index";
	default:
		return "Unknown (" + utils::format::hex(f) + ")";
	}
}

std::string constants::disk::mft::file_record_index_root_attribute_type(ULONG32 a)
{
	switch (a)
	{
	case 0x30: return "Filename";
	case 0x00: return "Reparse points";
	default:
		return "Unknown (" + utils::format::hex(a) + ")";
	}
}

std::string constants::disk::mft::file_record_reparse_point_type(ULONG32 tag)
{
	switch (tag)
	{
	case IO_REPARSE_TAG_MOUNT_POINT: return "Mount Point";
	case IO_REPARSE_TAG_HSM: return "Hierarchical Storage Manager";
	case IO_REPARSE_TAG_HSM2: return "Hierarchical Storage Manager 2";
	case IO_REPARSE_TAG_SIS: return "Single-instance Storage";
	case IO_REPARSE_TAG_WIM: return "WIM Mount";
	case IO_REPARSE_TAG_CSV: return "Clustered Shared Volumes";
	case IO_REPARSE_TAG_DFS: return "Distributed File System";
	case IO_REPARSE_TAG_SYMLINK: return "Symbolic Link";
	case IO_REPARSE_TAG_DFSR: return "DFS filter";
	case IO_REPARSE_TAG_DEDUP: return "Data Deduplication";
	case IO_REPARSE_TAG_NFS: return "Network File System";
	case IO_REPARSE_TAG_FILE_PLACEHOLDER: return "Windows Shell 8.1";
	case IO_REPARSE_TAG_WOF: return "Windows Overlay";
	case IO_REPARSE_TAG_WCI: return "Windows Container Isolation";
	case IO_REPARSE_TAG_WCI_1: return "Windows Container Isolation";
	case IO_REPARSE_TAG_GLOBAL_REPARSE: return "NPFS";
	case IO_REPARSE_TAG_CLOUD: return "Cloud Files";
	case IO_REPARSE_TAG_CLOUD_1: return "Cloud Files (1)";
	case IO_REPARSE_TAG_CLOUD_2: return "Cloud Files (2)";
	case IO_REPARSE_TAG_CLOUD_3: return "Cloud Files (3)";
	case IO_REPARSE_TAG_CLOUD_4: return "Cloud Files (4)";
	case IO_REPARSE_TAG_CLOUD_5: return "Cloud Files (5)";
	case IO_REPARSE_TAG_CLOUD_6: return "Cloud Files (6)";
	case IO_REPARSE_TAG_CLOUD_7: return "Cloud Files (7)";
	case IO_REPARSE_TAG_CLOUD_8: return "Cloud Files (8)";
	case IO_REPARSE_TAG_CLOUD_9: return "Cloud Files (9)";
	case IO_REPARSE_TAG_CLOUD_A: return "Cloud Files (A)";
	case IO_REPARSE_TAG_CLOUD_B: return "Cloud Files (B)";
	case IO_REPARSE_TAG_CLOUD_C: return "Cloud Files (C)";
	case IO_REPARSE_TAG_CLOUD_D: return "Cloud Files (D)";
	case IO_REPARSE_TAG_CLOUD_E: return "Cloud Files (E)";
	case IO_REPARSE_TAG_CLOUD_F: return "Cloud Files (F)";
	case IO_REPARSE_TAG_CLOUD_MASK: return "Cloud Files Mask";
	case IO_REPARSE_TAG_APPEXECLINK: return "AppExecLink";
	case IO_REPARSE_TAG_PROJFS: return "Windows Projected File System";
	case IO_REPARSE_TAG_STORAGE_SYNC: return "Azure File Sync";
	case IO_REPARSE_TAG_WCI_TOMBSTONE: return "Windows Container Isolation";
	case IO_REPARSE_TAG_UNHANDLED: return "Windows Container Isolation";
	case IO_REPARSE_TAG_ONEDRIVE: return "One Drive";
	case IO_REPARSE_TAG_PROJFS_TOMBSTONE: return "Windows Projected File System";
	case IO_REPARSE_TAG_AF_UNIX: return "Windows Subsystem for Linux Socket";
	default:
		return "Unknown (0x" + utils::format::hex(tag) + ")";
	}
}

std::string constants::disk::usn::reasons(DWORD reason)
{
	std::vector<std::string> ret;

	const std::map<DWORD, const PCHAR> reasons_map = {
		{ 0x1, "DATA_OVERWRITE"},
		{ 0x2, "DATA_EXTEND"},
		{ 0x4, "DATA_TRUNCATION"},
		{ 0x10, "NAMED_DATA_OVERWRITE"},
		{ 0x20, "NAMED_DATA_EXTEND"},
		{ 0x40, "NAMED_DATA_TRUNCATION"},
		{ 0x100, "FILE_CREATE"},
		{ 0x200, "FILE_DELETE"},
		{ 0x400, "EA_CHANGE"},
		{ 0x800, "SECURITY_CHANGE"},
		{ 0x1000, "RENAME_OLD_NAME"},
		{ 0x2000, "RENAME_NEW_NAME"},
		{ 0x4000, "INDEXABLE_CHANGE"},
		{ 0x8000, "BASIC_INFO_CHANGE"},
		{ 0x10000, "HARD_LINK_CHANGE"},
		{ 0x20000, "COMPRESSION_CHANGE"},
		{ 0x40000, "ENCRYPTION_CHANGE"},
		{ 0x80000, "OBJECT_ID_CHANGE"},
		{ 0x100000, "REPARSE_POINT_CHANGE"},
		{ 0x200000, "STREAM_CHANGE"},
		{ 0x80000000, "CLOSE"}
	};

	for (auto& r : reasons_map)
	{
		if (reason & r.first) ret.push_back(r.second);
	}

	return utils::strings::join(ret, "+");
}

std::string constants::disk::usn::fileattributes(DWORD attributes)
{
	std::vector<std::string> ret;

	const std::map<DWORD, const PCHAR> attributes_map = {
		{ 0x1, "READONLY"},
		{ 0x2, "HIDDEN"},
		{ 0x4, "SYSTEM"},
		{ 0x10, "DIRECTORY"},
		{ 0x20, "ARCHIVE"},
		{ 0x40, "DEVICE"},
		{ 0x80, "NORMAL"},
		{ 0x100, "TEMPORARY"},
		{ 0x200, "SPARSE_FILE"},
		{ 0x400, "REPARSE_POINT"},
		{ 0x800, "COMPRESSED"},
		{ 0x1000, "OFFLINE"},
		{ 0x2000, "NOT_CONTENT_INDEXED"},
		{ 0x4000, "ENCRYPTED"},
		{ 0x8000, "INTEGRITY_STREAM"},
		{ 0x10000, "VIRTUAL"},
		{ 0x20000, "NO_SCRUB_DATA"},
	};

	for (auto& r : attributes_map)
	{
		if (attributes & r.first) ret.push_back(r.second);
	}

	return utils::strings::join(ret, "+");
}

std::string constants::disk::logfile::operation(WORD w)
{
	switch (w) {
	case LOG_RECORD_OP_NOOP: return "Noop";
	case LOG_RECORD_OP_COMPENSATION_LOG_RECORD: return "CompensationLogRecord";
	case LOG_RECORD_OP_INITIALIZE_FILE_RECORD_SEGMENT: return "InitializeFileRecordSegment";
	case LOG_RECORD_OP_DEALLOCATE_FILE_RECORD_SEGMENT: return "DeallocateFileRecordSegment";
	case LOG_RECORD_OP_WRITE_END_OF_FILE_RECORD_SEGMENT: return "WriteEndOfFileRecordSegment";
	case LOG_RECORD_OP_CREATE_ATTRIBUTE: return "CreateAttribute";
	case LOG_RECORD_OP_DELETE_ATTRIBUTE: return "DeleteAttribute";
	case LOG_RECORD_OP_UPDATE_RESIDENT_VALUE: return "UpdateResidentValue";
	case LOG_RECORD_OP_UPDATE_NONRESIDENT_VALUE: return "UpdateNonresidentValue";
	case LOG_RECORD_OP_UPDATE_MAPPING_PAIRS: return "UpdateMappingPairs";
	case LOG_RECORD_OP_DELETE_DIRTY_CLUSTERS: return "DeleteDirtyClusters";
	case LOG_RECORD_OP_SET_NEW_ATTRIBUTE_SIZES: return "SetNewAttributeSizes";
	case LOG_RECORD_OP_ADD_INDEX_ENTRY_ROOT: return "AddIndexEntryRoot";
	case LOG_RECORD_OP_DELETE_INDEX_ENTRY_ROOT: return "DeleteIndexEntryRoot";
	case LOG_RECORD_OP_ADD_INDEX_ENTRY_ALLOCATION: return "AddIndexEntryAllocation";
	case LOG_RECORD_OP_DELETE_INDEX_ENTRY_ALLOCATION: return "DeleteIndexEntryAllocation";
	case LOG_RECORD_OP_SET_INDEX_ENTRY_VCN_ALLOCATION: return "SetIndexEntryVCNAllocation";
	case LOG_RECORD_OP_UPDATE_FILE_NAME_ROOT: return "UpdateFileNameRoot";
	case LOG_RECORD_OP_UPDATE_FILE_NAME_ALLOCATION: return "UpdateFileNameAllocation";
	case LOG_RECORD_OP_SET_BITS_IN_NONRESIDENT_BIT_MAP: return "SetBitsInNonresidentBitMap";
	case LOG_RECORD_OP_CLEAR_BITS_IN_NONRESIDENT_BIT_MAP: return "ClearBitsInNonresidentBitMap";
	case LOG_RECORD_OP_PREPARE_TRANSACTION: return "PrepareTransaction";
	case LOG_RECORD_OP_COMMIT_TRANSACTION: return "CommitTransaction";
	case LOG_RECORD_OP_FORGET_TRANSACTION: return "ForgetTransaction";
	case LOG_RECORD_OP_OPEN_NONRESIDENT_ATTRIBUTE: return "OpenNonresidentAttribute";
	case LOG_RECORD_OP_DIRTY_PAGE_TABLE_DUMP: return "DirtyPageTableDump";
	case LOG_RECORD_OP_TRANSACTION_TABLE_DUMP: return "TransactionTableDump";
	case LOG_RECORD_OP_UPDATE_RECORD_DATA_ROOT: return "UpdateRecordDataRoot";
	default:
		return "Invalid";
	}
}

std::string constants::disk::vss::state(DWORD64 s)
{
	switch (s)
	{
	case VSS_SS_UNKNOWN: return "Unknown";
	case VSS_SS_PREPARING: return "Preparing";
	case VSS_SS_PROCESSING_PREPARE: return "Processing prepare";
	case VSS_SS_PREPARED: return "Prepared";
	case VSS_SS_PROCESSING_PRECOMMIT: return "Processing precommit";
	case VSS_SS_PRECOMMITTED: return "Precommitted";
	case VSS_SS_PROCESSING_COMMIT: return "Processing committed";
	case VSS_SS_COMMITTED: return "Committed";
	case VSS_SS_PROCESSING_POSTCOMMIT: return "Processing postcommit";
	case VSS_SS_PROCESSING_PREFINALCOMMIT: return "Processing prefinalcommit";
	case VSS_SS_PREFINALCOMMITTED: return "Prefinalcommitted";
	case VSS_SS_PROCESSING_POSTFINALCOMMIT: return "Processing postfinalcommit";
	case VSS_SS_CREATED: return "Created";
	case VSS_SS_ABORTED: return "Aborted";
	case VSS_SS_DELETED: return "Deleted";
	case VSS_SS_POSTCOMMITTED: return "Postcommitted";
	case VSS_SS_COUNT: return "Count";
	default:
		return "Unknown";
	}
}

std::vector<std::string> constants::disk::vss::flags(DWORD64 f)
{
	std::vector<std::string> ret;

	if (f & VSS_VOLSNAP_ATTR_PERSISTENT) ret.push_back("Persistent");
	if (f & VSS_VOLSNAP_ATTR_NO_AUTORECOVERY) ret.push_back("No Autorecovery");
	if (f & VSS_VOLSNAP_ATTR_CLIENT_ACCESSIBLE) ret.push_back("Client Accessible");
	if (f & VSS_VOLSNAP_ATTR_NO_AUTO_RELEASE) ret.push_back("No Auto Release");
	if (f & VSS_VOLSNAP_ATTR_NO_WRITERS) ret.push_back("No Writers");
	if (f & VSS_VOLSNAP_ATTR_TRANSPORTABLE) ret.push_back("Transportable");
	if (f & VSS_VOLSNAP_ATTR_NOT_SURFACED) ret.push_back("Not Surfaced");
	if (f & VSS_VOLSNAP_ATTR_NOT_TRANSACTED) ret.push_back("Not Transacted");
	if (f & VSS_VOLSNAP_ATTR_HARDWARE_ASSISTED) ret.push_back("Hardware Assisted");
	if (f & VSS_VOLSNAP_ATTR_DIFFERENTIAL) ret.push_back("Differential");
	if (f & VSS_VOLSNAP_ATTR_PLEX) ret.push_back("Plex");
	if (f & VSS_VOLSNAP_ATTR_IMPORTED) ret.push_back("Imported");
	if (f & VSS_VOLSNAP_ATTR_EXPOSED_LOCALLY) ret.push_back("Exposed Locally");
	if (f & VSS_VOLSNAP_ATTR_EXPOSED_REMOTELY) ret.push_back("Exposed Remotely");
	if (f & VSS_VOLSNAP_ATTR_AUTORECOVER) ret.push_back("Auto Recover");
	if (f & VSS_VOLSNAP_ATTR_ROLLBACK_RECOVERY) ret.push_back("Rollback Recovery");
	if (f & VSS_VOLSNAP_ATTR_DELAYED_POSTSNAPSHOT) ret.push_back("Delayed Postsnapshot");
	if (f & VSS_VOLSNAP_ATTR_TXF_RECOVERY) ret.push_back("TXF Recovery");
	if (f & VSS_VOLSNAP_ATTR_FILE_SHARE) ret.push_back("File Share");

	return ret;
}
