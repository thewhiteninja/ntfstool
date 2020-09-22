#pragma once

#include <Windows.h>
#include <winternl.h>

#define MASTER_FILE_TABLE_NUMBER				(0)
#define MASTER_FILE_TABLE2_NUMBER				(1)
#define LOG_FILE_NUMBER							(2)
#define VOLUME_DASD_NUMBER						(3)
#define ATTRIBUTE_DEF_TABLE_NUMBER				(4)
#define ROOT_FILE_NAME_INDEX_NUMBER				(5)
#define BIT_MAP_FILE_NUMBER						(6)
#define BOOT_FILE_NUMBER						(7)
#define BAD_CLUSTER_FILE_NUMBER					(8)
#define QUOTA_TABLE_NUMBER						(9)
#define UPCASE_TABLE_NUMBER						(10)
#define CAIRO_NUMBER							(11)

#define FIRST_USER_FILE_NUMBER					(16)

#define RESIDENT_FORM							(0x00)
#define NON_RESIDENT_FORM						(0x01)

#define	MFT_RECORD_IN_USE						(0x0001)
#define MFT_RECORD_IS_DIRECTORY					(0x0002)

#define FILE_ATTR_READONLY  					(0x00000001)
#define FILE_ATTR_HIDDEN 						(0x00000002)
#define FILE_ATTR_SYSTEM						(0x00000004)

#define FILE_ATTR_DIRECTORY						(0x00000010)
#define FILE_ATTR_ARCHIVE						(0x00000020)
#define FILE_ATTR_DEVICE						(0x00000040)
#define FILE_ATTR_NORMAL						(0x00000080)
#define FILE_ATTR_TEMPORARY						(0x00000100)
#define FILE_ATTR_SPARSE_FILE					(0x00000200)
#define FILE_ATTR_REPARSE_POINT					(0x00000400)
#define FILE_ATTR_COMPRESSED					(0x00000800)
#define FILE_ATTR_OFFLINE						(0x00001000)
#define FILE_ATTR_NOT_CONTENT_INDEXED			(0x00002000)
#define FILE_ATTR_ENCRYPTED						(0x00004000)
#define FILE_ATTR_VALID_FLAGS					(0x00007fb7)
#define FILE_ATTR_VALID_SET_FLAGS				(0x000031a7)
#define FILE_ATTR_DUP_FILENAME_INDEX_PRESENT	(0x10000000)
#define FILE_ATTR_DUP_VIEW_INDEX_PRESENT		(0x20000000)

#define RESIDENT_FORM							(0x00)
#define NON_RESIDENT_FORM						(0x01)

#define ATTRIBUTE_FLAG_COMPRESSED				(0x0001)
#define ATTRIBUTE_FLAG_ENCRYPTED				(0x4000)
#define ATTRIBUTE_FLAG_SPARSE					(0x8000)

#define $STANDARD_INFORMATION					(0x10)
#define $ATTRIBUTE_LIST							(0x20)
#define $FILE_NAME								(0x30)
#define $OBJECT_ID								(0x40)
#define $SECURITY_DESCRIPTOR					(0x50)
#define $VOLUME_NAME							(0x60)
#define $VOLUME_INFORMATION						(0x70)
#define $DATA									(0x80)
#define $INDEX_ROOT								(0x90)
#define $INDEX_ALLOCATION						(0xA0)
#define $BITMAP									(0xB0)
#define $REPARSE_POINT							(0xC0)
#define $EA_INFORMATION							(0xD0)
#define $EA										(0xE0)
#define $LOGGED_UTILITY_STREAM					(0x100)
#define $END									(0xFFFFFFFF)

#define	FILE_RECORD_FLAG_INUSE					(0x01)
#define	FILE_RECORD_FLAG_DIR					(0x02)

#define	MFT_ATTRIBUTE_INDEX_ROOT_FLAG_SMALL		(0x00)
#define	MFT_ATTRIBUTE_INDEX_ROOT_FLAG_LARGE		(0x01)

#define $I30									(0x30)
#define MFT_ATTRIBUTE_INDEX_FILENAME			("$I30")
#define MFT_ATTRIBUTE_INDEX_REPARSE	         	("$R")

#define MFT_ATTRIBUTE_DATA_USN_NAME				("$J")

#define	MFT_ATTRIBUTE_INDEX_ENTRY_FLAG_SUBNODE	(0x01)
#define	MFT_ATTRIBUTE_INDEX_ENTRY_FLAG_LAST		(0x02)

#define MFT_DATARUN_END							(0x00)

#define MFT_LOGFILE_RESTART_AREA_FLAG_VOLUME_CLEANLY_UNMOUNTED	(0x2)
#define MFT_LOGFILE_NO_CLIENT					(0xffff)
#define MFT_LOGFILE_LOG_RECORD_HEADER_SIZE		(48)

#define LOG_RECORD_MULTI_PAGE					(1)

#define LOG_RECORD_OP_NOOP 0x00
#define LOG_RECORD_OP_COMPENSATION_LOG_RECORD 0x01
#define LOG_RECORD_OP_INITIALIZE_FILE_RECORD_SEGMENT 0x02
#define LOG_RECORD_OP_DEALLOCATE_FILE_RECORD_SEGMENT 0x03
#define LOG_RECORD_OP_WRITE_END_OF_FILE_RECORD_SEGMENT 0x04
#define LOG_RECORD_OP_CREATE_ATTRIBUTE 0x05
#define LOG_RECORD_OP_DELETE_ATTRIBUTE 0x06
#define LOG_RECORD_OP_UPDATE_RESIDENT_VALUE 0x07
#define LOG_RECORD_OP_UPDATE_NONRESIDENT_VALUE 0x08
#define LOG_RECORD_OP_UPDATE_MAPPING_PAIRS 0x09
#define LOG_RECORD_OP_DELETE_DIRTY_CLUSTERS 0x0A
#define LOG_RECORD_OP_SET_NEW_ATTRIBUTE_SIZES 0x0B
#define LOG_RECORD_OP_ADD_INDEX_ENTRY_ROOT 0x0C
#define LOG_RECORD_OP_DELETE_INDEX_ENTRY_ROOT 0x0D
#define LOG_RECORD_OP_ADD_INDEX_ENTRY_ALLOCATION 0x0E
#define LOG_RECORD_OP_DELETE_INDEX_ENTRY_ALLOCATION 0x0F
#define LOG_RECORD_OP_SET_INDEX_ENTRY_VCN_ALLOCATION 0x12
#define LOG_RECORD_OP_UPDATE_FILE_NAME_ROOT 0x13
#define LOG_RECORD_OP_UPDATE_FILE_NAME_ALLOCATION 0x14
#define LOG_RECORD_OP_SET_BITS_IN_NONRESIDENT_BIT_MAP 0x15
#define LOG_RECORD_OP_CLEAR_BITS_IN_NONRESIDENT_BIT_MAP 0x16
#define LOG_RECORD_OP_PREPARE_TRANSACTION 0x19
#define LOG_RECORD_OP_COMMIT_TRANSACTION 0x1A
#define LOG_RECORD_OP_FORGET_TRANSACTION 0x1B
#define LOG_RECORD_OP_OPEN_NONRESIDENT_ATTRIBUTE 0x1C
#define LOG_RECORD_OP_DIRTY_PAGE_TABLE_DUMP 0x1F
#define LOG_RECORD_OP_TRANSACTION_TABLE_DUMP 0x20
#define LOG_RECORD_OP_UPDATE_RECORD_DATA_ROOT 0x21

const GUID VSS_VOLUME_GUID = { 0x3808876b, 0xc176, 0x4e48, 0xb7, 0xae, 0x04, 0x04, 0x6e, 0x6c, 0xc7, 0x52 };

#pragma pack(push, 1)

typedef struct {
	GUID vssid;
	DWORD version;
	DWORD type;
	DWORD64 current_offset;
	DWORD64 relative_offset;
	DWORD64 zero0;
	DWORD64 catalog_offset;
	DWORD64 maximum_size;
	GUID volume;
	GUID shadow_copy_storage_volume;
} VSS_VOLUME_HEADER, * PVSS_VOLUME_HEADER;

typedef struct {
	DWORD64 type;
	DWORD64 volume_size;
	GUID store_guid;
	DWORD64 sequence_number;
	DWORD64 backup_schema_flags;
	DWORD64 creation_time;
	CHAR padding[72];
} VSS_CATALOG_ENTRY_2, * PVSS_CATALOG_ENTRY_2;

typedef struct {
	DWORD64 type;
	DWORD64 store_block_list_offset;
	GUID store_guid;
	DWORD64 store_header_offset;
	DWORD64 store_block_range_offset;
	DWORD64 store_current_bitmap_offset;
	DWORD64 file_id;
	DWORD64 allocated_size;
	DWORD64 store_previous_bitmap_offset;
	CHAR padding[48];
} VSS_CATALOG_ENTRY_3, * PVSS_CATALOG_ENTRY_3;

typedef struct {
	VSS_CATALOG_ENTRY_2 entry_2;
	VSS_CATALOG_ENTRY_3 entry_3;
} snapshot;

typedef struct {
	GUID vssid;
	DWORD version;
	DWORD type;
	DWORD64 offset_from_prev;
	DWORD64 current_offset;
	DWORD64 next_offset;
	CHAR padding[80];
	snapshot snapshots[1];
} VSS_CATALOG_HEADER, * PVSS_CATALOG_HEADER;


typedef struct {
	GUID vssid;
	DWORD version;
	DWORD type;
	DWORD64 offset_from_prev;
	DWORD64 current_offset;
	DWORD64 next_offset;
	DWORD64 data_size;
	CHAR padding[72];
	GUID info_type;
	GUID id;
	GUID set_id;
	DWORD state;
	DWORD count;
	DWORD64 flags;
	union {
		USHORT Length;
		WCHAR Buffer;
	} machines;
} VSS_STORE_HEADER, * PVSS_STORE_HEADER;

typedef struct {
	DWORD	magic;
	WORD	update_sequence_array_offset;
	WORD	update_sequence_array_count;
	DWORD64	chkdsk_lsn;
	DWORD	system_page_size;
	DWORD	log_page_size;
	WORD	restart_area_offset;
	WORD	minor_version;
	WORD	major_version;
} RESTART_PAGE_HEADER, * PRESTART_PAGE_HEADER;

typedef struct {
	DWORD64 current_lsn;
	WORD	log_clients;
	WORD	client_free_list;
	WORD	client_in_use_list;
	WORD	flags;
	DWORD	seq_number_bits;
	WORD	restart_area_length;
	WORD	client_array_offset;
	DWORD64	file_size;
	DWORD	last_lsn_data_length;
	WORD	log_record_header_length;
	WORD	log_page_data_offset;
	DWORD	restart_log_open_count;
	DWORD	reserved;
} RESTART_AREA, * PRESTART_AREA;

typedef struct {
	CHAR	magic[4];
	WORD	update_sequence_array_offset;
	WORD	update_sequence_array_count;
	union {
		DWORD64 last_lsn;
		DWORD64 file_offset;
	} copy;
	DWORD	flags;
	WORD	page_count;
	WORD	page_position;
	union {
		struct {
			WORD	next_record_offset;
			BYTE	reserved[6];
			DWORD64	last_end_lsn;
		}   packed;
	}   header;
} RECORD_PAGE_HEADER, * PRECORD_PAGE_HEADER;

typedef struct {
	WORD seq_number;
	WORD client_index;
} LOG_CLIENT_ID;

typedef struct {
	DWORD64	oldest_lsn;
	DWORD64	client_restart_lsn;
	WORD	prev_client;
	WORD	next_client;
	WORD	seq_number;
	BYTE	reserved[6];
	DWORD	client_name_length;
	WCHAR	client_name[64];
} LOG_CLIENT_RECORD, * PLOG_CLIENT_RECORD;

typedef struct {
	DWORD64 lsn;
	DWORD64 client_previous_lsn;
	DWORD64 client_undo_next_lsn;
	DWORD	client_data_length;
	LOG_CLIENT_ID client_id;
	DWORD	record_type;
	DWORD	transaction_id;
	WORD	flags;
	WORD	reserved_or_alignment[3];
	WORD	redo_operation;
	WORD	undo_operation;
	WORD	redo_offset;
	WORD	redo_length;
	WORD	undo_offset;
	WORD	undo_length;
	WORD	target_attribute;
	WORD	lcns_to_follow;
	WORD	record_offset;
	WORD	attribute_offset;
	WORD	mft_cluster_index;
	WORD	alignment_or_reserved;
	DWORD64 target_vcn;
	DWORD64 target_lcn;
} RECORD_LOG, * PRECORD_LOG;

typedef struct
{
	LONGLONG    offset;
	ULONGLONG   length;
} MFT_DATARUN, * PMFT_DATARUN;

typedef struct
{
	struct {
		ULONGLONG FileRecordNumber : 48;
		ULONGLONG SequenceNumber : 16;
	} ParentDirectory;
	ULONGLONG CreationTime;
	ULONGLONG ChangeTime;
	ULONGLONG LastWriteTime;
	ULONGLONG LastAccessTime;
	ULONGLONG AllocatedSize;
	ULONGLONG DataSize;
	ULONG FileAttributes;
	union
	{
		struct
		{
			USHORT PackedEaSize;
			USHORT AlignmentOrReserved;
		} EaInfo;
		ULONG ReparseTag;
	} Extended;
	UCHAR NameLength;
	UCHAR NameType;
	WCHAR Name[1];
} MFT_RECORD_ATTRIBUTE_FILENAME, * PMFT_RECORD_ATTRIBUTE_FILENAME;

typedef struct
{
	ULONG  TypeCode;
	DWORD  RecordLength;
	UCHAR  FormCode;
	UCHAR  NameLength;
	USHORT NameOffset;
	USHORT Flags;
	USHORT Instance;

	union
	{
		struct
		{
			ULONG  ValueLength;
			USHORT ValueOffset;
			UCHAR  ResidentFlags;
			UCHAR  Reserved;
		} Resident;

		struct
		{
			LONGLONG LowestVcn;
			LONGLONG HighestVcn;
			USHORT   MappingPairsOffset;
			UCHAR    CompressionUnit;
			UCHAR    Reserved[5];
			ULONGLONG AllocatedLength;
			ULONGLONG FileSize;
			ULONGLONG ValidDataLength;
			ULONGLONG TotalAllocated;
		} Nonresident;
	} Form;
} MFT_RECORD_ATTRIBUTE_HEADER, * PMFT_RECORD_ATTRIBUTE_HEADER;

typedef struct
{
	DWORD       typeID;
	WORD        recordLength;
	BYTE        nameLength;
	BYTE        nameOffset;
	LONGLONG    lowestVCN;
	LONGLONG    recordNumber;
	WORD        sequenceNumber;
	WORD        reserved;
} MFT_RECORD_ATTRIBUTE, * PMFT_RECORD_ATTRIBUTE;

typedef struct
{
	ULONGLONG	CreateTime;
	ULONGLONG	AlterTime;
	ULONGLONG	MFTTime;
	ULONGLONG	ReadTime;
	union {
		struct {
			DWORD readonly : 1;
			DWORD hidden : 1;
			DWORD system : 1;
			DWORD unused0 : 2;
			DWORD archive : 1;
			DWORD device : 1;
			DWORD normal : 1;
			DWORD temp : 1;
			DWORD sparse : 1;
			DWORD reparse : 1;
			DWORD compressed : 1;
			DWORD offline : 1;
			DWORD not_indexed : 1;
			DWORD encrypted : 1;
		} Permission;
		DWORD dword_part;
	} u;
	DWORD		MaxVersionNo;
	DWORD		VersionNo;
	DWORD		ClassId;
	DWORD		OwnerId;
	DWORD		SecurityId;
	ULONGLONG	QuotaCharged;
	ULONGLONG	USN;
} MFT_RECORD_ATTRIBUTE_STANDARD_INFORMATION, * PMFT_RECORD_ATTRIBUTE_STANDARD_INFORMATION;

typedef struct
{
	GUID		object_id;
} MFT_RECORD_ATTRIBUTE_OBJECT_ID, * PMFT_RECORD_ATTRIBUTE_OBJECT_ID;

typedef struct
{
	BYTE		bitmap[1];
} MFT_RECORD_ATTRIBUTE_BITMAP, * PMFT_RECORD_ATTRIBUTE_BITMAP;

typedef struct {
	ULONG  ReparseTag;
	USHORT ReparseDataLength;
	USHORT Reserved;
	union {
		struct {
			USHORT SubstituteNameOffset;
			USHORT SubstituteNameLength;
			USHORT PrintNameOffset;
			USHORT PrintNameLength;
			ULONG Flags;
			WCHAR PathBuffer[1];
		} SymbolicLinkReparseBuffer;
		struct {
			USHORT SubstituteNameOffset;
			USHORT SubstituteNameLength;
			USHORT PrintNameOffset;
			USHORT PrintNameLength;
			WCHAR PathBuffer[1];
		} MountPointReparseBuffer;
		struct {
			WCHAR  DataBuffer[1];
		} GenericReparseBuffer;
		struct {
			ULONG StringCount;
			WCHAR  StringBuffer[1];
		} AppExecLinkReparseBuffer;
	} DUMMYUNIONNAME;
} MFT_RECORD_ATTRIBUTE_REPARSE_POINT, * PMFT_RECORD_ATTRIBUTE_REPARSE_POINT;


typedef struct
{
	BYTE		Revision;
	BYTE		unused;
	struct {
		WORD OwnerDefaulted : 1;
		WORD GroupDefaulted : 1;
		WORD DACLPresent : 1;
		WORD DACLDefaulted : 1;
		WORD SACLPresent : 1;
		WORD SACLDefaulted : 1;
		WORD unused : 2;
		WORD DACLAutoInheritReq : 1;
		WORD SACLAutoInheritReq : 1;
		WORD DACLAutoInherit : 1;
		WORD SACLAutoInherit : 1;
		WORD DACLProtected : 1;
		WORD SACLProtected : 1;
		WORD RMControlValid : 1;
		WORD SelfRelative : 1;
	} ControlFlags;
	DWORD UserSIDOffset;
	DWORD GroupSIDOffset;
	DWORD SACLOffset;
	DWORD DACLOffset;
} MFT_RECORD_ATTRIBUTE_SECURITY_DESCRIPTOR, * PMFT_RECORD_ATTRIBUTE_SECURITY_DESCRIPTOR;

typedef struct
{
	DWORD		Magic;
	WORD		OffsetOfUS;
	WORD		SizeOfUS;
	ULONGLONG	LSN;
	ULONGLONG	VCN;
	DWORD		EntryOffset;
	DWORD		TotalEntrySize;
	DWORD		AllocEntrySize;
	BYTE		NotLeaf;
	BYTE		Padding[3];
} MFT_RECORD_ATTRIBUTE_INDEX_BLOCK, * PMFT_RECORD_ATTRIBUTE_INDEX_BLOCK;

typedef struct
{
	union
	{
		ULONGLONG FileReference;
		struct
		{
			USHORT DataOffset;
			USHORT DataLength;
			ULONG32 ReservedForZero;
		};
	};
	USHORT Length;
	USHORT AttributeLength;
	USHORT Flags;
	USHORT Reserved;
	union {
		union {
			struct {
				ULONGLONG vcn;
			} asNode;
			struct {
				ULONG32 ReparseTag;
				ULONGLONG FileReference;
			} asKeys;
		} reparse;
		MFT_RECORD_ATTRIBUTE_FILENAME FileName;
	};
} MFT_RECORD_ATTRIBUTE_INDEX_ENTRY, * PMFT_RECORD_ATTRIBUTE_INDEX_ENTRY;

typedef struct
{
	DWORD		AttrType;
	DWORD		CollRule;
	DWORD		IBSize;
	BYTE		ClustersPerIB;
	BYTE		Padding1[3];

	DWORD		EntryOffset;
	DWORD		TotalEntrySize;
	DWORD		AllocEntrySize;
	BYTE		Flags;
	BYTE		Padding2[3];
} MFT_RECORD_ATTRIBUTE_INDEX_ROOT, * PMFT_RECORD_ATTRIBUTE_INDEX_ROOT;

typedef struct
{
	CHAR        signature[4];
	WORD        updateOffset;
	WORD        updateNumber;
	LONGLONG    logFile;
	WORD        sequenceNumber;
	WORD        hardLinkCount;
	WORD        attributeOffset;
	WORD        flag;
	DWORD       usedSize;
	DWORD       allocatedSize;
	LONGLONG    baseRecord;
	WORD        nextAttributeID;
	BYTE        unsed[2];
	DWORD       MFTRecordIndex;
	WORD		updateSequenceNumber;
	WORD		updateSequenceArray[1];
} MFT_RECORD_HEADER, * PMFT_RECORD_HEADER;

typedef struct
{
	BYTE        jump[3];
	BYTE        oemID[8];
	WORD        bytePerSector;
	BYTE        sectorPerCluster;
	BYTE        reserved[2];
	BYTE        zero1[3];
	BYTE        unused1[2];
	BYTE        mediaDescriptor;
	BYTE        zeros2[2];
	WORD        sectorPerTrack;
	WORD        headNumber;
	DWORD       hiddenSector;
	BYTE        unused2[8];
	LONGLONG    totalSector;
	LONGLONG    MFTCluster;
	LONGLONG    MFTMirrCluster;
	INT8		clusterPerRecord;
	BYTE        unused4[3];
	INT8		clusterPerBlock;
	BYTE        unused5[3];
	LONGLONG    serialNumber;
	DWORD       checkSum;
	BYTE        bootCode[0x1aa];
	BYTE		endMarker[2];
} BOOT_SECTOR_NTFS, * PBOOT_SECTOR_NTFS;


#pragma pack(pop)