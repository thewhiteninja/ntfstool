#pragma once

#include <WinSock2.h>
#include <Windows.h>

enum class SmartAttributeID
{
	Invalid = 0,
	ReadErrorRate = 1,
	ThroughputPerformance = 2,
	SpinUpTime = 3,
	StartStopCount = 4,
	ReallocatedSectorsCount = 5,
	ReadChannelMargin = 6,
	SeekErrorRate = 7,
	SeekTimePerformance = 8,
	PowerOnHoursCount = 9,
	SpinRetryCount = 10,
	CalibrationRetryCount = 11,
	PowerCycleCount = 12,
	SoftReadErrorRate = 13,
	CurrentHeliumLevel = 22,
	UncorrectableSectorCountReadOrWrite = 160,
	RemainingSpareBlockPercentage = 161,
	TotalEraseCount = 164,
	MaximumEraseCount = 165,
	MinimumEraseCount = 166,
	AverageEraseCount = 167,
	MaxNANDEraseCountFromSpecification = 168,
	RemainingLifePercentage = 169,
	AvailableReservedSpace = 170,
	SSDProgramFailCount = 171,
	SSDEraseFailCount = 172,
	SSDWearLevelingCount = 173,
	UnexpectedPowerLossCount = 174,
	PowerLossProtectionFailure = 175,
	EraseFailCount = 176,
	WearRangeDelta = 177,
	UsedReservedBlockCountChip = 178,
	UsedReservedBlockCountTotal = 179,
	UnusedReservedBlockCountTotal = 180,
	ProgramFailCountTotalorNon4KAlignedAccessCount = 181,
	EraseFailCountSamsung = 182,
	SATADownshiftErrorCount = 183,
	EndtoEnderror = 184,
	HeadStability = 185,
	InducedOpVibrationDetection = 186,
	ReportedUncorrectableErrors = 187,
	CommandTimeout = 188,
	HighFlyWrites = 189,
	TemperatureDifferencefrom100 = 190,
	Gsenseerrorrate = 191,
	PoweroffRetractCount = 192,
	LoadCycleCount = 193,
	Temperature = 194,
	HardwareECCRecovered = 195,
	ReallocationEventCount = 196,
	CurrentPendingSectorCount = 197,
	UncorrectableSectorCount = 198,
	UltraDMACRCErrorCount = 199,
	MultiZoneErrorRate = 200,
	OffTrackSoftReadErrorRate = 201,
	DataAddressMarkerrors = 202,
	RunOutCancel = 203,
	SoftECCCorrection = 204,
	ThermalAsperityRateTAR = 205,
	FlyingHeight = 206,
	SpinHighCurrent = 207,
	SpinBuzz = 208,
	OfflineSeekPerformance = 209,
	VibrationDuringWrite = 211,
	ShockDuringWrite = 212,
	DiskShift = 220,
	GSenseErrorRate = 221,
	LoadedHours = 222,
	LoadUnloadRetryCount = 223,
	LoadFriction = 224,
	LoadUnloadCycleCount = 225,
	LoadInTime = 226,
	TorqueAmplificationCount = 227,
	PowerOffRetractCycle = 228,
	LifeCurveStatus = 230,
	SSDLifeLeft = 231,
	EnduranceRemaining = 232,
	MediaWearoutIndicator = 233,
	AverageEraseCountANDMaximumEraseCount = 234,
	GoodBlockCountANDSystemFreeBlockCount = 235,
	HeadFlyingHours = 240,
	LifetimeWritesFromHostGiB = 241,
	LiftetimeReadsFromHostGiB = 242,
	TotalLBAsWrittenExpanded = 243,
	TotalLBAsReadExpanded = 244,
	NANDWrites1GiB = 249,
	ReadErrorRetryRate = 250,
	MinimumSparesRemaining = 251,
	NewlyAddedBadFlashBlock = 252,
	FreeFallProtection = 254
};

#define DRIVE_HEAD_REG				0xA0

#define SMART_CYL_LOW_BAD			0xF4
#define SMART_CYL_HI_BAD			0x2C

#define READ_STATUS_BUFFER_SIZE		512
#define READ_IDENTITY_BUFFER_SIZE	512

#pragma pack(push, 1)

typedef struct _IDINFO
{
	USHORT	wGenConfig;
	USHORT	wNumCyls;
	USHORT	wReserved;
	USHORT	wNumHeads;
	USHORT	wBytesPerTrack;
	USHORT	wBytesPerSector;
	USHORT	wNumSectorsPerTrack;
	USHORT	wVendorUnique[3];
	CHAR	sSerialNumber[20];
	USHORT	wBufferType;
	USHORT	wBufferSize;
	USHORT	wECCSize;
	CHAR	sFirmwareRev[8];
	CHAR	sModelNumber[40];
	USHORT	wMoreVendorUnique;
	USHORT	wDoubleWordIO;
	struct {
		USHORT	Reserved : 8;
		USHORT	DMA : 1;
		USHORT	LBA : 1;
		USHORT	DisIORDY : 1;
		USHORT	IORDY : 1;
		USHORT	SoftReset : 1;
		USHORT	Overlap : 1;
		USHORT	Queue : 1;
		USHORT	InlDMA : 1;
	} wCapabilities;
	USHORT	wReserved1;
	USHORT	wPIOTiming;
	USHORT	wDMATiming;
	struct {
		USHORT	CHSNumber : 1;
		USHORT	CycleNumber : 1;
		USHORT	UnltraDMA : 1;
		USHORT	Reserved : 13;
	} wFieldValidity;
	USHORT	wNumCurCyls;
	USHORT	wNumCurHeads;
	USHORT	wNumCurSectorsPerTrack;
	DWORD	wCurSectors;
	struct {
		USHORT	CurNumber : 8;
		USHORT	Multi : 1;
		USHORT	Reserved : 7;
	} wMultSectorStuff;
	ULONG	dwTotalSectors;
	USHORT	wSingleWordDMA;
	USHORT	wMultiWordDMA;
	struct {
		USHORT	AdvPOIModes : 8;
		USHORT	Reserved : 8;
	} wPIOCapacity;
	USHORT	wMinMultiWordDMACycle;
	USHORT	wRecMultiWordDMACycle;
	USHORT	wMinPIONoFlowCycle;
	USHORT	wMinPOIFlowCycle;
	USHORT	wReserved69[11];
	struct {
		USHORT	Reserved1 : 1;
		USHORT	ATA1 : 1;
		USHORT	ATA2 : 1;
		USHORT	ATA3 : 1;
		USHORT	ATA4 : 1;
		USHORT	ATA5 : 1;
		USHORT	ATA6 : 1;
		USHORT	ATA7 : 1;
		USHORT	ATA8 : 1;
		USHORT	ATA9 : 1;
		USHORT	ATA10 : 1;
		USHORT	ATA11 : 1;
		USHORT	ATA12 : 1;
		USHORT	ATA13 : 1;
		USHORT	ATA14 : 1;
		USHORT	Reserved2 : 1;
	} wMajorVersion;
	USHORT	wMinorVersion;
	USHORT	wReserved82[6];
	struct {
		USHORT	Mode0 : 1;
		USHORT	Mode1 : 1;
		USHORT	Mode2 : 1;
		USHORT	Mode3 : 1;
		USHORT	Mode4 : 1;
		USHORT	Mode5 : 1;
		USHORT	Mode6 : 1;
		USHORT	Mode7 : 1;
		USHORT	Mode0Sel : 1;
		USHORT	Mode1Sel : 1;
		USHORT	Mode2Sel : 1;
		USHORT	Mode3Sel : 1;
		USHORT	Mode4Sel : 1;
		USHORT	Mode5Sel : 1;
		USHORT	Mode6Sel : 1;
		USHORT	Mode7Sel : 1;
	} wUltraDMA;
	USHORT	wReserved89[167];
} IDINFO, * PIDINFO;

typedef struct
{
	BYTE index;
	WORD flags;
	BYTE value;
	BYTE worst;
	union
	{
		DWORD64 rawValue : 32;
		DWORD64 rawValue48 : 48;
	};

} SMART_ATTRIBUTE, * PSMART_ATTRIBUTE;

typedef struct
{
	BYTE attributeIndex;
	BYTE threshold;
	BYTE unused[10];
} SMART_THRESHOLD, * PSMART_THRESHOLD;

typedef struct
{
	DWORD				cBufferSize;
	DRIVERSTATUS		DriverStatus;
	BYTE				reserved[2];
	SMART_ATTRIBUTE		Attributes[1];
} SMART_OUTPUT_ATTRIBUTES, * PSMART_OUTPUT_ATTRIBUTES;

typedef struct
{
	DWORD				cBufferSize;
	DRIVERSTATUS		DriverStatus;
	BYTE				reserved[2];
	SMART_THRESHOLD		Threshold[1];
} SMART_OUTPUT_THRESHOLDS, * PSMART_OUTPUT_THRESHOLDS;

typedef struct
{
	DWORD				cBufferSize;
	DRIVERSTATUS		DriverStatus;
	IDEREGS				Status;
} SMART_OUTPUT_STATUS, * PSMART_OUTPUT_STATUS;

typedef struct
{
	DWORD				cBufferSize;
	DRIVERSTATUS		DriverStatus;
	IDINFO				Identity;
} SMART_OUTPUT_IDENTITY, * PSMART_OUTPUT_IDENTITY;

#pragma pack(pop)