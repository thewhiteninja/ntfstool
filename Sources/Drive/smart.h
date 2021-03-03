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

#pragma pack(push, 1)

typedef struct
{
	BYTE  bDriverError;
	BYTE  bIDEStatus;
	BYTE  bReserved[2];
	DWORD dwReserved[2];
} ST_DRIVERSTAT;

typedef struct
{
	BYTE index;
	WORD flags;
	BYTE value;
	BYTE worst;
	union
	{
		DWORD64 rawValue : 32;
		DWORD64 rawValue6 : 48;
	};

} ST_SMART_ATTRIBUTE, * PST_SMART_ATTRIBUTE;

typedef struct
{
	BYTE attributeIndex;
	BYTE threshold;
	BYTE unused[10];
} ST_SMART_THRESHOLD, * PST_SMART_THRESHOLD;

typedef struct
{
	DWORD				cBufferSize;
	ST_DRIVERSTAT		DriverStatus;
	BYTE				reserved[2];
	ST_SMART_ATTRIBUTE	bBuffer[1];
} ST_ATAOUTPARAM_ATTRIBUTES, * PST_ATAOUTPARAM_ATTRIBUTES;

typedef struct
{
	DWORD				cBufferSize;
	ST_DRIVERSTAT		DriverStatus;
	BYTE				reserved[2];
	ST_SMART_THRESHOLD	bBuffer[1];
} ST_ATAOUTPARAM_THRESHOLDS, * PST_ATAOUTPARAM_THRESHOLDS;

typedef struct
{
	WORD wGenConfig;
	WORD wNumCyls;
	WORD wReserved;
	WORD wNumHeads;
	WORD wBytesPerTrack;
	WORD wBytesPerSector;
	WORD wSectorsPerTrack;
	WORD wVendorUnique[3];
	BYTE sSerialNumber[20];
	WORD wBufferType;
	WORD wBufferSize;
	WORD wECCSize;
	BYTE sFirmwareRev[8];
	BYTE sModelNumber[39];
	WORD wMoreVendorUnique;
	WORD wDoubleWordIO;
	WORD wCapabilities;
	WORD wReserved1;
	WORD wPIOTiming;
	WORD wDMATiming;
	WORD wBS;
	WORD wNumCurrentCyls;
	WORD wNumCurrentHeads;
	WORD wNumCurrentSectorsPerTrack;
	WORD ulCurrentSectorCapacity;
	WORD wMultSectorStuff;
	DWORD ulTotalAddressableSectors;
	WORD wSingleWordDMA;
	WORD wMultiWordDMA;
	BYTE bReserved[127];
} ST_IDSECTOR;

#pragma pack(pop)