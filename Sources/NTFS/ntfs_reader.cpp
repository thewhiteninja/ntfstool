#include "ntfs_reader.h"

NTFSReader::NTFSReader(std::wstring volume_name, DWORD64 volume_offset) : Reader(volume_name, volume_offset)
{
	PBOOT_SECTOR_NTFS pbs = (PBOOT_SECTOR_NTFS)_boot_record;
	sizes.cluster_size = pbs->bytePerSector * pbs->sectorPerCluster;
	sizes.record_size = pbs->clusterPerRecord >= 0 ? pbs->clusterPerRecord * sizes.cluster_size : 1 << -pbs->clusterPerRecord;
	sizes.block_size = pbs->clusterPerBlock >= 0 ? pbs->clusterPerBlock * sizes.cluster_size : 1 << -pbs->clusterPerBlock;
	sizes.sector_size = pbs->bytePerSector;
}

NTFSReader::~NTFSReader()
{
}