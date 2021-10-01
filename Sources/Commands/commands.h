#pragma once

#include <cstdint>

#include "Utils/utils.h"
#include "NTFS/ntfs_mft.h"
#include "NTFS/ntfs_mft_record.h"
#include "options.h"

#include <memory>

namespace commands {
	namespace info
	{
		int dispatch(std::shared_ptr<Options> opts);
	}

	namespace efs
	{
		namespace masterkey
		{
			int dispatch(std::shared_ptr<Options> opts);
		}
		namespace key
		{
			int dispatch(std::shared_ptr<Options> opts);
		}
		namespace certificate
		{
			int dispatch(std::shared_ptr<Options> opts);
		}
	}

	namespace mbr
	{
		int dispatch(std::shared_ptr<Options> opts);
	}

	namespace smart
	{
		int dispatch(std::shared_ptr<Options> opts);
	}

	namespace gpt
	{
		int dispatch(std::shared_ptr<Options> opts);
	}

	namespace logfile
	{
		int dispatch(std::shared_ptr<Options> opts);
	}

	namespace reparse
	{
		int dispatch(std::shared_ptr<Options> opts);
	}

	namespace image {
		int dispatch(std::shared_ptr<Options> opts);
	}

	namespace shadow {
		int dispatch(std::shared_ptr<Options> opts);
	}

	namespace usn
	{
		int dispatch(std::shared_ptr<Options> opts);
	}

	namespace extract
	{
		int dispatch(std::shared_ptr<Options> opts);
	}

	namespace shell
	{
		int dispatch(std::shared_ptr<Options> opts);
	}

	namespace vbr
	{
		int dispatch(std::shared_ptr<Options> opts);
	}

	namespace btree
	{
		int dispatch(std::shared_ptr<Options> opts);
	}

	namespace mft
	{
		int dispatch(std::shared_ptr<Options> opts);

		std::vector<std::string> print_attribute_index_root(PMFT_RECORD_ATTRIBUTE_INDEX_ROOT pAttribute, std::vector<std::shared_ptr<IndexEntry>> entries);

		std::vector<std::string> print_attribute_index_allocation(PMFT_RECORD_ATTRIBUTE_HEADER pIndexAttrHeader, std::shared_ptr<MFTRecord> record, ULONG32 cluster_size, std::vector<std::shared_ptr<IndexEntry>> entries, bool full = false);

		int print_mft_info_details(std::shared_ptr<MFTRecord> record, ULONG32 cluster_size);
	}

	namespace fve
	{
		int dispatch(std::shared_ptr<Options> opts);
	}

	namespace bitlocker
	{
		int dispatch(std::shared_ptr<Options> opts);
	}

	namespace bitdecrypt
	{
		int dispatch(std::shared_ptr<Options> opts);
	}

	namespace help
	{
		void dispatch(std::shared_ptr<Options> opts);
	}

	namespace streams
	{
		int dispatch(std::shared_ptr<Options> opts);
	}

	namespace undelete
	{
		int dispatch(std::shared_ptr<Options> opts);
	}
}