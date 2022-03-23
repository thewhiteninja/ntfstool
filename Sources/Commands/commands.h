#pragma once

#include <cstdint>

#include "Utils/utils.h"
#include "NTFS/ntfs_mft.h"
#include "NTFS/ntfs_mft_record.h"
#include "options.h"

#include <memory>

namespace commands {

	namespace helpers
	{
		int is_ntfs(std::shared_ptr<Disk> disk, std::shared_ptr<Volume> vol);

		std::shared_ptr<MFTRecord> find_record(std::shared_ptr<NTFSExplorer> ex, std::shared_ptr<Options> opts);
	}

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
		namespace backup
		{
			int dispatch(std::shared_ptr<Options> opts);
		}
		namespace decrypt
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
		namespace dump
		{
			int dispatch(std::shared_ptr<Options> opts);
		}
		namespace analyze
		{
			int dispatch(std::shared_ptr<Options> opts);
		}
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

	namespace mft
	{
		namespace record
		{
			int dispatch(std::shared_ptr<Options> opts);
		}

		namespace dump
		{
			int dispatch(std::shared_ptr<Options> opts);
		}

		namespace btree
		{
			int dispatch(std::shared_ptr<Options> opts);
		}

		std::vector<std::string> print_attribute_index_root(PMFT_RECORD_ATTRIBUTE_INDEX_ROOT pAttribute, std::vector<std::shared_ptr<IndexEntry>> entries);

		std::vector<std::string> print_attribute_index_allocation(PMFT_RECORD_ATTRIBUTE_HEADER pIndexAttrHeader, std::shared_ptr<MFTRecord> record, ULONG32 cluster_size, std::vector<std::shared_ptr<IndexEntry>> entries, bool full = false);

		int print_mft_info_details(std::shared_ptr<MFTRecord> record, ULONG32 cluster_size);
	}

	namespace bitlocker
	{
		namespace info
		{
			int dispatch(std::shared_ptr<Options> opts);
		}
		namespace decrypt
		{
			int dispatch(std::shared_ptr<Options> opts);
		}
		namespace fve
		{
			int dispatch(std::shared_ptr<Options> opts);
		}
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