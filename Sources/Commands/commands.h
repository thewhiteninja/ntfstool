#pragma once

#include <cstdint>

#include "Utils/utils.h"
#include "options.h"

#include <memory>

namespace commands {

	namespace info
	{
		int print_disks(std::shared_ptr<Options> opts);

		int print_partitions(std::shared_ptr<Options> opts);
	}

	namespace mbr
	{
		int print_mbr(std::shared_ptr<Options> opts);
	}

	namespace smart
	{
		int print_smart(std::shared_ptr<Options> opts);
	}

	namespace gpt
	{
		int print_gpt(std::shared_ptr<Options> opts);
	}

	namespace logfile
	{
		int print_logfile(std::shared_ptr<Options> opts);
	}

	namespace reparse
	{
		int print_reparse(std::shared_ptr<Options> opts);
	}

	namespace image {
		int create_image(std::shared_ptr<Options> opts);
	}

	namespace shadow {
		int print_volumeshadow(std::shared_ptr<Options> opts);
	}

	namespace usn
	{
		int print_usn_journal(std::shared_ptr<Options> opts);
	}

	namespace extract
	{
		int extract_file(std::shared_ptr<Options> opts);
	}

	namespace shell
	{
		int go(std::shared_ptr<Options> opts);
	}

	namespace vbr
	{
		int print_vbr(std::shared_ptr<Options> opts);
	}

	namespace mft
	{
		int print_mft(std::shared_ptr<Options> opts);
	}

	namespace bitlocker
	{
		int print_fve(std::shared_ptr<Options> opts);

		int print_bitlocker(std::shared_ptr<Options> opts);

		int list_guid(std::shared_ptr<Options> opts);

		int test_password(std::shared_ptr<Options> opts);

		int decrypt_volume(std::shared_ptr<Options> opts);
	}

	namespace help
	{
		void print_help(char* name, std::shared_ptr<Options> opts);
	}

	namespace undelete
	{
		int print_deleted_file(std::shared_ptr<Options> opts);
	}
}