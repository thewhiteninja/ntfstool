#pragma once

#include <string>
#include <vector>

#include <WinSock2.h>
#include <windows.h>


namespace constants {

	namespace disk
	{
		namespace smart
		{
			std::string attribute_name(DWORD index);

			std::string devicemap_type(DWORD type);

			std::string capabilities(DWORD cap);
		}

		namespace vss
		{
			std::string state(DWORD64 s);

			std::vector<std::string> flags(DWORD64 f);
		}

		std::string partition_type(DWORD t);

		std::string media_type(MEDIA_TYPE t);

		std::string drive_type(DWORD t);

		std::string mbr_type(uint8_t type);

		std::string gpt_type(GUID type);

		namespace mft
		{
			std::string file_record_flags(ULONG32 f);

			std::string file_record_attribute_type(ULONG32 a);

			std::string file_record_index_root_attribute_type(ULONG32 a);

			std::string file_record_index_root_attribute_flag(ULONG32 f);

			std::string file_record_reparse_point_type(ULONG32 t);

			std::string file_record_filename_name_type(UCHAR t);

			std::string efs_type(ULONG32);
		}

		namespace usn
		{
			std::string reasons(DWORD r);

			std::string fileattributes(DWORD a);
		}

		namespace logfile
		{
			std::string operation(WORD w);
		}
	}

	namespace efs
	{
		std::string hash_algorithm(DWORD r);

		std::string enc_algorithm(DWORD a);

		std::vector<std::string> permissions(DWORD p);
	}

	namespace bitlocker
	{
		std::string state(DWORD s);

		std::string algorithm(DWORD a);

		std::string fve_entry_type(ULONG32 t);

		std::string fve_value_type(ULONG32 t);

		std::string fve_key_protection_type(ULONG32 t);
	}
}
