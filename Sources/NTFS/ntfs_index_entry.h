#pragma once

#include <winsock2.h>
#include <Windows.h>

#include "ntfs.h"

#include <string>

class IndexEntry
{
private:
	DWORD64		_reference;
	DWORD64		_parent_reference;
	std::wstring _name;
	USHORT      _flags;
	DWORD64		_vcn;
	UCHAR		_name_type;

public:
	explicit IndexEntry(PMFT_RECORD_ATTRIBUTE_INDEX_ENTRY e);

	UCHAR	name_type() const { return _name_type; }

	DWORD64	vcn() const { return _vcn; }

	DWORD64 record_number() const { return _reference & 0xffffffffffff; }

	DWORD64 parent_record_number() const { return _parent_reference & 0xffffffffffff; }

	std::wstring name() const { return _name; }

	bool has_subnode() const { return _flags & MFT_ATTRIBUTE_INDEX_ENTRY_FLAG_SUBNODE; }

	bool is_last() const { return _flags & MFT_ATTRIBUTE_INDEX_ENTRY_FLAG_LAST; }
};
