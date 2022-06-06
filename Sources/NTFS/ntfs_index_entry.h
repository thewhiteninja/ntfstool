#pragma once


#include <Windows.h>

#include "ntfs.h"

#include <string>

class IndexEntry
{
private:
	DWORD64		_reference;
	DWORD64		_parent_reference;
	std::wstring _name;
	DWORD64		_vcn;
	UCHAR		_name_type;
	DWORD       _tag;
	USHORT		_flags;

	std::string _type;

public:
	explicit IndexEntry(PMFT_RECORD_ATTRIBUTE_INDEX_ENTRY e, std::string type);

	std::string type() const { return _type; }

	UCHAR	name_type() const { return _name_type; }

	DWORD64	vcn() const { return _vcn; }
	DWORD	tag() const { return _tag; }
	USHORT	flags() const { return _flags; }

	DWORD64 record_number() const { return _reference & 0xffffffffffff; }

	DWORD64 parent_record_number() const { return _parent_reference & 0xffffffffffff; }

	std::wstring name() const { return _name; }
};
