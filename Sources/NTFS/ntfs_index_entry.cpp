#include "ntfs_index_entry.h"

#include "Utils/utils.h"

#include <iostream>

IndexEntry::IndexEntry(PMFT_RECORD_ATTRIBUTE_INDEX_ENTRY e, std::string type)
{
	_type = type;

	if (_type == MFT_ATTRIBUTE_INDEX_FILENAME)
	{
		_reference = e->FileReference;
		_parent_reference = e->FileName.ParentDirectory.FileRecordNumber;

		_name = std::wstring(e->FileName.Name);
		_name.resize(e->FileName.NameLength);

		_name_type = e->FileName.NameType;
	}
	if (_type == MFT_ATTRIBUTE_INDEX_REPARSE)
	{
		_reference = e->reparse.asKeys.FileReference;

		_tag = e->reparse.asKeys.ReparseTag;
	}

	_vcn = *POINTER_ADD(PLONGLONG, e, e->Length - 8);
}