#include "ntfs_index_entry.h"

#include "Utils/utils.h"

#include <iostream>


IndexEntry::IndexEntry(PMFT_RECORD_ATTRIBUTE_INDEX_ENTRY e)
{
	_reference = e->FileReference;
	_parent_reference = e->FileName.ParentDirectory.FileRecordNumber;

	_name = std::wstring(e->FileName.Name);
	_name.resize(e->FileName.NameLength);

	_vcn = *POINTER_ADD(PLONGLONG, e, e->Length - 8);

	_flags = e->Flags;
}
