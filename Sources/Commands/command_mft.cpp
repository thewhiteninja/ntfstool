#include <iostream>
#include <iomanip>
#include <memory>

#include "Commands/commands.h"
#include "NTFS/ntfs.h"
#include "NTFS/ntfs_explorer.h"
#include "Utils/constant_names.h"
#include "Utils/table.h"

#include "options.h"
#include "Drive/disk.h"
#include "Drive/volume.h"

std::vector<std::string> print_attribute_standard(PMFT_RECORD_ATTRIBUTE_STANDARD_INFORMATION pAttribute)
{
	std::vector<std::string> ret;
	if (pAttribute != nullptr)
	{
		SYSTEMTIME st = { 0 };
		utils::times::ull_to_local_systemtime(pAttribute->CreateTime, &st);
		ret.push_back("File Created Time       : " + utils::times::display_systemtime(st));
		utils::times::ull_to_local_systemtime(pAttribute->AlterTime, &st);
		ret.push_back("Last File Write Time    : " + utils::times::display_systemtime(st));
		utils::times::ull_to_local_systemtime(pAttribute->MFTTime, &st);
		ret.push_back("FileRecord Changed Time : " + utils::times::display_systemtime(st));
		utils::times::ull_to_local_systemtime(pAttribute->ReadTime, &st);
		ret.push_back("Last Access Time        : " + utils::times::display_systemtime(st));
		ret.push_back("Permissions             :");
		ret.push_back("  read_only     : " + std::to_string(pAttribute->u.Permission.readonly));
		ret.push_back("  hidden        : " + std::to_string(pAttribute->u.Permission.hidden));
		ret.push_back("  system        : " + std::to_string(pAttribute->u.Permission.system));
		ret.push_back("  device        : " + std::to_string(pAttribute->u.Permission.device));
		ret.push_back("  normal        : " + std::to_string(pAttribute->u.Permission.normal));
		ret.push_back("  temporary     : " + std::to_string(pAttribute->u.Permission.temp));
		ret.push_back("  sparse        : " + std::to_string(pAttribute->u.Permission.sparse));
		ret.push_back("  reparse_point : " + std::to_string(pAttribute->u.Permission.reparse));
		ret.push_back("  compressed    : " + std::to_string(pAttribute->u.Permission.compressed));
		ret.push_back("  offline       : " + std::to_string(pAttribute->u.Permission.offline));
		ret.push_back("  not_indexed   : " + std::to_string(pAttribute->u.Permission.not_indexed));
		ret.push_back("  encrypted     : " + std::to_string(pAttribute->u.Permission.encrypted));
		ret.push_back("Max Number of Versions  : " + std::to_string(pAttribute->MaxVersionNo));
		ret.push_back("Version Number          : " + std::to_string(pAttribute->VersionNo));
	}
	return ret;
}

std::vector<std::string> print_attribute_index_root(PMFT_RECORD_ATTRIBUTE_INDEX_ROOT pAttribute, std::vector<std::shared_ptr<IndexEntry>> entries)
{
	std::vector<std::string> ret;
	if (pAttribute != nullptr)
	{
		ret.push_back("Attribute Type          : " + constants::disk::mft::file_record_index_root_attribute_type(pAttribute->AttrType));
		ret.push_back("Collation Rule          : " + std::to_string(pAttribute->CollRule));
		ret.push_back("Index Alloc Entry Size  : " + std::to_string(pAttribute->IBSize));
		ret.push_back("Cluster/Index Record    : " + std::to_string(pAttribute->ClustersPerIB));
		ret.push_back("-----");
		ret.push_back("First Entry Offset      : " + std::to_string(pAttribute->EntryOffset));
		ret.push_back("Index Entries Size      : " + std::to_string(pAttribute->TotalEntrySize));
		ret.push_back("Index Entries Allocated : " + std::to_string(pAttribute->AllocEntrySize));
		ret.push_back("Flags                   : " + constants::disk::mft::file_record_index_root_attribute_flag(pAttribute->Flags));

		if (pAttribute->Flags == MFT_ATTRIBUTE_INDEX_ROOT_FLAG_SMALL)
		{
			ret.push_back("Index");
			for (auto& entry : entries)
			{
				if (entry->type() == MFT_ATTRIBUTE_INDEX_FILENAME)
				{
					ret.push_back("       " + utils::format::hex(entry->record_number()) + " : " + utils::strings::to_utf8(entry->name()));
				}
				if (entry->type() == MFT_ATTRIBUTE_INDEX_REPARSE)
				{
					ret.push_back("       " + utils::format::hex(entry->record_number()) + " : " + constants::disk::mft::file_record_reparse_point_type(entry->tag()));
				}
			}
		}
	}
	return ret;
}

std::vector<std::string> print_attribute_reparse_point(PMFT_RECORD_ATTRIBUTE_REPARSE_POINT pAttribute)
{
	std::vector<std::string> ret;
	if (pAttribute != nullptr)
	{
		ret.push_back("Type                    : " + constants::disk::mft::file_record_reparse_point_type(pAttribute->ReparseTag));

		if (pAttribute->ReparseTag == IO_REPARSE_TAG_SYMLINK)
		{
			std::wstring subs_name = std::wstring(POINTER_ADD(PWCHAR, pAttribute->SymbolicLinkReparseBuffer.PathBuffer, pAttribute->SymbolicLinkReparseBuffer.SubstituteNameOffset));
			subs_name.resize(pAttribute->SymbolicLinkReparseBuffer.SubstituteNameLength / sizeof(WCHAR));
			ret.push_back("Substitute Name         : " + utils::strings::to_utf8(subs_name));
			std::wstring display_name = std::wstring(POINTER_ADD(PWCHAR, pAttribute->SymbolicLinkReparseBuffer.PathBuffer, pAttribute->SymbolicLinkReparseBuffer.PrintNameOffset));
			display_name.resize(pAttribute->SymbolicLinkReparseBuffer.PrintNameLength / sizeof(WCHAR));
			ret.push_back("Display Name            : " + utils::strings::to_utf8(display_name));
		}
		else if (pAttribute->ReparseTag == IO_REPARSE_TAG_MOUNT_POINT)
		{
			std::wstring subs_name = std::wstring(POINTER_ADD(PWCHAR, pAttribute->MountPointReparseBuffer.PathBuffer, pAttribute->MountPointReparseBuffer.SubstituteNameOffset));
			subs_name.resize(pAttribute->MountPointReparseBuffer.SubstituteNameLength / sizeof(WCHAR));
			ret.push_back("Substitute Name         : " + utils::strings::to_utf8(subs_name));
			std::wstring display_name = std::wstring(POINTER_ADD(PWCHAR, pAttribute->MountPointReparseBuffer.PathBuffer, pAttribute->MountPointReparseBuffer.PrintNameOffset));
			display_name.resize(pAttribute->MountPointReparseBuffer.PrintNameLength / sizeof(WCHAR));
			ret.push_back("Display Name            : " + utils::strings::to_utf8(display_name));
		}
		else
		{
			ret.push_back("Unsupported reparse point type");
		}
	}

	return ret;
}

std::vector<std::string> print_attribute_object_id(PMFT_RECORD_ATTRIBUTE_OBJECT_ID pAttribute)
{
	std::vector<std::string> ret;
	if (pAttribute != nullptr)
	{
		ret.push_back("Object Unique ID        : " + utils::id::guid_to_string(pAttribute->object_id));
	}
	return ret;
}

std::vector<std::string> print_attribute_security_descriptor(PMFT_RECORD_ATTRIBUTE_SECURITY_DESCRIPTOR pAttribute)
{
	std::vector<std::string> ret;
	if (pAttribute != nullptr)
	{
		ret.push_back("Revision                : " + std::to_string(pAttribute->Revision));
		ret.push_back("Control Flags           ");
		ret.push_back("  owner defaulted       : " + std::to_string(pAttribute->ControlFlags.OwnerDefaulted));
		ret.push_back("  group defaulted       : " + std::to_string(pAttribute->ControlFlags.GroupDefaulted));
		ret.push_back("  DACL present          : " + std::to_string(pAttribute->ControlFlags.DACLPresent));
		ret.push_back("  DACL defaulted        : " + std::to_string(pAttribute->ControlFlags.DACLDefaulted));
		ret.push_back("  SACL present          : " + std::to_string(pAttribute->ControlFlags.SACLPresent));
		ret.push_back("  SACL defaulted        : " + std::to_string(pAttribute->ControlFlags.SACLDefaulted));
		ret.push_back("  DACL auto inherit req : " + std::to_string(pAttribute->ControlFlags.DACLAutoInheritReq));
		ret.push_back("  SACL auto inherit req : " + std::to_string(pAttribute->ControlFlags.SACLAutoInheritReq));
		ret.push_back("  DACL auto inherit     : " + std::to_string(pAttribute->ControlFlags.DACLAutoInherit));
		ret.push_back("  SACL auto inherit     : " + std::to_string(pAttribute->ControlFlags.SACLAutoInherit));
		ret.push_back("  DACL protected        : " + std::to_string(pAttribute->ControlFlags.DACLProtected));
		ret.push_back("  SACL protected        : " + std::to_string(pAttribute->ControlFlags.SACLProtected));
		ret.push_back("  RM control valid      : " + std::to_string(pAttribute->ControlFlags.RMControlValid));
		ret.push_back("  self relative         : " + std::to_string(pAttribute->ControlFlags.SelfRelative));

		if (pAttribute->UserSIDOffset != 0)
		{
			PSID user_sid = POINTER_ADD(PSID, pAttribute, pAttribute->UserSIDOffset);
			ret.push_back("User  SID               : " + utils::id::sid_to_string(user_sid));
		}
		else
		{
			ret.push_back("User  SID               : not present");
		}
		if (pAttribute->GroupSIDOffset != 0)
		{
			PSID group_sid = POINTER_ADD(PSID, pAttribute, pAttribute->GroupSIDOffset);
			ret.push_back("Group SID               : " + utils::id::sid_to_string(group_sid));
		}
		else
		{
			ret.push_back("Group SID               : not present");
		}
		if (pAttribute->ControlFlags.SACLPresent && pAttribute->SACLOffset != 0)
		{
			PSECURITY_DESCRIPTOR psecd = POINTER_ADD(PACL, pAttribute, 0);
			LPSTR stringSD = NULL;
			ConvertSecurityDescriptorToStringSecurityDescriptor(
				psecd,
				SDDL_REVISION_1,
				SACL_SECURITY_INFORMATION,
				&stringSD,
				NULL
			);
			ret.push_back("SACL                    : " + std::string(stringSD));
			LocalFree(stringSD);
		}
		else
		{
			ret.push_back("SACL                    : not present");
		}
		if (pAttribute->ControlFlags.DACLPresent && pAttribute->DACLOffset != 0)
		{
			PSECURITY_DESCRIPTOR psecd = POINTER_ADD(PACL, pAttribute, 0);
			LPSTR stringSD = NULL;
			ConvertSecurityDescriptorToStringSecurityDescriptor(
				psecd,
				SDDL_REVISION_1,
				DACL_SECURITY_INFORMATION,
				&stringSD,
				NULL
			);
			ret.push_back("DACL                    : " + std::string(stringSD));
			LocalFree(stringSD);
		}
		else
		{
			ret.push_back("DACL                    : not present");
		}
	}
	return ret;
}

std::vector<std::string> print_attribute_filename(PMFT_RECORD_ATTRIBUTE_FILENAME pAttribute)
{
	std::vector<std::string> ret;
	if (pAttribute != nullptr)
	{
		ret.push_back("Parent Dir Record Index : " + std::to_string(pAttribute->ParentDirectory.FileRecordNumber));
		ret.push_back("Parent Dir Sequence Num : " + std::to_string(pAttribute->ParentDirectory.SequenceNumber));
		SYSTEMTIME st = { 0 };
		utils::times::ull_to_local_systemtime(pAttribute->CreationTime, &st);
		ret.push_back("File Created Time       : " + utils::times::display_systemtime(st));
		utils::times::ull_to_local_systemtime(pAttribute->LastWriteTime, &st);
		ret.push_back("Last File Write Time    : " + utils::times::display_systemtime(st));
		utils::times::ull_to_local_systemtime(pAttribute->ChangeTime, &st);
		ret.push_back("FileRecord Changed Time : " + utils::times::display_systemtime(st));
		utils::times::ull_to_local_systemtime(pAttribute->LastAccessTime, &st);
		ret.push_back("Last Access Time        : " + utils::times::display_systemtime(st));
		ret.push_back("Allocated Size          : " + std::to_string(pAttribute->AllocatedSize));
		ret.push_back("Real Size               : " + std::to_string(pAttribute->DataSize));
		ret.push_back("------");
		std::wstring name = std::wstring(pAttribute->Name);
		name.resize(pAttribute->NameLength);
		ret.push_back("NameType                : " + constants::disk::mft::file_record_filename_name_type(pAttribute->NameType));
		ret.push_back("Name                    : " + utils::strings::to_utf8(name));
	}
	return ret;
}

std::vector<std::string> print_attribute_logged_utility()
{
	std::vector<std::string> ret;
	ret.push_back("Binary data");
	return ret;
}

std::vector<std::string> print_attribute_bitmap(PMFT_RECORD_ATTRIBUTE_BITMAP pAttribute, DWORD length)
{
	std::vector<std::string> ret;
	DWORD index_node_used = 0;
	for (DWORD i = 0; i < length; i++)
	{
		BYTE b = pAttribute->bitmap[i];
		for (int bit = 0; bit < 8; bit++)
		{
			index_node_used += b & 0x01;
			b >>= 1;
		}
	}
	ret.push_back("Index Node Used         : " + std::to_string(index_node_used));
	return ret;
}

std::vector<std::string> print_attribute_data(std::shared_ptr<MFTRecord> record, PMFT_RECORD_ATTRIBUTE_HEADER pAttribute, ULONG32 cluster_size)
{
	std::vector<std::string> ret;

	std::wstring name = std::wstring(POINTER_ADD(PWCHAR, pAttribute, pAttribute->NameOffset));
	name.resize(pAttribute->NameLength);

	if (pAttribute->NameLength > 0)
	{
		ret.push_back("Name                    : " + utils::strings::to_utf8(name));
	}

	ULONG64 datasize = record->datasize(utils::strings::to_utf8(name));
	if (record->header()->baseRecord == 0)
	{
		ret.push_back("Data Size               : " + std::to_string(datasize) + " (" + utils::format::size(datasize) + ")");
	}

	if (pAttribute->FormCode == NON_RESIDENT_FORM)
	{
		if (pAttribute->Flags)
		{
			ret.push_back("Flags                   : ");

			if (pAttribute->Flags & ATTRIBUTE_FLAG_COMPRESSED)
			{
				if (pAttribute->Form.Nonresident.CompressionUnit == 0)
				{
					ret.push_back("    Compressed (Uncompressed data)");
				}
				else
				{
					ret.push_back("    Compressed (unit: " + std::to_string(1 << pAttribute->Form.Nonresident.CompressionUnit) + " clusters)");
				}
			}
			if (pAttribute->Flags & ATTRIBUTE_FLAG_ENCRYPTED) ret.push_back("    Encrypted");
			if (pAttribute->Flags & ATTRIBUTE_FLAG_SPARSE) ret.push_back("    Sparse");
		}

		auto dataruns = record->read_dataruns(pAttribute);
		if (!dataruns.empty())
		{
			ret.push_back("Dataruns                : ");
			LONGLONG last = 0;
			ULONGLONG size_on_disk = 0;
			for (const auto& run : dataruns)
			{
				if (last != run.offset)
				{
					size_on_disk += (run.length * cluster_size);
				}
				ret.push_back("    Length: " + utils::format::hex(static_cast<DWORD>(run.length)) + " Offset: " + utils::format::hex(static_cast<DWORD>(run.offset)) + (last == run.offset ? " (S)" : ""));
				last = run.offset;
			}
			ret.push_back("Size on disk            : " + std::to_string(size_on_disk) + " (" + utils::format::size(size_on_disk) + ")");
		}
	}

	return ret;
}

std::vector<std::string> print_attribute_index_allocation(std::vector<std::shared_ptr<IndexEntry>> entries)
{
	std::vector<std::string> ret;
	ret.push_back("Index");
	for (auto& entry : entries)
	{
		if (entry->type() == MFT_ATTRIBUTE_INDEX_FILENAME)
		{
			ret.push_back("       " + utils::format::hex(entry->record_number()) + " : " + utils::strings::to_utf8(entry->name()));
		}
		if (entry->type() == MFT_ATTRIBUTE_INDEX_REPARSE)
		{
			ret.push_back("       " + utils::format::hex(entry->record_number()) + " : " + constants::disk::mft::file_record_reparse_point_type(entry->tag()));
		}
	}
	return ret;
}

std::vector<std::string> print_attribute_list(PMFT_RECORD_ATTRIBUTE pAttribute, DWORD length)
{
	std::vector<std::string> ret;
	DWORD offset = 0;
	PMFT_RECORD_ATTRIBUTE pAttributeCurr;
	while (offset < length)
	{
		pAttributeCurr = POINTER_ADD(PMFT_RECORD_ATTRIBUTE, pAttribute, offset);

		ret.push_back(constants::disk::mft::file_record_attribute_type(pAttributeCurr->typeID));
		if (pAttributeCurr->nameLength > 0)
		{
			std::wstring name = std::wstring(POINTER_ADD(PWCHAR, pAttributeCurr, pAttributeCurr->nameOffset), pAttributeCurr->nameLength);
			ret.push_back("Name      : " + utils::strings::to_utf8(name));
		}

		ret.push_back("Record Num: " + utils::format::hex((ULONG64)pAttributeCurr->recordNumber));

		offset += pAttributeCurr->recordLength;

		if (offset < length)
		{
			ret.push_back("------");
		}
	}

	return ret;
}

int print_mft_info(std::shared_ptr<Disk> disk, std::shared_ptr<Volume> vol, DWORD inode)
{
	if ((vol->filesystem() != "NTFS") && (vol->filesystem() != "Bitlocker"))
	{
		std::cerr << "[!] NTFS volume required" << std::endl;
		return 1;
	}

	std::shared_ptr<NTFSExplorer> explorer = std::make_shared<NTFSExplorer>(vol);
	std::shared_ptr<MFTRecord> record = explorer->mft()->record_from_number(inode);
	PMFT_RECORD_HEADER record_header = record->header();

	utils::ui::title("MFT (inode:" + std::to_string(inode) + ") from " + disk->name() + " > Volume:" + std::to_string(vol->index()));

	std::string signature = std::string((PCHAR)record_header->signature);
	std::cout << "Signature         : " << signature.substr(0, 4) << std::endl;
	std::cout << "Update Offset     : " << record_header->updateOffset << std::endl;
	std::cout << "Update Number     : " << record_header->updateNumber << std::endl;
	std::cout << "$LogFile LSN      : " << record_header->logFile << std::endl;
	std::cout << "Sequence Number   : " << record_header->sequenceNumber << std::endl;
	std::cout << "Hardlink Count    : " << record_header->hardLinkCount << std::endl;
	std::cout << "Attribute Offset  : " << record_header->attributeOffset << std::endl;
	std::cout << "Flags             : " << constants::disk::mft::file_record_flags(record_header->flag) << std::endl;
	std::cout << "Real Size         : " << record_header->usedSize << std::endl;
	std::cout << "Allocated Size    : " << record_header->allocatedSize << std::endl;
	std::cout << "Base File Record  : " << utils::format::hex(record_header->baseRecord, true) << std::endl;
	std::cout << "Next Attribute ID : " << record_header->nextAttributeID << std::endl;
	std::cout << "MFT Record Index  : " << record_header->MFTRecordIndex << std::endl;
	std::cout << "Update Seq Number : " << record_header->updateSequenceNumber << std::endl;
	std::cout << "Update Seq Array  : ";
	for (int i = 0; i < record_header->updateNumber - 1; i++) std::cout << utils::format::hex(record_header->updateSequenceArray[i]);
	std::cout << std::endl;
	std::cout << std::endl;

	std::shared_ptr<utils::ui::Table> fr_attributes = std::make_shared<utils::ui::Table>();
	fr_attributes->set_interline(true);

	fr_attributes->add_header_line("Id");
	fr_attributes->add_header_line("Type");
	fr_attributes->add_header_line("Non-resident");
	fr_attributes->add_header_line("Length");
	fr_attributes->add_header_line("Overview");

	int n = 1;
	PMFT_RECORD_ATTRIBUTE_HEADER pAttribute = POINTER_ADD(PMFT_RECORD_ATTRIBUTE_HEADER, record_header, record_header->attributeOffset);
	while (pAttribute->TypeCode != $END)
	{
		fr_attributes->add_item_line(std::to_string(n++));
		fr_attributes->add_item_line(constants::disk::mft::file_record_attribute_type(pAttribute->TypeCode));
		fr_attributes->add_item_line((pAttribute->FormCode == NON_RESIDENT_FORM ? "True" : "False"));
		if (pAttribute->FormCode == NON_RESIDENT_FORM)
		{
			fr_attributes->add_item_line(std::to_string(pAttribute->Form.Nonresident.ValidDataLength));
		}
		else
		{
			fr_attributes->add_item_line(std::to_string(pAttribute->Form.Resident.ValueLength));
		}
		switch (pAttribute->TypeCode)
		{
		case $FILE_NAME:
		{
			PMFT_RECORD_ATTRIBUTE_FILENAME pattr = nullptr;
			if (pAttribute->FormCode == RESIDENT_FORM)
			{
				pattr = POINTER_ADD(PMFT_RECORD_ATTRIBUTE_FILENAME, pAttribute, pAttribute->Form.Resident.ValueOffset);
			}
			else
			{
				wprintf(L"Non-resident $FILENAME is not supported");
			}
			fr_attributes->add_item_multiline(print_attribute_filename(pattr));
			break;
		}
		case $STANDARD_INFORMATION:
		{
			PMFT_RECORD_ATTRIBUTE_STANDARD_INFORMATION pattr = nullptr;
			if (pAttribute->FormCode == RESIDENT_FORM)
			{
				pattr = POINTER_ADD(PMFT_RECORD_ATTRIBUTE_STANDARD_INFORMATION, pAttribute, pAttribute->Form.Resident.ValueOffset);
			}
			else
			{
				wprintf(L"Non-resident $STANDARD_INFORMATION is not supported");
			}
			fr_attributes->add_item_multiline(print_attribute_standard(pattr));
			break;
		}
		case $OBJECT_ID:
		{
			PMFT_RECORD_ATTRIBUTE_OBJECT_ID pattr = nullptr;
			if (pAttribute->FormCode == RESIDENT_FORM)
			{
				pattr = POINTER_ADD(PMFT_RECORD_ATTRIBUTE_OBJECT_ID, pAttribute, pAttribute->Form.Resident.ValueOffset);
			}
			else
			{
				wprintf(L"Non-resident $OBJECT_ID is not supported");
			};
			fr_attributes->add_item_multiline(print_attribute_object_id(pattr));
			break;
		}
		case $SECURITY_DESCRIPTOR:
		{
			PMFT_RECORD_ATTRIBUTE_SECURITY_DESCRIPTOR pattr = nullptr;
			if (pAttribute->FormCode == RESIDENT_FORM)
			{
				pattr = POINTER_ADD(PMFT_RECORD_ATTRIBUTE_SECURITY_DESCRIPTOR, pAttribute, pAttribute->Form.Resident.ValueOffset);
			}
			else
			{
				wprintf(L"Non-resident $SECURITY_DESCRIPTOR is not supported");
			};
			fr_attributes->add_item_multiline(print_attribute_security_descriptor(pattr));
			break;
		}
		case $INDEX_ROOT:
		{
			PMFT_RECORD_ATTRIBUTE_INDEX_ROOT pattr = nullptr;
			if (pAttribute->FormCode == RESIDENT_FORM)
			{
				pattr = POINTER_ADD(PMFT_RECORD_ATTRIBUTE_INDEX_ROOT, pAttribute, pAttribute->Form.Resident.ValueOffset);
			}
			else
			{
				wprintf(L"Non-resident $INDEX_ROOT is not supported");
			};
			fr_attributes->add_item_multiline(print_attribute_index_root(pattr, record->index()));
			break;
		}
		case $REPARSE_POINT:
		{
			PMFT_RECORD_ATTRIBUTE_REPARSE_POINT pattr = nullptr;
			if (pAttribute->FormCode == RESIDENT_FORM)
			{
				pattr = POINTER_ADD(PMFT_RECORD_ATTRIBUTE_REPARSE_POINT, pAttribute, pAttribute->Form.Resident.ValueOffset);
			}
			else
			{
				wprintf(L"Non-resident $REPARSE_POINT is not supported");
			}
			fr_attributes->add_item_multiline(print_attribute_reparse_point(pattr));
			break;
		}

		case $INDEX_ALLOCATION:
		{
			fr_attributes->add_item_multiline(print_attribute_index_allocation(record->index()));
			break;
		}
		case $DATA:
		{
			fr_attributes->add_item_multiline(print_attribute_data(record, pAttribute, explorer->reader()->sizes.cluster_size), 46);
			break;
		}
		case $LOGGED_UTILITY_STREAM:
		{
			fr_attributes->add_item_multiline(print_attribute_logged_utility());
			break;
		}
		case $BITMAP:
		{
			std::shared_ptr<Buffer<PBYTE>> attr_buf = record->attribute_data<PBYTE>(pAttribute);

			fr_attributes->add_item_multiline(print_attribute_bitmap(reinterpret_cast<PMFT_RECORD_ATTRIBUTE_BITMAP>(attr_buf->data()), attr_buf->size()));

			break;
		}
		case $ATTRIBUTE_LIST:
		{
			PMFT_RECORD_ATTRIBUTE pattr = nullptr;
			std::shared_ptr<Buffer<PBYTE>> attr_buf = nullptr;

			DWORD len = 0;
			if (pAttribute->FormCode == RESIDENT_FORM)
			{
				pattr = POINTER_ADD(PMFT_RECORD_ATTRIBUTE, pAttribute, pAttribute->Form.Resident.ValueOffset);
				len = pAttribute->Form.Resident.ValueLength;
			}
			else
			{
				len = pAttribute->Form.Nonresident.ValidDataLength & 0xffffffff;
				attr_buf = record->attribute_data<PBYTE>(pAttribute);
				pattr = (PMFT_RECORD_ATTRIBUTE)attr_buf->data();
			};
			fr_attributes->add_item_multiline(print_attribute_list(pattr, len));
			break;
		}
		default:
			fr_attributes->add_item_line("NYI attribute type");
		}
		fr_attributes->new_line();

		pAttribute = POINTER_ADD(PMFT_RECORD_ATTRIBUTE_HEADER, pAttribute, pAttribute->RecordLength);
	}
	utils::ui::title("Attributes:");
	fr_attributes->render(std::cout);
	std::cout << std::endl;

	return 0;
}

namespace commands
{
	namespace mft
	{
		int print_mft(std::shared_ptr<Options> opts)
		{
			std::ios_base::fmtflags flag_backup(std::cout.flags());

			std::shared_ptr<Disk> disk = get_disk(opts);
			if (disk != nullptr)
			{
				std::shared_ptr<Volume> volume = disk->volumes(opts->volume);
				if (volume != nullptr)
				{
					print_mft_info(disk, volume, opts->inode);
				}
			}
			std::cout.flags(flag_backup);
			return 0;
		}
	}
}