
#include "Drive/disk.h"
#include "Utils/utils.h"
#include "options.h"
#include "Commands/commands.h"
#include "NTFS/ntfs.h"
#include "NTFS/ntfs_explorer.h"
#include "Utils/constant_names.h"
#include "Utils/table.h"

#include <nlohmann/json.hpp>

#include <cstdint>
#include <string>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <memory>
#include <iterator>



int print_reparse(std::shared_ptr<Disk> disk, std::shared_ptr<Volume> vol, const std::string& format, std::string output) {

	if ((vol->filesystem() != "NTFS") && (vol->filesystem() != "Bitlocker"))
	{
		std::cerr << "[!] NTFS volume required" << std::endl;
		return 1;
	}

	utils::ui::title("Reparse points from " + disk->name() + " > Volume:" + std::to_string(vol->index()));

	std::cout << "[+] Opening " << vol->name() << std::endl;

	std::shared_ptr<NTFSExplorer> explorer = std::make_shared<NTFSExplorer>(vol);

	std::cout << "[+] Reading $Extend\\$Reparse" << std::endl;

	std::shared_ptr<MFTRecord> record = explorer->mft()->record_from_path("\\$Extend\\$Reparse");

	std::shared_ptr<utils::ui::Table> df_table = std::make_shared<utils::ui::Table>();
	df_table->set_interline(true);

	df_table->add_header_line("Id");
	df_table->add_header_line("MFT Index");
	df_table->add_header_line("Filename");
	df_table->add_header_line("Type");
	df_table->add_header_line("Target/Data");

	int n = 0;
	auto index = record->index();
	std::cout << "[+] " << index.size() << " entries found" << std::endl;

	for (auto b : index)
	{
		std::shared_ptr<MFTRecord> rp = explorer->mft()->record_from_number(b->record_number());
		if (rp)
		{
			auto pattr = rp->attribute_header($REPARSE_POINT, "");
			if (pattr != nullptr)
			{
				if (pattr->FormCode == RESIDENT_FORM)
				{
					df_table->add_item_line(std::to_string(n++));
					df_table->add_item_line(utils::format::hex(rp->header()->MFTRecordIndex));
					df_table->add_item_line(utils::strings::to_utf8(rp->filename()));

					auto rp_value = POINTER_ADD(PMFT_RECORD_ATTRIBUTE_REPARSE_POINT, pattr, pattr->Form.Resident.ValueOffset);

					df_table->add_item_line(constants::disk::mft::file_record_reparse_point_type(rp_value->ReparseTag));

					std::vector<std::string> target;

					if (rp_value->ReparseTag == IO_REPARSE_TAG_SYMLINK)
					{
						std::wstring subs_name = std::wstring(POINTER_ADD(PWCHAR, rp_value->SymbolicLinkReparseBuffer.PathBuffer, rp_value->SymbolicLinkReparseBuffer.SubstituteNameOffset));
						subs_name.resize(rp_value->SymbolicLinkReparseBuffer.SubstituteNameLength / sizeof(WCHAR));
						target.push_back(utils::strings::to_utf8(subs_name));
					}
					else if (rp_value->ReparseTag == IO_REPARSE_TAG_MOUNT_POINT)
					{
						std::wstring subs_name = std::wstring(POINTER_ADD(PWCHAR, rp_value->MountPointReparseBuffer.PathBuffer, rp_value->MountPointReparseBuffer.SubstituteNameOffset));
						subs_name.resize(rp_value->MountPointReparseBuffer.SubstituteNameLength / sizeof(WCHAR));
						target.push_back(utils::strings::to_utf8(subs_name));
					}
					else if (rp_value->ReparseTag == IO_REPARSE_TAG_APPEXECLINK)
					{
						unsigned int n = 0;
						size_t i = 0;
						while (n < rp_value->AppExecLinkReparseBuffer.StringCount && i < rp_value->ReparseDataLength)
						{
							std::wstring subs_name = std::wstring(POINTER_ADD(PWCHAR, rp_value->AppExecLinkReparseBuffer.StringBuffer, i));
							target.push_back(utils::strings::to_utf8(subs_name));
							if (n < rp_value->AppExecLinkReparseBuffer.StringCount - 1) target.push_back("");

							i += (subs_name.length() + 1) * sizeof(WCHAR);
							n++;
						}
					}
					else
					{
						target.push_back(utils::convert::to_hex(rp_value->GenericReparseBuffer.DataBuffer, rp_value->ReparseDataLength));
					}

					df_table->add_item_multiline(target);

					df_table->new_line();
				}
			}
		}
	}

	df_table->render(std::cout);
	std::cout << std::endl;

	std::cout << "[+] Closing volume" << std::endl;

	return 0;
}


namespace commands {

	namespace reparse {

		int print_reparse(std::shared_ptr<Options> opts)
		{
			std::ios_base::fmtflags flag_backup(std::cout.flags());

			std::shared_ptr<Disk> disk = get_disk(opts);
			if (disk != nullptr)
			{
				std::shared_ptr<Volume> volume = disk->volumes(opts->volume);
				if (volume != nullptr)
				{
					print_reparse(disk, volume, opts->format, opts->out);
				}
			}

			std::cout.flags(flag_backup);
			return 0;
		}
	}
}
