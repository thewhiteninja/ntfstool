
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

#include <vss.h>


int print_volumeshadow(std::shared_ptr<Disk> disk, std::shared_ptr<Volume> vol) {

	if ((vol->filesystem() != "NTFS") && (vol->filesystem() != "Bitlocker"))
	{
		std::cerr << "[!] NTFS volume required" << std::endl;
		return 1;
	}

	std::cout << std::setfill('0');
	utils::ui::title("Volume Shadow from " + disk->name() + " > Volume:" + std::to_string(vol->index()));

	std::cout << "[+] Opening " << vol->name() << std::endl;

	std::shared_ptr<NTFSExplorer> explorer = std::make_shared<NTFSExplorer>(vol);

	HANDLE hVolume = explorer->handle();

	DWORD read = 0;
	std::shared_ptr<Buffer<PVSS_VOLUME_HEADER>> vssbuf = std::make_shared<Buffer<PVSS_VOLUME_HEADER>>(512);
	SetFilePointer(hVolume, 0x1e00, NULL, FILE_BEGIN);
	if (ReadFile(hVolume, vssbuf->data(), 512, &read, NULL))
	{
		if (IsEqualGUID(vssbuf->data()->vssid, VSS_VOLUME_GUID))
		{
			std::cout << "[+] VSS header found at 0x1e00" << std::endl;

			std::shared_ptr<utils::ui::Table> df_table = std::make_shared<utils::ui::Table>();
			df_table->set_interline(true);

			int n = 0;
			df_table->add_header_line("SetID/ID");
			df_table->add_header_line("Count");
			df_table->add_header_line("Date");
			df_table->add_header_line("Details");

			LARGE_INTEGER next_offset;
			next_offset.QuadPart = vssbuf->data()->catalog_offset;
			while (next_offset.QuadPart)
			{
				std::shared_ptr<Buffer<PVSS_CATALOG_HEADER>> vsscatbuf = std::make_shared<Buffer<PVSS_CATALOG_HEADER>>(0x1000);
				SetFilePointer(hVolume, next_offset.LowPart, &next_offset.HighPart, FILE_BEGIN);
				if (ReadFile(hVolume, vsscatbuf->data(), 0x1000, &read, NULL))
				{
					auto cat = vsscatbuf->data();
					int i = 0;
					while ((cat->snapshots[i].entry_2.type == 0x2) && (cat->snapshots[i].entry_3.type == 0x3))
					{
						std::shared_ptr<Buffer<PVSS_STORE_HEADER>> store_header_buf = std::make_shared<Buffer<PVSS_STORE_HEADER>>(512);
						LARGE_INTEGER store_header_offset;
						store_header_offset.QuadPart = cat->snapshots[i].entry_3.store_header_offset;
						SetFilePointer(hVolume, store_header_offset.LowPart, &store_header_offset.HighPart, FILE_BEGIN);
						if (ReadFile(hVolume, store_header_buf->data(), 512, &read, NULL))
						{
							df_table->add_item_multiline(
								{
								utils::id::guid_to_string(store_header_buf->data()->set_id),
								"",
								utils::id::guid_to_string(store_header_buf->data()->id)
								},
								38
							);

							df_table->add_item_line(std::to_string(store_header_buf->data()->count));

							SYSTEMTIME st;
							utils::times::ull_to_systemtime(cat->snapshots[i].entry_2.creation_time, &st);
							df_table->add_item_line(utils::times::display_systemtime(st));

							std::vector<std::string> cellstrings;
							DWORD serviceMachine_size = (&store_header_buf->data()->machines.Length)[0] / sizeof(WCHAR);
							if (serviceMachine_size)
							{
								std::wstring serviceMachine = (&store_header_buf->data()->machines.Buffer) + 1;
								serviceMachine.resize(serviceMachine_size);
								cellstrings.push_back("Service Machine    : " + utils::strings::to_utf8(serviceMachine));
							}
							DWORD originatingMachine_size = (&store_header_buf->data()->machines.Length)[serviceMachine_size + 1] / sizeof(WCHAR);
							if (serviceMachine_size)
							{
								std::wstring originatingMachine = (&store_header_buf->data()->machines.Buffer) + serviceMachine_size + 2;
								originatingMachine.resize(originatingMachine_size);
								cellstrings.push_back("Originating Machine: " + utils::strings::to_utf8(originatingMachine));
							}
							cellstrings.push_back("State              : " + constants::disk::vss::state(store_header_buf->data()->state - 1));
							cellstrings.push_back("Flags              : 0x" + utils::format::hex((DWORD)store_header_buf->data()->flags));

							for (auto flagsstr : constants::disk::vss::flags(store_header_buf->data()->flags))
							{
								cellstrings.push_back("                   - " + flagsstr);
							}

							df_table->add_item_multiline(cellstrings, 42);

							df_table->new_line();
						}

						store_header_buf = nullptr;
						i++;
					}

					next_offset.QuadPart = cat->next_offset;
				}
				else
				{
					break;
				}
				vsscatbuf = nullptr;
			}

			std::cout << std::endl;
			df_table->render(std::cout);
			std::cout << std::endl;
		}
		else
		{
			std::cout << "[+] VSS header not found" << std::endl;
		}
	}

	std::cout << "[+] Closing volume" << std::endl;

	return 0;
}

namespace commands
{
	namespace shadow
	{
		int print_volumeshadow(std::shared_ptr<Options> opts)
		{
			std::ios_base::fmtflags flag_backup(std::cout.flags());

			std::shared_ptr<Disk> disk = get_disk(opts);
			if (disk != nullptr)
			{
				std::shared_ptr<Volume> volume = disk->volumes(opts->volume);
				if (volume != nullptr)
				{
					print_volumeshadow(disk, volume);
				}
			}

			std::cout.flags(flag_backup);
			return 0;
		}
	}
}