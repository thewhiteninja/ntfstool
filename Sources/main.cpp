#include <WinSock2.h>
#include <Windows.h>

#include "options.h"
#include "Commands/commands.h"
#include <Utils/crash_handler.h>

#include <iostream>
#include <filesystem>


int main(int argc, char** argv) {

	install_crash_handler();

	SetConsoleOutputCP(CP_UTF8);
	std::cout << std::endl;

	if (!utils::processes::elevated(GetCurrentProcess()))
	{
		std::cerr << "Administrator rights are required to read physical drives." << std::endl;
		return 1;
	}

	std::shared_ptr<Options> opts = parse_options(argc, argv);

	if (opts->show_usage) commands::help::print_help(argv[0], opts);
	else {
		try {

			if (opts->command == "mbr")				commands::mbr::print_mbr(opts);
			else if (opts->command == "shell")		commands::shell::go(opts);
			else if (opts->command == "smart")		commands::smart::print_smart(opts);
			else if (opts->command == "gpt")		commands::gpt::print_gpt(opts);
			else if (opts->command == "usn")		commands::usn::print_usn_journal(opts);
			else if (opts->command == "extract")	commands::extract::extract_file(opts);
			else if (opts->command == "vbr")		commands::vbr::print_vbr(opts);
			else if (opts->command == "image")		commands::image::create_image(opts);
			else if (opts->command == "undelete")	commands::undelete::print_deleted_file(opts);
			else if (opts->command == "mft")		commands::mft::print_mft(opts);
			else if (opts->command == "shadow")		commands::shadow::print_volumeshadow(opts);
			else if (opts->command == "logfile") 	commands::logfile::print_logfile(opts);
			else if (opts->command == "reparse") 	commands::reparse::print_reparse(opts);
			else if (opts->command == "bitdecrypt")	commands::bitlocker::decrypt_volume(opts);
			else if (opts->command == "bitlocker")
			{
				if (opts->password != "" || opts->recovery != "" || opts->bek != "")
				{
					commands::bitlocker::test_password(opts);
				}
				else
				{
					commands::bitlocker::print_bitlocker(opts);
				}
			}
			else if (opts->command == "fve") 		commands::bitlocker::print_fve(opts);
			else if (opts->command == "help")		commands::help::print_help(argv[0], opts);
			else if (opts->command == "info")
			{
				if ((opts->disk != 0xffffffff || opts->image != "") && opts->volume != 0xffffffff)
				{
					commands::info::print_partitions(opts);
				}
				else
				{
					commands::info::print_disks(opts);
				}
			}
			else {
				if (opts->command == "") commands::help::print_help(argv[0], opts);
				else throw std::logic_error("unknown command '" + opts->command + "'");
			}
		}
		catch (const std::exception& e) {
			std::cerr << "Err: " << e.what() << std::endl << std::endl;
		}
	}

	uninstall_crash_handler();

	return 0;
}