#include <Windows.h>

#include "options.h"
#include "Commands/commands.h"
#include <Utils/crash_handler.h>

#include <iostream>
#include <filesystem>

int main(int argc, char** argv) {
	install_crash_handler();

	SetConsoleOutputCP(CP_UTF8);

	if (!utils::processes::elevated(GetCurrentProcess()))
	{
		std::cerr << "Administrator rights are required to read physical drives" << std::endl;
		return 1;
	}

	std::shared_ptr<Options> opts = parse_options(argc, argv);

	if (opts->show_usage)
	{
		commands::help::dispatch(opts);
	}
	else
	{
		try
		{
			if (opts->command == "bitlocker.decrypt")		commands::bitlocker::decrypt::dispatch(opts);
			else if (opts->command == "bitlocker.fve") 		commands::bitlocker::fve::dispatch(opts);
			else if (opts->command == "bitlocker.info")		commands::bitlocker::info::dispatch(opts);
			else if (opts->command == "efs.backup")			commands::efs::backup::dispatch(opts);
			else if (opts->command == "efs.certificate")	commands::efs::certificate::dispatch(opts);
			else if (opts->command == "efs.decrypt")		commands::efs::decrypt::dispatch(opts);
			else if (opts->command == "efs.key")			commands::efs::key::dispatch(opts);
			else if (opts->command == "efs.masterkey")		commands::efs::masterkey::dispatch(opts);
			else if (opts->command == "extract")			commands::extract::dispatch(opts);
			else if (opts->command == "gpt")				commands::gpt::dispatch(opts);
			else if (opts->command == "help")				commands::help::dispatch(opts);
			else if (opts->command == "image")				commands::image::dispatch(opts);
			else if (opts->command == "info")				commands::info::dispatch(opts);
			else if (opts->command == "logfile.dump")		commands::logfile::dispatch(opts);
			else if (opts->command == "mbr")				commands::mbr::dispatch(opts);
			else if (opts->command == "mft.btree")			commands::mft::btree::dispatch(opts);
			else if (opts->command == "mft.dump")			commands::mft::dump::dispatch(opts);
			else if (opts->command == "mft.record")			commands::mft::record::dispatch(opts);
			else if (opts->command == "reparse") 			commands::reparse::dispatch(opts);
			else if (opts->command == "shadow")				commands::shadow::dispatch(opts);
			else if (opts->command == "shell")				commands::shell::dispatch(opts);
			else if (opts->command == "smart")				commands::smart::dispatch(opts);
			else if (opts->command == "streams") 			commands::streams::dispatch(opts);
			else if (opts->command == "undelete")			commands::undelete::dispatch(opts);
			else if (opts->command == "usn.analyze")		commands::usn::analyze::dispatch(opts);
			else if (opts->command == "usn.dump")			commands::usn::dump::dispatch(opts);
			else if (opts->command == "vbr")				commands::vbr::dispatch(opts);
			else
			{
				if (opts->command == "")
				{
					commands::help::dispatch(opts);
				}
				else
				{
					throw std::logic_error("Unknown command '" + opts->command + "'");
				}
			}
		}
		catch (const std::exception& e)
		{
			std::cerr << e.what() << std::endl << std::endl;
			opts->subcommand = "";
			commands::help::dispatch(opts);
		}
	}

	uninstall_crash_handler();

	return 0;
}