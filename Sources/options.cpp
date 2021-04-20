#include "options.h"
#include <iostream>
#include <algorithm>
#include <cstring>

bool is_option(char* arg, const char* name) { return (strncmp(arg, name, strlen(name)) == 0) && (arg[strlen(name)] == '='); }

bool is_number(const std::string& s)
{
	return !s.empty() && std::find_if(s.begin(),
		s.end(), [](unsigned char c) { return !std::isdigit(c); }) == s.end();
}

void read_option_ulong(char* arg, unsigned long* pul)
{
	char* pos = strchr(arg, '=');
	if (is_number(pos + 1))
	{
		*pul = std::strtoul(pos + 1, NULL, 10);
	}
	else
	{
		if (pos != NULL) *pos = '\0';
		std::cerr << "[!] Invalid number for \"" << std::string(arg) << "\" argument" << std::endl;
		exit(1);
	}
}

void read_option_string(char* arg, std::string& s)
{
	char* pos = strchr(arg, '=');
	s = std::string(pos + 1);
}

std::shared_ptr<Options> parse_options(int argc, char** argv) {
	std::shared_ptr<Options> ret = std::make_shared<Options>();

	if (argc > 1)
	{
		ret->command = std::string(argv[1]);
	}

	for (int i = 2; i < argc; i++)
	{
		if (is_option(argv[i], "output")) { read_option_string(argv[i], ret->out); continue; }
		if (is_option(argv[i], "from")) { read_option_string(argv[i], ret->from); continue; }
		if (is_option(argv[i], "disk")) { read_option_ulong(argv[i], &ret->disk); continue; }
		if (is_option(argv[i], "volume")) { read_option_ulong(argv[i], &ret->volume); continue; }
		if (is_option(argv[i], "inode")) { read_option_ulong(argv[i], &ret->inode); continue; }
		if (is_option(argv[i], "fve_block")) { read_option_ulong(argv[i], &ret->fve_block); continue; }
		if (is_option(argv[i], "password")) { read_option_string(argv[i], ret->password); continue; }
		if (is_option(argv[i], "recovery")) { read_option_string(argv[i], ret->recovery); continue; }
		if (is_option(argv[i], "image")) { read_option_string(argv[i], ret->image); continue; }
		if (is_option(argv[i], "bek")) { read_option_string(argv[i], ret->bek); continue; }
		if (is_option(argv[i], "fvek")) { read_option_string(argv[i], ret->fvek); continue; }
		if (is_option(argv[i], "format")) { read_option_string(argv[i], ret->format); continue; }
		if (!strncmp(argv[i], "--sam", 5)) { ret->sam = true; continue; }
		if (!strncmp(argv[i], "--system", 8)) { ret->system = true; continue; }
		if (ret->subcommand == "") { ret->subcommand = std::string(argv[i]); continue; }
		ret->show_usage = true;
	}

	return ret;
}

std::shared_ptr<Disk> get_disk(std::shared_ptr<Options> opts)
{
	std::shared_ptr<Disk> disk = nullptr;
	if (opts->image != "")
	{
		disk = core::win::disks::from_image(opts->image);
		if (disk == nullptr)
		{
			std::cerr << "[!] Invalid or missing disk image file" << std::endl;
			return nullptr;
		}
	}
	else
	{
		if (opts->disk != 0xffffffff)
		{
			disk = core::win::disks::by_index(opts->disk);
		}
	}
	return disk;
}

Options::Options()
{
}