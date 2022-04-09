#include "options.h"
#include <iostream>
#include <algorithm>
#include <cstring>
#include <Commands/commands.h>

bool equals(char* arg, const char* name) { return strncmp(arg, name, strlen(name)) == 0; }

bool is_option(char* arg, const char* name) { return (strncmp(arg, name, strlen(name)) == 0) && (arg[strlen(name)] == '='); }

bool is_number(const std::string& s)
{
	return !s.empty() && std::find_if(s.begin(),
		s.end(), [](unsigned char c) { return !std::isdigit(c); }) == s.end();
}

bool is_hexnum(const std::string& s)
{
	return !s.empty() && std::find_if(s.begin(),
		s.end(), [](unsigned char c) { return !std::isxdigit(c); }) == s.end();
}

void read_option_int64(char* arg, int64_t* pul)
{
	char* pos = strchr(arg, '=');
	if (is_number(pos + 1))
	{
		*pul = std::strtoull(pos + 1, NULL, 10);
	}
	else
	{
		if ((pos[1] == '0') && (pos[2] == 'x'))
		{
			if (is_hexnum(pos + 3))
			{
				*pul = std::strtoull(pos + 3, NULL, 16);
			}
			else
			{
				if (*pos == '=') *pos = 0;
				std::cerr << "[!] " << ((strnlen(pos + 1, 256) == 0) ? "Missing" : "Invalid") << " hex number for \"" << std::string(arg) << "\" argument" << ((strnlen(pos + 1, 256) == 0) ? "" : " (" + std::string(pos + 1) + ")") << std::endl;
				exit(1);
			}
		}
		else
		{
			if (*pos == '=') *pos = 0;
			std::cerr << "[!] " << ((strnlen(pos + 1, 256) == 0) ? "Missing" : "Invalid") << " number for \"" << std::string(arg) << "\" argument" << ((strnlen(pos + 1, 256) == 0) ? "" : " (" + std::string(pos + 1) + ")") << std::endl;
			exit(1);
		}
	}
}
void read_option_int32(char* arg, int32_t* pul)
{
	char* pos = strchr(arg, '=');
	if (is_number(pos + 1))
	{
		*pul = std::strtoul(pos + 1, NULL, 10);
	}
	else
	{
		if ((pos[1] == '0') && (pos[2] == 'x'))
		{
			if (is_hexnum(pos + 3))
			{
				*pul = std::strtoul(pos + 3, NULL, 16);
			}
			else
			{
				if (*pos == '=') *pos = 0;
				std::cerr << "[!] " << ((strnlen(pos + 1, 256) == 0) ? "Missing" : "Invalid") << " hex number for \"" << std::string(arg) << "\" argument" << ((strnlen(pos + 1, 256) == 0) ? "" : " (" + std::string(pos + 1) + ")") << std::endl;
				exit(1);
			}
		}
		else
		{
			if (*pos == '=') *pos = 0;
			std::cerr << "[!] " << ((strnlen(pos + 1, 256) == 0) ? "Missing" : "Invalid") << " number for \"" << std::string(arg) << "\" argument" << ((strnlen(pos + 1, 256) == 0) ? "" : " (" + std::string(pos + 1) + ")") << std::endl;
			exit(1);
		}
	}
}

void read_option_string(char* arg, std::string& s)
{
	char* pos = strchr(arg, '=');
	s = std::string(pos + 1);
}

void read_option_hexbuffer(char* arg, std::shared_ptr<Buffer<PBYTE>>* s)
{
	char* pos = strchr(arg, '=');
	std::string hexbuf = std::string(pos + 1);
	utils::strings::trim(hexbuf);
	*s = Buffer<PBYTE>::from_hex(hexbuf);
}

bool is_help(char* opt)
{
	return (equals(opt, "-h") || equals(opt, "--help") || equals(opt, "/?"));
}

std::shared_ptr<Options> parse_options(int argc, char** argv) {
	std::shared_ptr<Options> ret = std::make_shared<Options>();

	if (argc > 1)
	{
		if (is_help(argv[1])) ret->show_usage = true;
		else ret->command = std::string(argv[1]);
	}

	for (int i = 2; i < argc; i++)
	{
		if (is_option(argv[i], "output")) { read_option_string(argv[i], ret->output); continue; }
		if (is_option(argv[i], "from")) { read_option_string(argv[i], ret->from); continue; }
		if (is_option(argv[i], "stream")) { read_option_string(argv[i], ret->stream); continue; }
		if (is_option(argv[i], "disk")) { read_option_int32(argv[i], &ret->disk); continue; }
		if (is_option(argv[i], "volume")) { read_option_int32(argv[i], &ret->volume); continue; }
		if (is_option(argv[i], "inode")) { read_option_int64(argv[i], &ret->inode); continue; }
		if (is_option(argv[i], "fve_block")) { read_option_int32(argv[i], &ret->fve_block); continue; }
		if (is_option(argv[i], "password")) { read_option_string(argv[i], ret->password); continue; }
		if (is_option(argv[i], "sid")) { read_option_string(argv[i], ret->sid); continue; }
		if (is_option(argv[i], "masterkey")) { read_option_hexbuffer(argv[i], &ret->masterkey); continue; }
		if (is_option(argv[i], "pfx")) { read_option_string(argv[i], ret->pfx); continue; }
		if (is_option(argv[i], "mode")) { read_option_string(argv[i], ret->mode); continue; }
		if (is_option(argv[i], "recovery")) { read_option_string(argv[i], ret->recovery); continue; }
		if (is_option(argv[i], "image")) { read_option_string(argv[i], ret->image); continue; }
		if (is_option(argv[i], "bek")) { read_option_string(argv[i], ret->bek); continue; }
		if (is_option(argv[i], "fvek")) { read_option_string(argv[i], ret->fvek); continue; }
		if (is_option(argv[i], "format")) { read_option_string(argv[i], ret->format); continue; }
		if (is_option(argv[i], "rules")) { read_option_string(argv[i], ret->rules); continue; }
		if (!strncmp(argv[i], "--sam", 5)) { ret->sam = true; continue; }
		if (!strncmp(argv[i], "--system", 8)) { ret->system = true; continue; }
		if (is_help(argv[i])) { ret->show_usage = true; continue; }
		if (ret->subcommand == "") { ret->subcommand = std::string(argv[i]); continue; }

		std::cerr << std::endl << "[!] Invalid option: " << argv[i] << std::endl;
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
			invalid_option(opts, "image", opts->image);
		}
	}
	else
	{
		if (opts->disk >= 0)
		{
			disk = core::win::disks::by_index(opts->disk);
		}
		else
		{
			invalid_option(opts, "disk", opts->disk);
		}
	}
	return disk;
}

Options::Options()
{
}

void invalid_option(std::shared_ptr<Options> opts, std::string name, int64_t invalid_value, std::string error_msg)
{
	invalid_option(opts, name, invalid_value == -1 ? "" : std::to_string(invalid_value), error_msg);
}

void invalid_option(std::shared_ptr<Options> opts, std::string name, std::string invalid_value, std::string error_msg)
{
	if (invalid_value == "")
	{
		std::cerr << "[!] Missing ";
	}
	else
	{
		std::cerr << "[!] Invalid ";
	}
	std::cerr << name << " option";
	if (invalid_value != "")
	{
		std::cerr << " (" << invalid_value << ")";
	}
	if (error_msg.length())
	{
		std::cerr << ". " << error_msg;
	}
	std::cerr << std::endl << std::endl;

	opts->subcommand = opts->command;
	commands::help::dispatch(opts);
	exit(1);
}