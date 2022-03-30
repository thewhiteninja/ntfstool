#include "Drive/disk.h"
#include "Utils/utils.h"
#include "options.h"
#include "Utils/constant_names.h"

#include <cstdint>
#include <string>
#include <iostream>
#include <iomanip>
#include <memory>

#define VERSION "1.6"

void usage(const char* binname)
{
	std::cerr << "Usage: " << binname << " command [options]" << std::endl;
	std::cerr << std::endl;
	std::cerr << "Version: " << VERSION << " (Build date: " << __DATE__ << " " << __TIME__ << ")" << std::endl << std::endl;
	std::cerr << "Commands:" << std::endl;
	std::cerr << "  info             : list and display physical disks and volumes" << std::endl;
	std::cerr << "  mbr              : display master boot record" << std::endl;
	std::cerr << "  gpt              : display GUID partition table" << std::endl;
	std::cerr << "  vbr              : display volume boot record" << std::endl;
	std::cerr << "  mft.btree        : display index btree" << std::endl;
	std::cerr << "  mft.dump         : dump MFT (raw, csv, json)" << std::endl;
	std::cerr << "  mft.record       : display master file table" << std::endl;
	std::cerr << "  extract          : extract a file" << std::endl;
	std::cerr << "  bitlocker.info   : display bitlocker GUID/status and test password, recovery or BEK file" << std::endl;
	std::cerr << "  bitlocker.decrypt: decrypt volume to an image file" << std::endl;
	std::cerr << "  bitlocker.fve    : display FVE metadata" << std::endl;
	std::cerr << "  efs.backup       : Export EFS keys from a volume" << std::endl;
	std::cerr << "  efs.decrypt      : Decrypt EFS encrypted file from backup key" << std::endl;
	std::cerr << "  efs.certificate  : list, display and export system certificates" << std::endl;
	std::cerr << "  efs.key          : list, display, decrypt and export private keys" << std::endl;
	std::cerr << "  efs.masterkey    : list, display and decrypt masterkeys" << std::endl;
	std::cerr << "  logfile.dump     : dump log file (raw, csv, json)" << std::endl;
	std::cerr << "  usn.dump         : dump usn journal (raw, csv, json)" << std::endl;
	std::cerr << "  usn.analyze      : analyze usn journal with specified rules (csv, json)" << std::endl;
	std::cerr << "  shadow           : list volume shadow copies" << std::endl;
	std::cerr << "  reparse          : parse and display reparse points" << std::endl;
	std::cerr << "  undelete         : find deleted files" << std::endl;
	std::cerr << "  shell            : start a mini-shell" << std::endl;
	std::cerr << "  smart            : display SMART data" << std::endl;
	std::cerr << "  help             : display this message or command help" << std::endl;
	std::cerr << std::endl;
	std::cerr << "Need help for a command?" << std::endl;
	std::cerr << "  help [command]" << std::endl;
	std::cerr << std::endl;
}

void command_header(const char* cmd)
{
	std::cerr << cmd << " command" << std::endl;
	for (int i = 0; i < strnlen_s(cmd, 20) + 8; i++) std::cerr << "-";
	std::cerr << std::endl << std::endl;
}

void command_description(const char* name, const char* usage, const char* description)
{
	std::cerr << "  " << name << " " << usage << std::endl;
	std::cerr << std::endl;
	std::cerr << "  - " << description << std::endl;
	std::cerr << std::endl;
}

void command_examples(const char* name, const char* title, const char* example)
{

	std::cerr << "  " << title << ":" << std::endl;
	std::cerr << "  > " << name << " " << example << std::endl;
	std::cerr << std::endl;
}

void print_help_help(const char* name)
{
	command_header("help");
	command_description(name, "help [command]", "Provides help information for all commands");
	command_examples(name, "Example", "help shell");
}

void print_help_info(const char* name)
{
	command_header("info");
	command_description(name, "info (disk id) (volume id)", "Provides a list of physical disks or information for selected disk and volume");
	command_examples(name, "Display the list of physical disks", "info");
	command_examples(name, "Display information on disk 1", "info disk=1");
	command_examples(name, "Display information on disk 2 and volume 1", "info disk=2 volume=1");
}

void print_help_mbr(const char* name)
{
	command_header("mbr");
	command_description(name, "mbr [disk id]", "Provides MBR information and partition table for selected disk");
	command_examples(name, "Display MBR for disk 0", "mbr disk=0");
}

void print_help_gpt(const char* name)
{
	command_header("gpt");
	command_description(name, "gpt [disk id]", "Provides GPT information and partition table for selected disk");
	command_examples(name, "Display GPT for disk 0", "gpt disk=0");
}

void print_help_vbr(const char* name)
{
	command_header("vbr");
	command_description(name, "vbr [disk id] [volume id]", "Provides VBR information and disassembly for selected disk and volume");
	command_examples(name, "Display VBR for disk 0 and volume 2", "vbr disk=0 volume=2");
}

void print_help_mft_record(const char* name)
{
	command_header("mft.record");
	command_description(name, "mft.record [disk id] [volume id] (inode/from)", "Display MFT file record information and detailed attributes for selected disk, volume and inode/path");
	command_examples(name, "Display MFT file record for disk 0, volume 2 and inode 5", "mft.record disk=0 volume=2 inode=5");
	command_examples(name, "Display MFT File record for disk 0, volume 2 and file \"c:\\file.bin\"", "mft.record disk=0 volume=2 from=\"c:\\file.bin\"");
}

void print_help_mft_btree(const char* name)
{
	command_header("mft.btree");
	command_description(name, "mft.btree [disk id] [volume id] (inode/from)", "Display index B-tree nodes and detailed attributes for selected disk, volume and inode/path");
	command_examples(name, "Display Index B-tree for disk 0, volume 2 and inode 5", "mft.btree disk=0 volume=2 inode=5");
	command_examples(name, "Display Index B-tree for disk 0, volume 2 and from \"c:\\file.bin\"", "mft.btree disk=0 volume=2 from \"c:\\file.bin\"");
}

void print_help_mft_dump(const char* name)
{
	command_header("mft.dump");
	command_description(name, "mft.dump [disk id] [volume id] [output] (format)", "Dump $MFT for selected disk, volume and inode/path");
	command_examples(name, "Dump raw $MFT for disk 0, volume 2 to a file", "mft.dump disk=0 volume=2 output=myvolume.mft");
	command_examples(name, "Parse $MFT for disk 0, volume 2 and output results in a CSV file", "mft.dump disk=0 volume=2 output=my_mft.json format=json");
}

void print_help_bitlocker(const char* name)
{
	command_header("bitlocker");
	command_description(name, "bitlocker.info [disk id] [volume id] (password | recovery | bek)", "Provides Bitlocker information for selected disk, volume");
	command_examples(name, "Display Bitlocker information for disk 2, volume 4", "bitlocker.info disk=2 volume=4");
	command_examples(name, "Test a password for encrypted for disk 2 and volume 4", "bitlocker.info disk=0 volume=2 password=123456");
	command_examples(name, "Test a recovery key for encrypted for disk 2 and volume 4", "bitlocker.info disk=0 volume=2 recovery=123456-234567-345678-456789-567890-678901-789012-890123");
	command_examples(name, "Test a BEK file for encrypted for disk 2 and volume 4", "bitlocker.info disk=0 volume=2 bek=H:\\3926293F-E661-4417-A36B-B41175B4D862.BEK");
}

void print_help_bitdecrypt(const char* name)
{
	command_header("bitlocker.decrypt");
	command_description(name, "bitlocker.decrypt [disk id] [volume id] [fvek] [output]", "Decrypt Bitlocker encrypted volume to a file using the Full Volume Encryption Key (FVEK)");
	command_examples(name, "Decrypt disk 2, volume 4 to decrypted.img", "bitlocker.decrypt disk=2 volume=4 fvek=21DA18B8434D864D11654FE84AAB1BDDF135DFDE912EBCAD54A6D87CB8EF64AC output=decrypted.img");
}

void print_help_fve(const char* name)
{
	command_header("bitlocker.fve");
	command_description(name, "bitlocker.fve [disk id] [volume id] (block)", "Display FVE metadata information for an Bitlocker encrypted volume");
	command_examples(name, "Display FVE metadata for disk 0, volume 1", "bitlocker.fve disk=0 volume=1");
	command_examples(name, "Display FVE metadata for disk 2, volume 4 and FVE block 2", "bitlocker.fve disk=2 volume=4 fve_block=2");
}

void print_help_logfile(const char* name)
{
	command_header("logfile.dump");
	command_description(name, "logfile.dump [disk id] [volume id] [output] (format)", "Dump and parse $LogFile of a NTFS volume  (raw, csv, json)");
	command_examples(name, "Dump raw $LogFile for disk 1, volume 2 to log.dat", "logfile.dump disk=1 volume=2 output=log.dat");
	command_examples(name, "Parse $LogFile for disk 2, volume 4 and output results in csv file", "logfile.dump disk=2 volume=4 output=log.csv format=csv");
}

void print_help_usn_dump(const char* name)
{
	command_header("usn.dump");
	command_description(name, "usn.dump [disk id] [volume id] [output] (format)", "Dump and parse $UsnJrnl of a NTFS volume (raw, csv, json)");
	command_examples(name, "Dump raw $UsnJrnl for disk 1, volume 2 to usn.dat", "us.dumpn disk=1 volume=2 output=usn.dat");
	command_examples(name, "Parse $UsnJrnl for disk 2, volume 4 and output results in json file", "usn.dump disk=2 volume=4 output=usn.json format=json");
}

void print_help_usn_analyze(const char* name)
{
	command_header("usn.analyze");
	command_description(name, "usn.analyze [disk id] [volume id] [rules] [output] (format)", "Parse and filter $UsnJrnl of a NTFS volume with specified rules (csv, json)");
	command_examples(name, "Parse and filer $UsnJrnl for disk 2, volume 4 and output results in json file", "usn.analyze disk=2 volume=4 rules=myrules.json output=usn.json format=json");
}

void print_help_efs_masterkey(const char* name)
{
	command_header("efs.masterkey");
	command_description(name, "efs.masterkey [disk id] [volume id] (inode/from) (sid) (password)", "List, display and decrypt masterkeys on a volume");
	command_examples(name, "List masterkeys for disk 1, volume 2", "efs.masterkey disk=1 volume=2");
	command_examples(name, "Display a masterkey for disk 1, volume 2 and inode 0x1337", "efs.masterkey disk=1 volume=2 inode=0x1337");
	command_examples(name, "Decrypt and display a masterkey using sid and password", "efs.masterkey disk=1 volume=2 inode=0x1337 sid=\"S-1123...1001\" password=\"123456\"");
}


void print_help_efs_backup(const char* name)
{
	command_header("efs.backup");
	command_description(name, "efs.backup [disk id] [volume id] [password]", "Export EFS keys from a volume");
	command_examples(name, "Export EFS keys for disk 1, volume 2 using password:123456", "efs.backup disk=1 volume=2 password=123456");
}

void print_help_efs_decrypt(const char* name)
{
	command_header("efs.decrypt");
	command_description(name, "efs.decrypt [disk id] [volume id] [inode|from] [pfx] [password] (output)", "Decrypt file from inode or path using pfx archive (protected by password) to output");
	command_examples(name, "Decrypt EFS file inode:1234 for disk 1 and volume 2 using backup.pfx protected by password 123456 to mydecryptedfile",
		"efs.decrypt disk=1 volume=2 inode=1234 pfx=backup.pfx password=123456 output=mydecryptedfile");
}

void print_help_efs_key(const char* name)
{
	command_header("efs.key");
	command_description(name, "efs.key [disk id] [volume id] [inode|from] (masterkey) (output) (format)", "List, display and decrypt keys on a volume");
	command_examples(name, "List keys for disk 1, volume 2", "efs.key disk=1 volume=2");
	command_examples(name, "Display a key for disk 1, volume 2 and inode 0x1337", "efs.key disk=1 volume=2 inode=0x1337");
	command_examples(name, "Decrypt a key for inode 0x1337 with masterkey", "efs.key disk=1 volume=2 inode=0x1337 masterkey=DEADBEEF123...321");
	command_examples(name, "Export a key to mykey.pem", "efs.key disk=1 volume=2 inode=0x1337 masterkey=DEADBEEF123...321 output=mykey");
}

void print_help_efs_certificate(const char* name)
{
	command_header("efs.certificate");
	command_description(name, "efs.certificate [disk id] [volume id] [inode|from] (output) (format)", "List and display certificate on a volume");
	command_examples(name, "List certificates for disk 1, volume 2", "efs.certificate disk=1 volume=2");
	command_examples(name, "Display a certificate for disk 1, volume 2 and inode 0x1337", "efs.certificate disk=1 volume=2 inode=0x1337");
	command_examples(name, "Export a certificate to mycert.pem", "efs.certificate disk=1 volume=2 inode=0x1337 output=mycert");
}

void print_help_extract(const char* name)
{
	command_header("extract");
	command_description(name, "extract [disk id] [volume id] [from] [output]", "Extract a file specified by a path in from to output");
	command_examples(name, "Extract a file", "extract disk=0 volume=1 from=\"c:\\windows\\notepad.exe\" output=\"d:\\notepad.exe\"");
	command_examples(name, "Extract SAM hive", "extract disk=0 volume=1 --sam output=\"d:\\sam\"");
	command_examples(name, "Extract SYSTEM file", "extract disk=0 volume=1 --system output=\"d:\\system\"");
}

void print_help_streams(const char* name)
{
	command_header("streams");
	command_description(name, "streams [disk id] [volume id] [from/inode]", "List alternate data streams of a file from its path or inode");
	command_examples(name, "Display the list ADS for c:\\random_file", "streams disk=0 volume=1 from=\"c:\\random_file\"");
}

void print_help_undelete(const char* name)
{
	command_header("undelete");
	command_description(name, "undelete [disk id] [volume id] ([inode] [output])", "List deleted files for selected disk and volume");
	command_examples(name, "Display the list deleted file for disk 0, volume 1", "undelete disk=0 volume=1");
	command_examples(name, "Extract deleted file with inode 41 for disk 2, volume 3 to restored.dat", "undelete disk=2 volume=3 inode=41 output=restored.dat");
}

void print_help_shell(const char* name)
{
	command_header("shell");
	command_description(name, "shell [disk id] [volume id]", "Start a mini-shell for selected disk and volume");
	command_examples(name, "Start a shell for disk 1, volume 1", "shell disk=1 volume=1");
}

void print_help_shadow(const char* name)
{
	command_header("shadow");
	command_description(name, "shadow [disk id] [volume id]", "List volume shadow copies from selected disk and volume");
	command_examples(name, "Display volume shadow copies for disk 1, volume 2", "shadow disk=1 volume=2");
}

void print_help_reparse(const char* name)
{
	command_header("reparse");
	command_description(name, "reparse [disk id] [volume id]", "Parse reparse points from \\$Extend\\$Reparse for selected disk and volume");
	command_examples(name, "Display reparse points for disk 1, volume 1", "reparse disk=1 volume=1");
}

void print_help_image(const char* name)
{
	command_header("image");
	command_description(name, "image [disk id] [volume id] [output]", "Create an image file of a disk or volume");
	command_examples(name, "Create an image of physical drive 2 to z:\\backup.img", "image disk=2 output=z:\\backup.img");
}

void print_help_smart(const char* name)
{
	command_header("smart");
	command_description(name, "smart [disk id]", "Retrieve SMART data for the specified disk");
	command_examples(name, "Display SMART data from physical drive 2", "smart disk=2");
}

namespace commands
{
	namespace help
	{
		void dispatch(std::shared_ptr<Options> opts)
		{
			char name_buf[MAX_PATH] = { 0 };
			GetModuleFileNameA(nullptr, name_buf, MAX_PATH);
			std::string name = utils::files::basename(name_buf);

			if (opts->subcommand == "")
			{
				usage(name.c_str());
			}
			else
			{
				if (opts->subcommand == "bitdecrypt") { print_help_bitdecrypt(name.c_str()); return; }
				if (opts->subcommand == "bitlocker") { print_help_bitlocker(name.c_str()); return; }
				if (opts->subcommand == "efs.backup") { print_help_efs_backup(name.c_str()); return; }
				if (opts->subcommand == "efs.certificate") { print_help_efs_certificate(name.c_str()); return; }
				if (opts->subcommand == "efs.decrypt") { print_help_efs_decrypt(name.c_str()); return; }
				if (opts->subcommand == "efs.key") { print_help_efs_key(name.c_str()); return; }
				if (opts->subcommand == "efs.masterkey") { print_help_efs_masterkey(name.c_str()); return; }
				if (opts->subcommand == "extract") { print_help_extract(name.c_str()); return; }
				if (opts->subcommand == "fve") { print_help_fve(name.c_str()); return; }
				if (opts->subcommand == "gpt") { print_help_gpt(name.c_str()); return; }
				if (opts->subcommand == "help") { print_help_help(name.c_str()); return; }
				if (opts->subcommand == "image") { print_help_image(name.c_str()); return; }
				if (opts->subcommand == "info") { print_help_info(name.c_str()); return; }
				if (opts->subcommand == "logfile.dump") { print_help_logfile(name.c_str()); return; }
				if (opts->subcommand == "mbr") { print_help_mbr(name.c_str()); return; }
				if (opts->subcommand == "mft.btree") { print_help_mft_btree(name.c_str()); return; }
				if (opts->subcommand == "mft.dump") { print_help_mft_dump(name.c_str()); return; }
				if (opts->subcommand == "mft.record") { print_help_mft_record(name.c_str()); return; }
				if (opts->subcommand == "reparse") { print_help_reparse(name.c_str()); return; }
				if (opts->subcommand == "shadow") { print_help_shadow(name.c_str()); return; }
				if (opts->subcommand == "shell") { print_help_shell(name.c_str()); return; }
				if (opts->subcommand == "smart") { print_help_smart(name.c_str()); return; }
				if (opts->subcommand == "streams") { print_help_streams(name.c_str()); return; }
				if (opts->subcommand == "undelete") { print_help_undelete(name.c_str()); return; }
				if (opts->subcommand == "usn.analyze") { print_help_usn_analyze(name.c_str()); return; }
				if (opts->subcommand == "usn.dump") { print_help_usn_dump(name.c_str()); return; }
				if (opts->subcommand == "vbr") { print_help_vbr(name.c_str()); return; }

				usage(name.c_str());
			}
		}
	}
}