
#include "Drive/disk.h"
#include "Utils/utils.h"
#include "options.h"
#include "Utils/constant_names.h"

#include <cstdint>
#include <string>
#include <iostream>
#include <iomanip>
#include <memory>

#define VERSION "1.3"

void usage(char* binname)
{
	std::cerr << "Usage: " << binname << " command [options]" << std::endl;
	std::cerr << std::endl;
	std::cerr << "Commands:" << std::endl;
	std::cerr << "    info       : list and display physical disks and volumes" << std::endl;
	std::cerr << "    mbr        : display master boot record" << std::endl;
	std::cerr << "    gpt        : display guid partition table" << std::endl;
	std::cerr << "    vbr        : display volume boot record" << std::endl;
	std::cerr << "    mft        : display master file table" << std::endl;
	std::cerr << "    extract    : extract a file" << std::endl;
	std::cerr << "    bitlocker  : display bitlocker guid/status and test password, recovery or bek file" << std::endl;
	std::cerr << "    bitdecrypt : decrypt volume to an image file" << std::endl;
	std::cerr << "    fve        : display fve metadata" << std::endl;
	std::cerr << "    logfile    : dump and parse log file" << std::endl;
	std::cerr << "    usn        : dump and parse usn journal" << std::endl;
	std::cerr << "    shadow     : list volume shadow copies" << std::endl;
	std::cerr << "    reparse    : parse and display reparse points" << std::endl;
	std::cerr << "    undelete   : find deleted files" << std::endl;
	std::cerr << "    shell      : start a mini-shell" << std::endl;
	std::cerr << "    smart      : display S.M.A.R.T data" << std::endl;
	std::cerr << "    help       : display this message or command help" << std::endl;
	std::cerr << std::endl;
	std::cerr << "Example:" << std::endl;
	std::cerr << "    help extract" << std::endl;
	std::cerr << std::endl;

	std::cerr << "Version: " << VERSION << " (" << __DATE__ << ")" << std::endl;
}

void print_help_help(char* name)
{
	std::cerr << "Help command" << std::endl;
	std::cerr << "------------" << std::endl;
	std::cerr << std::endl;
	std::cerr << "    " << name << " help [command]" << std::endl;
	std::cerr << std::endl;
	std::cerr << "    Description:" << std::endl;
	std::cerr << "    Provides help information for all commands." << std::endl;
	std::cerr << std::endl;
	std::cerr << "    Example: " << std::endl;
	std::cerr << "    " << name << " help shell" << std::endl;
	std::cerr << std::endl;
}

void print_help_info(char* name)
{
	std::cerr << "Info command" << std::endl;
	std::cerr << "------------" << std::endl;
	std::cerr << std::endl;
	std::cerr << "    " << name << " info (disk id) (volume id)" << std::endl;
	std::cerr << std::endl;
	std::cerr << "    Description:" << std::endl;
	std::cerr << "    Provides a list of physical disks or information for selected disk and volume." << std::endl;
	std::cerr << std::endl;
	std::cerr << "    Example: List of physical disks" << std::endl;
	std::cerr << "    " << name << " info" << std::endl;
	std::cerr << std::endl;
	std::cerr << "    Example: Information on disk 1" << std::endl;
	std::cerr << "    " << name << " info disk=1" << std::endl;
	std::cerr << std::endl;
	std::cerr << "    Example: Information on disk 2 and volume 1" << std::endl;
	std::cerr << "    " << name << " info disk=2 volume=1" << std::endl;
	std::cerr << std::endl;
}

void print_help_mbr(char* name)
{
	std::cerr << "MBR command" << std::endl;
	std::cerr << "-----------" << std::endl;
	std::cerr << std::endl;
	std::cerr << "    " << name << " mbr [disk id]" << std::endl;
	std::cerr << std::endl;
	std::cerr << "    Description:" << std::endl;
	std::cerr << "    Provides MBR information and partition table for selected disk." << std::endl;
	std::cerr << std::endl;
	std::cerr << "    Example: MBR for disk 0" << std::endl;
	std::cerr << "    " << name << " mbr disk=0" << std::endl;
	std::cerr << std::endl;
}

void print_help_gpt(char* name)
{
	std::cerr << "GPT command" << std::endl;
	std::cerr << "-----------" << std::endl;
	std::cerr << std::endl;
	std::cerr << "    " << name << " gpt [disk id]" << std::endl;
	std::cerr << std::endl;
	std::cerr << "    Description:" << std::endl;
	std::cerr << "    Provides GPT information and partition table for selected disk." << std::endl;
	std::cerr << std::endl;
	std::cerr << "    Example: GPT for disk 0" << std::endl;
	std::cerr << "    " << name << " gpt disk=0" << std::endl;
	std::cerr << std::endl;
}

void print_help_vbr(char* name)
{
	std::cerr << "VBR command" << std::endl;
	std::cerr << "-----------" << std::endl;
	std::cerr << std::endl;
	std::cerr << "    " << name << " vbr [disk id] [volume id]" << std::endl;
	std::cerr << std::endl;
	std::cerr << "    Description:" << std::endl;
	std::cerr << "    Provides VBR information and disassembly for selected disk and volume." << std::endl;
	std::cerr << "    Support: FAT, NTFS, Bitlocker." << std::endl;
	std::cerr << std::endl;
	std::cerr << "    Example: vbr for disk 0 and volume 2" << std::endl;
	std::cerr << "    " << name << " vbr disk=0 volume=2" << std::endl;
	std::cerr << std::endl;
}

void print_help_mft(char* name)
{
	std::cerr << "MFT command" << std::endl;
	std::cerr << "-----------" << std::endl;
	std::cerr << std::endl;
	std::cerr << "    " << name << " mft [disk id] [volume id] (inode)" << std::endl;
	std::cerr << std::endl;
	std::cerr << "    Description:" << std::endl;
	std::cerr << "    Provides MFT file record information and detailed attributes for selected disk, volume and inode." << std::endl;
	std::cerr << "    Default inode: 0 (MFT)." << std::endl;
	std::cerr << std::endl;
	std::cerr << "    Example: MFT file record for disk 0, volume 2" << std::endl;
	std::cerr << "    " << name << " mft disk=0 volume=2" << std::endl;
	std::cerr << std::endl;
	std::cerr << "    Example: File record for disk 0, volume 2 and inode 5" << std::endl;
	std::cerr << "    " << name << " mft disk=0 volume=2 inode=5" << std::endl;
	std::cerr << std::endl;
}

void print_help_bitlocker(char* name)
{
	std::cerr << "Bitlocker command" << std::endl;
	std::cerr << "-----------------" << std::endl;
	std::cerr << std::endl;
	std::cerr << "    " << name << " bitlocker [disk id] [volume id] (password | recovery | bek)" << std::endl;
	std::cerr << std::endl;
	std::cerr << "    Description:" << std::endl;
	std::cerr << "    Provides Bitlocker information for selected disk, volume." << std::endl;
	std::cerr << "    It is also possible to test a password, recovery key or BEK file using the corresponding option." << std::endl;
	std::cerr << std::endl;
	std::cerr << "    Example: Bitlocker information disk 2, volume 4" << std::endl;
	std::cerr << "    " << name << " bitlocker disk=2 volume=4" << std::endl;
	std::cerr << std::endl;
	std::cerr << "    Example: Test a password for encrypted disk 2 and volume 4" << std::endl;
	std::cerr << "    " << name << " mft disk=0 volume=2 password=123456" << std::endl;
	std::cerr << std::endl;
	std::cerr << "    Example: Test a recovery key for encrypted disk 2 and volume 4" << std::endl;
	std::cerr << "    " << name << " mft disk=0 volume=2 recovery=123456-234567-345678-456789-567890-678901-789012-890123" << std::endl;
	std::cerr << std::endl;
	std::cerr << "    Example: Test a BEK file for encrypted disk 2 and volume 4" << std::endl;
	std::cerr << "    " << name << " mft disk=0 volume=2 bek=H:\\3926293F-E661-4417-A36B-B41175B4D862.BEK" << std::endl;
	std::cerr << std::endl;
}

void print_help_bitdecrypt(char* name)
{
	std::cerr << "Bitdecrypt command" << std::endl;
	std::cerr << "------------------" << std::endl;
	std::cerr << std::endl;
	std::cerr << "    " << name << " bitdecrypt [disk id] [volume id] [fvek] [output]" << std::endl;
	std::cerr << std::endl;
	std::cerr << "    Description:" << std::endl;
	std::cerr << "    Decrypt Bitlocker encrypted volume to a file using the Full Volume Encryption Key (FVEK)." << std::endl;
	std::cerr << "    FVEK can be retrieved using the bitlocker command." << std::endl;
	std::cerr << std::endl;
	std::cerr << "    Example: Decrypt disk 2, volume 4 to decrypted.img" << std::endl;
	std::cerr << "    " << name << " bitdecrypt disk=2 volume=4 fvek=21DA18B8434D864D11654FE84AAB1BDDF135DFDE912EBCAD54A6D87CB8EF64AC output=decrypted.img" << std::endl;
	std::cerr << std::endl;
}


void print_help_fve(char* name)
{
	std::cerr << "FVE command" << std::endl;
	std::cerr << "-----------" << std::endl;
	std::cerr << std::endl;
	std::cerr << "    " << name << " bitdecrypt [disk id] [volume id] [fvek] [output]" << std::endl;
	std::cerr << std::endl;
	std::cerr << "    Description:" << std::endl;
	std::cerr << "    Provides FVE metadata information for an Bitlocker encrypted volume." << std::endl;
	std::cerr << "    Three copies of the FVE data are stored on the volume." << std::endl;
	std::cerr << "    Option fve_block can be used to select the block (Default: 0)." << std::endl;
	std::cerr << std::endl;
	std::cerr << "    Example: FVE metadata for disk 0, volume 1" << std::endl;
	std::cerr << "    " << name << " fve disk=0 volume=1" << std::endl;
	std::cerr << std::endl;
	std::cerr << "    Example: FVE metadata for disk 2, volume 4 and FVE block 2" << std::endl;
	std::cerr << "    " << name << " fve disk=2 volume=4 fve_block=2" << std::endl;
	std::cerr << std::endl;
}

void print_help_logfile(char* name)
{
	std::cerr << "Logfile command" << std::endl;
	std::cerr << "---------------" << std::endl;
	std::cerr << std::endl;
	std::cerr << "    " << name << " logfile [disk id] [volume id] [output] (format)" << std::endl;
	std::cerr << std::endl;
	std::cerr << "    Description:" << std::endl;
	std::cerr << "    Dump or parse the $LogFile of a NTFS volume." << std::endl;
	std::cerr << "    Format: raw, csv, json. Default: raw." << std::endl;
	std::cerr << std::endl;
	std::cerr << "    Example: Dump raw $LogFile for disk 1, volume 2 to log.dat" << std::endl;
	std::cerr << "    " << name << " logfile disk=1 volume=2 output=log.dat" << std::endl;
	std::cerr << std::endl;
	std::cerr << "    Example: Parse logfile for disk 2, volume 4 and output results in csv file" << std::endl;
	std::cerr << "    " << name << " logfile disk=2 volume=4 output=log.csv format=csv" << std::endl;
	std::cerr << std::endl;
}


void print_help_usn(char* name)
{
	std::cerr << "USN command" << std::endl;
	std::cerr << "-----------" << std::endl;
	std::cerr << std::endl;
	std::cerr << "    " << name << " usn [disk id] [volume id] [output] (format)" << std::endl;
	std::cerr << std::endl;
	std::cerr << "    Description:" << std::endl;
	std::cerr << "    Dump or parse the $UsnJrnl of a NTFS volume." << std::endl;
	std::cerr << "    Format: raw, csv, json. Default: raw." << std::endl;
	std::cerr << std::endl;
	std::cerr << "    Example: Dump raw $UsnJrnl for disk 1, volume 2 to usn.dat" << std::endl;
	std::cerr << "    " << name << " usn disk=1 volume=2 output=usn.dat" << std::endl;
	std::cerr << std::endl;
	std::cerr << "    Example: Parse usn journal for disk 2, volume 4 and output results in json file" << std::endl;
	std::cerr << "    " << name << " usn disk=2 volume=4 output=usn.json format=json" << std::endl;
	std::cerr << std::endl;
}

void print_help_extract(char* name)
{
	std::cerr << "Extract command" << std::endl;
	std::cerr << "---------------" << std::endl;
	std::cerr << std::endl;
	std::cerr << "    " << name << " extract [disk id] [volume id] [from] [output]" << std::endl;
	std::cerr << std::endl;
	std::cerr << "    Description:" << std::endl;
	std::cerr << "    Extract a file specified by a path in from to output." << std::endl;
	std::cerr << std::endl;
	std::cerr << "    Example: Extract a file" << std::endl;
	std::cerr << "    " << name << " extract disk=0 volume=1 from=\"c:\\windows\\notepad.exe\" output = \"d:\\notepad.exe\"" << std::endl;
	std::cerr << std::endl;
	std::cerr << "    Example: Extract SAM" << std::endl;
	std::cerr << "    " << name << " extract disk=0 volume=1 --sam output = \"d:\\sam\"" << std::endl;
	std::cerr << std::endl;
	std::cerr << "    Example: Extract SYSTEM file" << std::endl;
	std::cerr << "    " << name << " extract disk=0 volume=1 --system output = \"d:\\system\"" << std::endl;
	std::cerr << std::endl;
}


void print_help_undelete(char* name)
{
	std::cerr << "Undelete command" << std::endl;
	std::cerr << "----------------" << std::endl;
	std::cerr << std::endl;
	std::cerr << "    " << name << " undelete [disk id] [volume id] ([inode] [output])" << std::endl;
	std::cerr << std::endl;
	std::cerr << "    Description:" << std::endl;
	std::cerr << "    List deleted files for selected disk and volume." << std::endl;
	std::cerr << "    Each entry is provided using a recoverable percent computed from overwritten sectors of the file" << std::endl;
	std::cerr << std::endl;
	std::cerr << "    Example: List deleted file for disk 0, volume 1" << std::endl;
	std::cerr << "    " << name << " undelete disk=0 volume=1" << std::endl;
	std::cerr << std::endl;
	std::cerr << "    Example: Extract deleted file with inode 41 for disk 2, volume 3 to restored.dat" << std::endl;
	std::cerr << "    " << name << " undelete disk=2 volume=3 inode=41 output=restored.dat" << std::endl;
	std::cerr << std::endl;
}

void print_help_shell(char* name)
{
	std::cerr << "Shell command" << std::endl;
	std::cerr << "-------------" << std::endl;
	std::cerr << std::endl;
	std::cerr << "    " << name << " shell [disk id] [volume id]" << std::endl;
	std::cerr << std::endl;
	std::cerr << "    Description:" << std::endl;
	std::cerr << "    Start a mini-shell for selected disk and volume." << std::endl;
	std::cerr << "    Command: ls, cat, cd, stat" << std::endl;
	std::cerr << std::endl;
	std::cerr << "    Example: Start a shell for disk 1, volume 1" << std::endl;
	std::cerr << "    " << name << " shell disk=1 volume=1" << std::endl;
	std::cerr << std::endl;
}

void print_help_shadow(char* name)
{
	std::cerr << "Shadow command" << std::endl;
	std::cerr << "---------------" << std::endl;
	std::cerr << std::endl;
	std::cerr << "    " << name << " shadow [disk id] [volume id]" << std::endl;
	std::cerr << std::endl;
	std::cerr << "    Description:" << std::endl;
	std::cerr << "    List volume shadow copies from selected disk and volume." << std::endl;
	std::cerr << std::endl;
	std::cerr << "    Example: Display volume shadow copies for disk 1, volume 2" << std::endl;
	std::cerr << "    " << name << " shadow disk=1 volume=2" << std::endl;
	std::cerr << std::endl;
}

void print_help_reparse(char* name)
{
	std::cerr << "Reparse command" << std::endl;
	std::cerr << "---------------" << std::endl;
	std::cerr << std::endl;
	std::cerr << "    " << name << " reparse [disk id] [volume id]" << std::endl;
	std::cerr << std::endl;
	std::cerr << "    Description:" << std::endl;
	std::cerr << "    Parse reparse points from \\$Extend\\$Reparse for selected disk and volume." << std::endl;
	std::cerr << std::endl;
	std::cerr << "    Example: Display reparse points for disk 1, volume 1" << std::endl;
	std::cerr << "    " << name << " reparse disk=1 volume=1" << std::endl;
	std::cerr << std::endl;
}

void print_help_image(char* name)
{
	std::cerr << "Image command" << std::endl;
	std::cerr << "---------------" << std::endl;
	std::cerr << std::endl;
	std::cerr << "    " << name << " image [disk id] [volume id] [output]" << std::endl;
	std::cerr << std::endl;
	std::cerr << "    Description:" << std::endl;
	std::cerr << "    Create an image file of a disk or volume." << std::endl;
	std::cerr << std::endl;
	std::cerr << "    Example: Create an image of physical drive 2 to z:\\backup.img" << std::endl;
	std::cerr << "    " << name << " image disk=2 output=z:\\backup.img" << std::endl;
	std::cerr << std::endl;
}

void print_help_smart(char* name)
{
	std::cerr << "SMART command" << std::endl;
	std::cerr << "---------------" << std::endl;
	std::cerr << std::endl;
	std::cerr << "    " << name << " smart [disk id]" << std::endl;
	std::cerr << std::endl;
	std::cerr << "    Description:" << std::endl;
	std::cerr << "    Retrieve S.M.A.R.T data for the specified disk." << std::endl;
	std::cerr << std::endl;
	std::cerr << "    Example: Display S.M.A.R.T data from physical drive 2" << std::endl;
	std::cerr << "    " << name << " smart disk=2" << std::endl;
	std::cerr << std::endl;
}

namespace commands {

	namespace help {

		void print_help(char* name, std::shared_ptr<Options> opts) {
			if (opts->subcommand == "")
			{
				usage(name);
			}
			else
			{
				if (opts->subcommand == "help") { print_help_help(name); return; }
				if (opts->subcommand == "info") { print_help_info(name); return; }
				if (opts->subcommand == "mbr") { print_help_mbr(name); return; }
				if (opts->subcommand == "gpt") { print_help_gpt(name); return; }
				if (opts->subcommand == "vbr") { print_help_vbr(name); return; }
				if (opts->subcommand == "mft") { print_help_mft(name); return; }
				if (opts->subcommand == "extract") { print_help_extract(name); return; }
				if (opts->subcommand == "bitlocker") { print_help_bitlocker(name); return; }
				if (opts->subcommand == "bitdecrypt") { print_help_bitdecrypt(name); return; }
				if (opts->subcommand == "fve") { print_help_fve(name); return; }
				if (opts->subcommand == "image") { print_help_image(name); return; }
				if (opts->subcommand == "shadow") { print_help_shadow(name); return; }
				if (opts->subcommand == "logfile") { print_help_logfile(name); return; }
				if (opts->subcommand == "reparse") { print_help_reparse(name); return; }
				if (opts->subcommand == "usn") { print_help_usn(name); return; }
				if (opts->subcommand == "undelete") { print_help_undelete(name); return; }
				if (opts->subcommand == "shell") { print_help_shell(name); return; }
				if (opts->subcommand == "smart") { print_help_smart(name); return; }
				usage(name);
			}
		}

	}

}