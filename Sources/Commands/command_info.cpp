#include "Drive/disk.h"
#include "Utils/utils.h"
#include "Utils/table.h"
#include "options.h"
#include "Utils/constant_names.h"
#include "openssl/sha.h"
#include "openssl/evp.h"

#include <cstdint>
#include <string>
#include <memory>

void print_disks_short(std::vector<std::shared_ptr<Disk>> disks) {
	std::shared_ptr<utils::ui::Table> disktable = std::make_shared<utils::ui::Table>();
	disktable->set_margin_left(4);

	disktable->add_header_line("Id");
	disktable->add_header_line("Model");
	disktable->add_header_line("Type");
	disktable->add_header_line("Partition");
	disktable->add_header_line("Size");

	for (std::shared_ptr<Disk> disk : disks) {
		disktable->add_item_line(std::to_string(disk->index()));
		disktable->add_item_line(disk->product_id());

		std::string media_type = constants::disk::media_type(disk->geometry()->Geometry.MediaType);
		if (media_type == "Virtual")
		{
			disktable->add_item_line(media_type);
		}
		else
		{
			disktable->add_item_line(media_type + (disk->is_ssd() ? " SSD" : " HDD"));
		}
		disktable->add_item_line(constants::disk::partition_type(disk->partition_type()));
		disktable->add_item_line(std::to_string(disk->size()) + " (" + utils::format::size(disk->size()) + ")");
		disktable->new_line();
	}

	if (disks.size() > 0)
	{
		utils::ui::title("Disks:");
		disktable->render(std::cout);
	}
	else
	{
		std::cout << "No disk found" << std::endl;
	}
}

void print_hardware_disk(std::shared_ptr<Disk> disk) {
	utils::ui::title("Info for disk: " + disk->name());

	std::cout << "    Model       : " << disk->product_id() << std::endl;
	std::cout << "    Version     : " << disk->product_version() << std::endl;
	std::cout << "    Serial      : " << disk->serial_number() << std::endl;
	std::cout << "    Media Type  : " << constants::disk::media_type(disk->geometry()->Geometry.MediaType) << (disk->is_ssd() ? " SSD" : " HDD") << std::endl;
	std::cout << "    Size        : " << disk->size() << " (" << utils::format::size(disk->size()) << ")" << std::endl;
	std::cout << "    Geometry    : " << std::to_string(disk->geometry()->Geometry.BytesPerSector) << " bytes * " << std::to_string(disk->geometry()->Geometry.SectorsPerTrack) << " sectors * " << std::to_string(disk->geometry()->Geometry.TracksPerCylinder) << " tracks * " << std::to_string(disk->geometry()->Geometry.Cylinders.QuadPart) << " cylinders" << std::endl;
	std::cout << "    Partition   : " << constants::disk::partition_type(disk->partition_type()) << std::endl;
	std::cout << std::endl;

	std::shared_ptr<utils::ui::Table> partitions = std::make_shared<utils::ui::Table>();
	partitions->set_margin_left(4);
	partitions->add_header_line("Id");
	switch (disk->partition_type()) {
	case PARTITION_STYLE_MBR:
	{
		partitions->add_header_line("Boot");
		break;
	}
	case PARTITION_STYLE_GPT:
	{
		partitions->add_header_line("Type");
		break;
	}
	default:
		break;
	}
	partitions->add_header_line("Label");
	partitions->add_header_line("Mounted");
	partitions->add_header_line("Filesystem");
	partitions->add_header_line("Offset");
	partitions->add_header_line("Size");

	for (std::shared_ptr<Volume> volume : disk->volumes()) {
		partitions->add_item_line(std::to_string(volume->index()));

		switch (disk->partition_type()) {
		case PARTITION_STYLE_MBR:
		{
			if (volume->bootable()) partitions->add_item_line("Yes");
			else partitions->add_item_line("No");
			break;
		}
		case PARTITION_STYLE_GPT:
		{
			partitions->add_item_line(volume->guid_type());
			break;
		}
		default:
			break;
		}

		partitions->add_item_line(volume->label());
		partitions->add_item_line(utils::strings::join_vec(volume->mountpoints(), ", "));
		partitions->add_item_line(volume->filesystem());
		partitions->add_item_line(utils::format::hex(volume->offset()));
		partitions->add_item_line(utils::format::hex(volume->size()) + " (" + utils::format::size(volume->size()) + ")");

		partitions->new_line();
	}

	partitions->render(std::cout);
	std::cout << std::endl;
}


void print_image_disk(std::shared_ptr<Disk> disk) {
	utils::ui::title("Info for image: " + disk->name());

	HANDLE hDisk = CreateFileA(disk->name().c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if (hDisk != INVALID_HANDLE_VALUE)
	{
		FILETIME creation, write, access;
		SYSTEMTIME creation_s, write_s, access_s;
		if (GetFileTime(hDisk, &creation, &access, &write))
		{
			utils::times::filetime_to_local_systemtime(creation, &creation_s);
			std::cout << "Creation    : " << utils::times::display_systemtime(creation_s) << std::endl;
			utils::times::filetime_to_local_systemtime(write, &write_s);
			std::cout << "Modification: " << utils::times::display_systemtime(write_s) << std::endl;
			utils::times::filetime_to_local_systemtime(access, &access_s);
			std::cout << "Access      : " << utils::times::display_systemtime(access_s) << std::endl;
			std::cout << std::endl;
			if (utils::ui::ask_question("Hash SHA256"))
			{
				BYTE hashbuf[SHA256_DIGEST_LENGTH] = { 0 };
				std::cout << std::endl;
				std::cout << "Hash SHA256 : Calculating ...";
				utils::crypto::hash::sha256_file(disk->name(), hashbuf);
				std::cout << "\r" << "Hash SHA256 : " << utils::format::hex(hashbuf, SHA256_DIGEST_LENGTH) << std::endl;
				std::cout << std::endl;
			}
			else
			{
				std::cout << std::endl;
			}
		}
		CloseHandle(hDisk);
	}

	std::cout << "Size        : " << disk->size() << " (" << utils::format::size(disk->size()) << ")" << std::endl;
	std::cout << "Volume      : " << constants::disk::partition_type(disk->partition_type()) << std::endl;
	std::cout << std::endl;

	std::shared_ptr<utils::ui::Table> partitions = std::make_shared<utils::ui::Table>();
	partitions->add_header_line("Id");
	switch (disk->partition_type()) {
	case PARTITION_STYLE_MBR:
	{
		partitions->add_header_line("Boot");
		break;
	}
	case PARTITION_STYLE_GPT:
	{
		partitions->add_header_line("Type");
		break;
	}
	default:
		break;
	}
	partitions->add_header_line("Filesystem");
	partitions->add_header_line("Offset");
	partitions->add_header_line("Size");

	for (std::shared_ptr<Volume> volume : disk->volumes()) {
		partitions->add_item_line(std::to_string(volume->index()));

		switch (disk->partition_type()) {
		case PARTITION_STYLE_MBR:
		{
			if (volume->bootable()) partitions->add_item_line("Yes");
			else partitions->add_item_line("No");
			break;
		}
		case PARTITION_STYLE_GPT:
		{
			partitions->add_item_line(volume->guid_type());
			break;
		}
		default:
			break;
		}

		partitions->add_item_line(volume->filesystem());
		partitions->add_item_line(utils::format::hex(volume->offset()));
		partitions->add_item_line(utils::format::hex(volume->size()) + " (" + utils::format::size(volume->size()) + ")");

		partitions->new_line();
	}

	partitions->render(std::cout);
	std::cout << std::endl;
}

void print_hardware_volume(std::shared_ptr<Disk> disk, std::shared_ptr<Volume> vol) {
	utils::ui::title("Info for " + disk->name() + " > Volume:" + std::to_string(vol->index()));

	if (vol->serial_number())
	{
		std::cout << "Serial Number  : ";
		std::cout << utils::format::hex(vol->serial_number() >> 16) << "-" << utils::format::hex(vol->serial_number() & 0xffff) << std::endl;
	}
	if (vol->filesystem().length() > 0)
	{
		std::cout << "Filesystem     : " << vol->filesystem() << std::endl;
	}
	if (vol->partition_type() == PARTITION_STYLE_MBR)
	{
		std::cout << "Bootable       : " << (vol->bootable() ? "True" : "False") << std::endl;
	}
	if (vol->partition_type() == PARTITION_STYLE_GPT)
	{
		std::cout << "GUID           : " << vol->guid_type() << std::endl;
	}
	std::cout << "Type           : " << constants::disk::drive_type(vol->type()) << std::endl;
	if (vol->label().length() > 0)
	{
		std::cout << "Label          : " << vol->label() << std::endl;
	}
	std::cout << "Offset         : " << vol->offset() << " (" << utils::format::size(vol->offset()) << ")" << std::endl;
	std::cout << "Size           : " << vol->size() << " (" << utils::format::size(vol->size()) << ")" << std::endl;
	std::cout << "Free           : " << vol->free() << " (" << utils::format::size(vol->free()) << ")" << std::endl;

	std::cout << "Mounted        : " << (vol->is_mounted() ? "True" : "False");
	if (vol->is_mounted())
	{
		std::cout << " (" << utils::strings::join_vec(vol->mountpoints(), ", ") << ")";
	}
	std::cout << std::endl;
	std::cout << "Bitlocker      : " << (vol->bitlocker().bitlocked ? "True" : "False");
	if (vol->bitlocker().bitlocked)
	{
		std::cout << " (" << (vol->filesystem().length() == 0 ? "Locked" : "Unlocked") << ")";
	}
	std::cout << std::endl;
}

void print_image_volume(std::shared_ptr<Disk> disk, std::shared_ptr<Volume> vol) {
	utils::ui::title("Info for image: " + disk->name() + " > Volume:" + std::to_string(vol->index()));

	if (vol->filesystem().length() > 0)
	{
		std::cout << "Filesystem     : " << vol->filesystem() << std::endl;
	}
	if (vol->partition_type() == PARTITION_STYLE_MBR)
	{
		std::cout << "Bootable       : " << (vol->bootable() ? "True" : "False") << std::endl;
	}
	if (vol->partition_type() == PARTITION_STYLE_GPT)
	{
		std::cout << "GUID           : " << vol->guid_type() << std::endl;
	}

	std::cout << "Offset         : " << vol->offset() << " (" << utils::format::size(vol->offset()) << ")" << std::endl;
	std::cout << "Size           : " << vol->size() << " (" << utils::format::size(vol->size()) << ")" << std::endl;
	std::cout << "Bitlocker      : " << (vol->bitlocker().bitlocked ? "True" : "False");
	if (vol->bitlocker().bitlocked)
	{
		std::cout << " (" << (vol->filesystem().length() == 0 ? "Locked" : "Unlocked") << ")";
	}
	std::cout << std::endl;
}

int print_disks(std::shared_ptr<Options> opts)
{
	if ((opts->image == "") && (opts->disk == -1))
	{
		print_disks_short(core::win::disks::list());
		return 0;
	}

	std::shared_ptr<Disk> disk = get_disk(opts);
	if (disk != nullptr)
	{
		if (opts->image != "") print_image_disk(disk);
		else print_hardware_disk(disk);
	}
	else
	{
		invalid_option(opts, "disk", opts->disk);
	}

	return 0;
}

int print_partitions(std::shared_ptr<Options> opts)
{
	std::ios_base::fmtflags flag_backup(std::cout.flags());

	std::shared_ptr<Disk> disk = get_disk(opts);
	if (disk != nullptr)
	{
		std::shared_ptr<Volume> volume = disk->volumes(opts->volume);
		if (volume != nullptr)
		{
			if (opts->image != "")
			{
				print_image_volume(disk, volume);
			}
			else
			{
				print_hardware_volume(disk, volume);
			}
		}
		else
		{
			invalid_option(opts, "volume", opts->volume);
		}
	}
	else
	{
		invalid_option(opts, "disk", opts->disk);
	}

	std::cout.flags(flag_backup);
	return 0;
}

namespace commands
{
	namespace info
	{
		int dispatch(std::shared_ptr<Options> opts)
		{
			if ((opts->disk != -1 || opts->image != "") && opts->volume != -1)
			{
				print_partitions(opts);
			}
			else
			{
				print_disks(opts);
			}
			return 0;
		}
	}
}