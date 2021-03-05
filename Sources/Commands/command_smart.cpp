
#include "Utils/buffer.h"
#include "Drive/disk.h"
#include "Drive/smart.h"
#include "Utils/table.h"
#include "Utils/utils.h"
#include "Utils/constant_names.h"
#include "options.h"

#include <algorithm>
#include <cstdint>
#include <string>
#include <iostream>
#include <iomanip>
#include <memory>
#include <stdexcept> 


bool smart_is_enabled(HANDLE hDevice, BYTE driveIndex)
{
	SENDCMDINPARAMS stCIP = { 0 };
	SENDCMDOUTPARAMS stCOP = { 0 };
	DWORD dwRet = 0;

	stCIP.cBufferSize = 0;
	stCIP.bDriveNumber = driveIndex;
	stCIP.irDriveRegs.bFeaturesReg = ENABLE_SMART;
	stCIP.irDriveRegs.bSectorCountReg = 1;
	stCIP.irDriveRegs.bSectorNumberReg = 1;
	stCIP.irDriveRegs.bCylLowReg = SMART_CYL_LOW;
	stCIP.irDriveRegs.bCylHighReg = SMART_CYL_HI;
	stCIP.irDriveRegs.bDriveHeadReg = DRIVE_HEAD_REG | ((driveIndex & 1) << 4);
	stCIP.irDriveRegs.bCommandReg = SMART_CMD;

	return DeviceIoControl(hDevice, SMART_SEND_DRIVE_COMMAND, &stCIP, sizeof(stCIP) - 1, &stCOP, sizeof(stCOP) - 1, &dwRet, NULL);
}

bool smart_read_attributes(HANDLE hDevice, BYTE driveIndex, std::shared_ptr<Buffer<PSMART_OUTPUT_ATTRIBUTES>> outputBuffer)
{
	SENDCMDINPARAMS stCIP = { 0 };
	DWORD dwRet = 0;

	stCIP.cBufferSize = READ_ATTRIBUTE_BUFFER_SIZE;
	stCIP.bDriveNumber = driveIndex;
	stCIP.irDriveRegs.bFeaturesReg = READ_ATTRIBUTES;
	stCIP.irDriveRegs.bSectorCountReg = 1;
	stCIP.irDriveRegs.bSectorNumberReg = 1;
	stCIP.irDriveRegs.bCylLowReg = SMART_CYL_LOW;
	stCIP.irDriveRegs.bCylHighReg = SMART_CYL_HI;
	stCIP.irDriveRegs.bDriveHeadReg = DRIVE_HEAD_REG | ((driveIndex & 1) << 4);
	stCIP.irDriveRegs.bCommandReg = SMART_CMD;

	return DeviceIoControl(hDevice, SMART_RCV_DRIVE_DATA, &stCIP, sizeof(stCIP) - 1, outputBuffer->data(), outputBuffer->size() - 1, &dwRet, NULL);
}

bool smart_read_thresholds(HANDLE hDevice, BYTE driveIndex, std::shared_ptr<Buffer<PSMART_OUTPUT_THRESHOLDS>> outputBuffer)
{
	SENDCMDINPARAMS stCIP = { 0 };
	DWORD dwRet = 0;

	stCIP.cBufferSize = READ_THRESHOLD_BUFFER_SIZE;
	stCIP.bDriveNumber = driveIndex;
	stCIP.irDriveRegs.bFeaturesReg = READ_THRESHOLDS;
	stCIP.irDriveRegs.bSectorCountReg = 1;
	stCIP.irDriveRegs.bSectorNumberReg = 1;
	stCIP.irDriveRegs.bCylLowReg = SMART_CYL_LOW;
	stCIP.irDriveRegs.bCylHighReg = SMART_CYL_HI;
	stCIP.irDriveRegs.bDriveHeadReg = DRIVE_HEAD_REG | ((driveIndex & 1) << 4);
	stCIP.irDriveRegs.bCommandReg = SMART_CMD;

	return DeviceIoControl(hDevice, SMART_RCV_DRIVE_DATA, &stCIP, sizeof(stCIP) - 1, outputBuffer->data(), outputBuffer->size() - 1, &dwRet, NULL);
}

bool smart_read_status(HANDLE hDevice, BYTE driveIndex, std::shared_ptr<Buffer<PSMART_OUTPUT_STATUS>> outputBuffer)
{
	SENDCMDINPARAMS stCIP = { 0 };
	DWORD dwRet = 0;

	stCIP.cBufferSize = READ_STATUS_BUFFER_SIZE;
	stCIP.bDriveNumber = driveIndex;
	stCIP.irDriveRegs.bFeaturesReg = RETURN_SMART_STATUS;
	stCIP.irDriveRegs.bSectorCountReg = 1;
	stCIP.irDriveRegs.bSectorNumberReg = 1;
	stCIP.irDriveRegs.bCylLowReg = SMART_CYL_LOW;
	stCIP.irDriveRegs.bCylHighReg = SMART_CYL_HI;
	stCIP.irDriveRegs.bDriveHeadReg = DRIVE_HEAD_REG | ((driveIndex & 1) << 4);
	stCIP.irDriveRegs.bCommandReg = SMART_CMD;

	return DeviceIoControl(hDevice, SMART_SEND_DRIVE_COMMAND, &stCIP, sizeof(stCIP) - 1, outputBuffer->data(), outputBuffer->size() - 1, &dwRet, NULL);
}

bool smart_read_identity(HANDLE hDevice, BYTE driveIndex, std::shared_ptr<Buffer<PSMART_OUTPUT_IDENTITY>> outputBuffer)
{
	SENDCMDINPARAMS stCIP = { 0 };
	DWORD dwRet = 0;

	stCIP.cBufferSize = READ_IDENTITY_BUFFER_SIZE;
	stCIP.bDriveNumber = driveIndex;
	stCIP.irDriveRegs.bFeaturesReg = 0;
	stCIP.irDriveRegs.bSectorCountReg = 1;
	stCIP.irDriveRegs.bSectorNumberReg = 1;
	stCIP.irDriveRegs.bCylLowReg = 0;
	stCIP.irDriveRegs.bCylHighReg = 0;
	stCIP.irDriveRegs.bDriveHeadReg = DRIVE_HEAD_REG | ((driveIndex & 1) << 4);
	stCIP.irDriveRegs.bCommandReg = ID_CMD;

	return DeviceIoControl(hDevice, SMART_RCV_DRIVE_DATA, &stCIP, sizeof(stCIP) - 1, outputBuffer->data(), outputBuffer->size() - 1, &dwRet, NULL);
}

std::string read_string(PVOID buffer, DWORD len)
{
	std::ostringstream os;
	auto char_buffer = reinterpret_cast<PCHAR>(buffer);
	bool first_byte = true;

	for (int i = len - 1; i >= 0; i -= 2)
	{
		os << char_buffer[i - 1] << char_buffer[i];
	}

	auto ret = utils::strings::reverse(os.str());

	ret.erase(ret.begin(), std::find_if(ret.begin(), ret.end(), [](int ch) {
		return !std::isspace(ch & 0xff) && (ch != 0);
		}));

	return ret;
}

void print_smart_data(std::shared_ptr<Disk> disk)
{
	utils::ui::title("S.M.A.R.T data from " + disk->name());

	HANDLE hDisk = CreateFileA(disk->name().c_str(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_SYSTEM, 0);
	if (hDisk != INVALID_HANDLE_VALUE)
	{
		GETVERSIONINPARAMS versionInfo = { 0 };
		DWORD dwRet = 0;
		bool ret = DeviceIoControl(hDisk, SMART_GET_VERSION, NULL, 0, &versionInfo, sizeof(GETVERSIONINPARAMS), &dwRet, NULL);
		if (ret)
		{
			std::cout << "    S.M.A.R.T Version: " << std::to_string(versionInfo.bVersion) << " revision " << std::to_string(versionInfo.bRevision) << std::endl;
			std::cout << "    Type             : " << constants::disk::smart::devicemap_type(versionInfo.bIDEDeviceMap) << std::endl;
			std::cout << "    Capabilities     : " << constants::disk::smart::capabilities(versionInfo.fCapabilities) << std::endl;
			std::cout << std::endl;

			if ((versionInfo.fCapabilities & CAP_SMART_CMD) == CAP_SMART_CMD)
			{
				if (smart_is_enabled(hDisk, static_cast<BYTE>(disk->index())))
				{
					dwRet = 0;
					auto statusBuffer = std::make_shared<Buffer<PSMART_OUTPUT_STATUS>>(sizeof(SMART_OUTPUT_STATUS) + READ_STATUS_BUFFER_SIZE);

					if (smart_read_status(hDisk, static_cast<BYTE>(disk->index()), statusBuffer))
					{
						std::cout << "    Status          : " <<
							((statusBuffer->data()->Status.bCylLowReg == SMART_CYL_LOW_BAD && statusBuffer->data()->Status.bCylHighReg == SMART_CYL_HI_BAD) ?
								"Threshold Exceeded Condition!" :
								"Passed") <<
							std::endl << std::endl;
					}
					else
					{
						std::cerr << "[!] Failed to read S.M.A.R.T status." << std::endl;
					}

					auto idBuffer = std::make_shared<Buffer<PSMART_OUTPUT_IDENTITY>>(sizeof(SMART_OUTPUT_IDENTITY) + READ_IDENTITY_BUFFER_SIZE);

					if (smart_read_identity(hDisk, static_cast<BYTE>(disk->index()), idBuffer))
					{
						std::cout << "    -- Device ID" << std::endl << std::endl;
						std::shared_ptr<utils::ui::Table> table = std::make_shared<utils::ui::Table>();
						table->set_margin_left(4);

						table->add_header_line("Property");
						table->add_header_line("Value");

						table->add_item_line("General Configuration");
						table->add_item_line(utils::format::hex(idBuffer->data()->Identity.wGenConfig, true));
						table->new_line();
						table->add_item_line("Number of Cylinders");
						table->add_item_line(std::to_string(idBuffer->data()->Identity.wNumCyls));
						table->new_line();
						table->add_item_line("Reserved");
						table->add_item_line(utils::format::hex(idBuffer->data()->Identity.wReserved, true));
						table->new_line();
						table->add_item_line("Number Of Heads");
						table->add_item_line(std::to_string(idBuffer->data()->Identity.wNumHeads));
						table->new_line();
						table->add_item_line("Bytes Per Track");
						table->add_item_line(std::to_string(idBuffer->data()->Identity.wBytesPerTrack));
						table->new_line();
						table->add_item_line("Bytes Per Sector");
						table->add_item_line(std::to_string(idBuffer->data()->Identity.wBytesPerSector));
						table->new_line();
						table->add_item_line("Sectors Per Track");
						table->add_item_line(std::to_string(idBuffer->data()->Identity.wSectorsPerTrack));
						table->new_line();
						table->add_item_line("Vendor Unique");
						table->add_item_line(read_string(idBuffer->data()->Identity.wVendorUnique, 6));
						table->new_line();
						table->add_item_line("Seria Number");
						table->add_item_line(read_string(idBuffer->data()->Identity.sSerialNumber, 20));
						table->new_line();
						table->add_item_line("Buffer Type");
						table->add_item_line(std::to_string(idBuffer->data()->Identity.wBufferType));
						table->new_line();
						table->add_item_line("Buffer Size");
						table->add_item_line(std::to_string(idBuffer->data()->Identity.wBufferSize));
						table->new_line();
						table->add_item_line("ECC Size");
						table->add_item_line(std::to_string(idBuffer->data()->Identity.wECCSize));
						table->new_line();
						table->add_item_line("Firmware Revision");
						table->add_item_line(read_string(idBuffer->data()->Identity.sFirmwareRev, 8));
						table->new_line();
						table->add_item_line("Model Number");
						table->add_item_line(read_string(idBuffer->data()->Identity.sModelNumber, 40));
						table->new_line();
						table->add_item_line("Maximum Number of Sectors On R/W");
						table->add_item_line(std::to_string(idBuffer->data()->Identity.wMoreVendorUnique));
						table->new_line();
						table->add_item_line("Double Word IO");
						table->add_item_line(std::to_string(idBuffer->data()->Identity.wDoubleWordIO));
						table->new_line();
						table->add_item_line("Capabilities");
						table->add_item_line(std::to_string(idBuffer->data()->Identity.wCapabilities));
						table->new_line();
						table->add_item_line("Reserved1");
						table->add_item_line(utils::format::hex(idBuffer->data()->Identity.wReserved1, true));
						table->new_line();
						table->add_item_line("PIO Timing");
						table->add_item_line(std::to_string(idBuffer->data()->Identity.wPIOTiming));
						table->new_line();
						table->add_item_line("DMA Timing");
						table->add_item_line(std::to_string(idBuffer->data()->Identity.wDMATiming));
						table->new_line();
						table->add_item_line("BS");
						table->add_item_line(std::to_string(idBuffer->data()->Identity.wBS));
						table->new_line();
						table->add_item_line("Current numbers of cylinders");
						table->add_item_line(std::to_string(idBuffer->data()->Identity.wNumCurrentCyls));
						table->new_line();
						table->add_item_line("Current numbers of heads");
						table->add_item_line(std::to_string(idBuffer->data()->Identity.wNumCurrentHeads));
						table->new_line();
						table->add_item_line("Current numbers of sectors per track");
						table->add_item_line(std::to_string(idBuffer->data()->Identity.wNumCurrentSectorsPerTrack));
						table->new_line();
						table->add_item_line("Multiple Sector Setting");
						table->add_item_line(std::to_string(idBuffer->data()->Identity.wMultSectorStuff));
						table->new_line();
						table->add_item_line("Total Number of Sectors Addressable (LBA)");
						table->add_item_line(std::to_string(idBuffer->data()->Identity.ulTotalAddressableSectors));
						table->new_line();
						table->add_item_line("Singleword DMA Transfer");
						table->add_item_line(std::to_string(idBuffer->data()->Identity.wSingleWordDMA));
						table->new_line();
						table->add_item_line("Multiword DMA Transfer");
						table->add_item_line(std::to_string(idBuffer->data()->Identity.wMultiWordDMA));
						table->new_line();
						table->add_item_line("Advanced PIO Modes");
						table->add_item_line(utils::format::hex(idBuffer->data()->Identity.wMultiWordDMA, true));
						table->new_line();
						table->add_item_line("Multiword DMA Transfer");
						table->add_item_line(std::to_string(idBuffer->data()->Identity.wMultiWordDMA));
						table->new_line();
						table->add_item_line("Minimum Multiword DMA Transfer Cycle Time per Word");
						table->add_item_line(std::to_string(idBuffer->data()->Identity.wMinMultiWordDMACycle));
						table->new_line();
						table->add_item_line("Recommended Multiword DMA Transfer Cycle Time per Word");
						table->add_item_line(std::to_string(idBuffer->data()->Identity.wRecMultiWordDMACycle));
						table->new_line();
						table->add_item_line("Minimum PIO Transfer Cycle Time");
						table->add_item_line(std::to_string(idBuffer->data()->Identity.wMinPIONoFlowCycle));
						table->new_line();
						table->add_item_line("Recommended PIO Transfer Cycle Time");
						table->add_item_line(std::to_string(idBuffer->data()->Identity.wMinPOIFlowCycle));
						table->new_line();

						table->render(std::cout);
						std::cout << std::endl;
					}
					else
					{
						std::cerr << "[!] Failed to read S.M.A.R.T status." << std::endl;
					}

					auto attributeBuffer = std::make_shared<Buffer<PSMART_OUTPUT_ATTRIBUTES>>(sizeof(SMART_OUTPUT_ATTRIBUTES) + READ_ATTRIBUTE_BUFFER_SIZE);
					auto thresholdBuffer = std::make_shared<Buffer<PSMART_OUTPUT_THRESHOLDS>>(sizeof(SMART_OUTPUT_THRESHOLDS) + READ_THRESHOLD_BUFFER_SIZE);

					if (smart_read_attributes(hDisk, static_cast<BYTE>(disk->index()), attributeBuffer) &&
						smart_read_thresholds(hDisk, static_cast<BYTE>(disk->index()), thresholdBuffer))
					{
						std::cout << "    -- Attributes" << std::endl << std::endl;

						std::shared_ptr<utils::ui::Table> table = std::make_shared<utils::ui::Table>();
						table->set_margin_left(4);

						table->add_header_line("Index", utils::ui::TableAlign::RIGHT);
						table->add_header_line("Name");
						table->add_header_line("Flags");
						table->add_header_line("Raw", utils::ui::TableAlign::RIGHT);
						table->add_header_line("Value", utils::ui::TableAlign::RIGHT);
						table->add_header_line("Worst", utils::ui::TableAlign::RIGHT);
						table->add_header_line("Threshold", utils::ui::TableAlign::RIGHT);
						table->add_header_line("Status", utils::ui::TableAlign::RIGHT);

						unsigned int nb_attributes = attributeBuffer->data()->cBufferSize / 0xc;
						PSMART_ATTRIBUTE currAttribute = &attributeBuffer->data()->Attributes[0];
						PSMART_THRESHOLD currThreshold = &thresholdBuffer->data()->Threshold[0];
						for (unsigned int i = 0; i < nb_attributes; i++)
						{
							if (currAttribute->index)
							{
								table->add_item_line(utils::format::hex(currAttribute->index, true));
								table->add_item_line(constants::disk::smart::attribute_name(currAttribute->index));
								table->add_item_line(utils::format::hex(currAttribute->flags, true));
								table->add_item_line(utils::format::hex6(currAttribute->rawValue48, true));
								table->add_item_line(std::to_string(currAttribute->value));
								table->add_item_line(std::to_string(currAttribute->worst));
								table->add_item_line(std::to_string(currThreshold->threshold));
								table->add_item_line(currAttribute->value < currThreshold->threshold ? "Failure" : "Ok");
								table->new_line();
							}
							currAttribute = POINTER_ADD(PSMART_ATTRIBUTE, currAttribute, 0xc);
							currThreshold = POINTER_ADD(PSMART_THRESHOLD, currThreshold, 0xc);
						}

						table->render(std::cout);
						std::cout << std::endl;
					}
					else
					{
						std::cerr << "[!] Failed to read S.M.A.R.T attributes." << std::endl;
					}
				}
				else
				{
					std::cerr << "[!] S.M.A.R.T is not enabled." << std::endl;
				}
			}
			else
			{
				std::cerr << "[!] S.M.A.R.T commands are not supported." << std::endl;
			}
		}
		CloseHandle(hDisk);
	}

	std::cout << std::endl;
}

namespace commands {

	namespace smart {

		int print_smart(std::shared_ptr<Options> opts) {
			std::ios_base::fmtflags flag_backup(std::cout.flags());

			std::shared_ptr<Disk> disk = get_disk(opts);

			if (disk != nullptr)
			{
				print_smart_data(disk);
			}

			std::cout.flags(flag_backup);
			return 0;
		}
	}
}