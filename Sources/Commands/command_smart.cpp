
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


bool isSmartEnabled(HANDLE hDevice, DWORD ucDriveIndex)
{
	SENDCMDINPARAMS stCIP = { 0 };
	SENDCMDOUTPARAMS stCOP = { 0 };
	DWORD dwRet = 0;
	BOOL bRet = FALSE;

	stCIP.cBufferSize = 0;
	stCIP.bDriveNumber = ucDriveIndex & 0xff;
	stCIP.irDriveRegs.bFeaturesReg = ENABLE_SMART;
	stCIP.irDriveRegs.bSectorCountReg = 1;
	stCIP.irDriveRegs.bSectorNumberReg = 1;
	stCIP.irDriveRegs.bCylLowReg = SMART_CYL_LOW;
	stCIP.irDriveRegs.bCylHighReg = SMART_CYL_HI;
	stCIP.irDriveRegs.bDriveHeadReg = DRIVE_HEAD_REG | ((ucDriveIndex & 1) << 4);
	stCIP.irDriveRegs.bCommandReg = SMART_CMD;

	return DeviceIoControl(hDevice, SMART_SEND_DRIVE_COMMAND, &stCIP, sizeof(stCIP) - 1, &stCOP, sizeof(stCOP) - 1, &dwRet, NULL);
}

bool readSmartAttributes(HANDLE hDevice, DWORD ucDriveIndex, std::shared_ptr<Buffer<PST_ATAOUTPARAM_ATTRIBUTES>> outputBuffer)
{
	SENDCMDINPARAMS stCIP = { 0 };
	SENDCMDOUTPARAMS stCOP = { 0 };
	DWORD dwRet = 0;
	BOOL bRet = FALSE;

	stCIP.cBufferSize = READ_ATTRIBUTE_BUFFER_SIZE;
	stCIP.bDriveNumber = ucDriveIndex & 0xff;
	stCIP.irDriveRegs.bFeaturesReg = READ_ATTRIBUTES;
	stCIP.irDriveRegs.bSectorCountReg = 1;
	stCIP.irDriveRegs.bSectorNumberReg = 1;
	stCIP.irDriveRegs.bCylLowReg = SMART_CYL_LOW;
	stCIP.irDriveRegs.bCylHighReg = SMART_CYL_HI;
	stCIP.irDriveRegs.bDriveHeadReg = DRIVE_HEAD_REG | (((ucDriveIndex & 0xff) & 1) << 4);
	stCIP.irDriveRegs.bCommandReg = SMART_CMD;

	return DeviceIoControl(hDevice, SMART_RCV_DRIVE_DATA, &stCIP, sizeof(stCIP) - 1, outputBuffer->data(), outputBuffer->size() - 1, &dwRet, NULL);
}



bool readSmartThresholds(HANDLE hDevice, DWORD ucDriveIndex, std::shared_ptr<Buffer<PST_ATAOUTPARAM_THRESHOLDS>> outputBuffer)
{
	SENDCMDINPARAMS stCIP = { 0 };
	SENDCMDOUTPARAMS stCOP = { 0 };
	DWORD dwRet = 0;
	BOOL bRet = FALSE;

	stCIP.cBufferSize = READ_THRESHOLD_BUFFER_SIZE;
	stCIP.bDriveNumber = ucDriveIndex & 0xff;
	stCIP.irDriveRegs.bFeaturesReg = READ_THRESHOLDS;
	stCIP.irDriveRegs.bSectorCountReg = 1;
	stCIP.irDriveRegs.bSectorNumberReg = 1;
	stCIP.irDriveRegs.bCylLowReg = SMART_CYL_LOW;
	stCIP.irDriveRegs.bCylHighReg = SMART_CYL_HI;
	stCIP.irDriveRegs.bDriveHeadReg = DRIVE_HEAD_REG | (((ucDriveIndex & 0xff) & 1) << 4);
	stCIP.irDriveRegs.bCommandReg = SMART_CMD;

	return DeviceIoControl(hDevice, SMART_RCV_DRIVE_DATA, &stCIP, sizeof(stCIP) - 1, outputBuffer->data(), outputBuffer->size() - 1, &dwRet, NULL);
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
			std::cout << "    Version       : " << std::to_string(versionInfo.bVersion) << " revision " << std::to_string(versionInfo.bRevision) << std::endl;
			std::cout << "    Type          : " << constants::disk::smart::devicemap_type(versionInfo.bIDEDeviceMap) << std::endl;
			std::cout << "    Capabilities  : " << constants::disk::smart::capabilities(versionInfo.fCapabilities) << std::endl;
			std::cout << std::endl;

			if ((versionInfo.fCapabilities & CAP_SMART_CMD) == CAP_SMART_CMD)
			{
				if (isSmartEnabled(hDisk, disk->index()))
				{
					dwRet = 0;
					auto attributeBuffer = std::make_shared<Buffer<PST_ATAOUTPARAM_ATTRIBUTES>>(sizeof(ST_ATAOUTPARAM_ATTRIBUTES) + READ_ATTRIBUTE_BUFFER_SIZE);
					auto thresholdBuffer = std::make_shared<Buffer<PST_ATAOUTPARAM_THRESHOLDS>>(sizeof(ST_ATAOUTPARAM_THRESHOLDS) + READ_THRESHOLD_BUFFER_SIZE);

					if (readSmartAttributes(hDisk, disk->index(), attributeBuffer) && readSmartThresholds(hDisk, disk->index(), thresholdBuffer))
					{
						std::shared_ptr<utils::ui::Table> table = std::make_shared<utils::ui::Table>();
						table->set_margin_left(4);

						table->add_header_line("Index", utils::ui::TableAlign::RIGHT);
						table->add_header_line("Name");
						table->add_header_line("Flags");
						table->add_header_line("Raw", utils::ui::TableAlign::RIGHT);
						table->add_header_line("Value / Worst / Threshold", utils::ui::TableAlign::RIGHT);
						table->add_header_line("Status", utils::ui::TableAlign::RIGHT);

						unsigned int nb_attributes = attributeBuffer->data()->cBufferSize / 0xc;
						PST_SMART_ATTRIBUTE currAttribute = &attributeBuffer->data()->bBuffer[0];
						PST_SMART_THRESHOLD currThreshold = &thresholdBuffer->data()->bBuffer[0];
						for (unsigned int i = 0; i < nb_attributes; i++)
						{
							if (currAttribute->index)
							{
								table->add_item_line(utils::strings::upper(utils::format::hex(currAttribute->index)) + "h");
								table->add_item_line(constants::disk::smart::attribute_name(currAttribute->index));
								table->add_item_line(utils::strings::upper(utils::format::hex(currAttribute->flags)) + "h");
								table->add_item_line(utils::strings::upper(utils::format::hex6(currAttribute->rawValue6)) + "h");
								table->add_item_line(std::to_string(currAttribute->value) + " / " + std::to_string(currAttribute->worst) + " / " + std::to_string(currThreshold->threshold));
								table->add_item_line(currAttribute->value < currThreshold->threshold ? "Failure" : "Ok");
								table->new_line();
							}
							currAttribute = POINTER_ADD(PST_SMART_ATTRIBUTE, currAttribute, 0xc);
							currThreshold = POINTER_ADD(PST_SMART_THRESHOLD, currThreshold, 0xc);
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