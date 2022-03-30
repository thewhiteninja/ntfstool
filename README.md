# ntfstool

[![GitHub license](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE.MIT)
[![Language: C++](https://img.shields.io/badge/Language-C%2B%2B-brightgreen.svg?tyle=flat-square)](#)
[![x64](https://img.shields.io/badge/Windows-64_bit-0078d7.svg)](#)
[![x86](https://img.shields.io/badge/Windows-32_bit-0078d7.svg)](#)
[![v1.6](https://img.shields.io/badge/Version-1.6-ff5733.svg)](#)
[![Build](https://ci.appveyor.com/api/projects/status/a3cn5dpdv146tdji?svg=true)](https://ci.appveyor.com/project/thewhiteninja/ntfstool)

<img align="right" width="100" height="100" src="https://cdn-icons-png.flaticon.com/512/3850/3850133.png">

<br />

NTFSTool is a forensic tool focused on [NTFS][10] volumes.
It supports reading partition info (MBR, partition table, VBR) but also information on Master File Table, Bitlocker encrypted volume, EFS encrypted files, USN journal and more.

Download the latest binaries on [AppVeyor](https://ci.appveyor.com/project/thewhiteninja/ntfstool).

See below for some [examples](#examples) of the features!


## Features

### Forensics

NTFSTool displays the complete structure of master boot record, volume boot record, partition table and [$MFT][8] file record.
It is also possible to dump any file (even $MFT or [SAM][9]) or parse and analyze [USN journal][6], [LogFile][7] including streams from Alternate Data Stream ([ADS][5]). $MFT can be dumped as csv or json with [Zone.Identifier][13] parsing to quickly identify downloaded files.
The undelete command will search for any file record marked as "not in use" and allow you to retrieve the file (or part of the file if it was already rewritten).
It support input from image file, live disk or virtual like [VeraCrypt][11] and [TrueCrypt][12], but you can also use tools like [OSFMount][3] to mount your disk image.
Sparse and compressed files (lznt1, xpress) are also supported. 

[3]: https://www.osforensics.com/tools/mount-disk-images.html
[5]: https://www.sans.org/white-papers/1503/
[6]: https://docs.microsoft.com/en-gb/windows/win32/fileio/change-journal-records
[7]: https://dfir.ru/2019/02/16/how-the-logfile-works/
[8]: https://en.wikipedia.org/wiki/NTFS#Master_File_Table
[9]: https://en.wikipedia.org/wiki/Security_Account_Manager
[10]: https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc781134(v=ws.10)?redirectedfrom=MSDN
[11]: https://www.veracrypt.fr/en/Home.html
[12]: http://truecrypt.sourceforge.net/
[13]: https://www.digital-detective.net/forensic-analysis-of-zone-identifier-stream/

### Bitlocker support

For bitlocked partition, it can display FVE records, check a password and key (bek, password, recovery key), extract VMK and FVEK.
There is no bruteforce feature because GPU-based cracking is better (see [Bitcracker][1] and [Hashcat][2]) but you can get the hash for these tools.

[1]: https://arxiv.org/pdf/1901.01337
[2]: https://hashcat.net/hashcat/

### EFS support

Masterkeys, private keys and certificates can be listed, displayed and decrypted using needed inputs (SID, password).
Certificates with private keys can be exported using the backup command.

Reinmport the backup on another machine to be able to read your encrypted file again!
Or you can use the `efs.decrypt` command to decrypt a file using the backed-up key.

More information on [Mimikatz Wiki][4] 

[4]: https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files#installing-the-pfx

### USN Journal analysis

USN journal records can be analyzed using custom rules to detect suspicious programs and actions but also to have an overview of the journal (% of file deleted, created ...)

Example of rules: [Rules/default.json](Rules/default.json)

```
  {
    "id": "ccleaner",
    "description": "CCleaner is a disk cleanup tool for temporary junk files, web history, logs and even wiping the disk.",
    "severity": "high",
    "rule": {
      "filename": "(.*)ccleaner\\.exe(-([A-F0-9]{8}).pf)?"
    }
  }
```

See an example of run here: [usn.analyze](#usn-analyze)

### Shell

There is a limited shell with few commands (exit, cd, ls, cat, pwd, cp, quit, rec).

Command `rec` shows the MFT record details.

## Help & Examples

Help command displays description and examples for each command.

Options can be entered as decimal or hex number with "0x" prefix (ex: inode).

    ntfstool help [command]
    
| Command | Description |
| --- | --- |
| [info](#info) | Display information for all disks and volumes |
| [mbr](#mbr) | Display MBR structure, code and partitions for a disk |
| [gpt](#gpt) | Display GPT structure, code  and partitions for a disk |
| [vbr](#vbr)  | Display VBR structure and code for a specidifed volume (ntfs, fat32, fat1x, bitlocker supported) |
| [extract](#extract)  | Extract a file from a volume. |
| [image](#image)  | Create an image file of a disk or volume. |
| [mft.dump](#mft-dump)  | Dump $MFT file  in specified format: csv, json, raw. |
| [mft.record](#mft-record)  | Display FILE record details for a specified MFT inode. Almost all attribute types supported |
| [mft.btree](#mft-btree)  | Display VCN content and Btree index for an inode |
| [bitlocker.info](#bitlocker-info)  | Display information and hash ($bitlocker$) for all VMK. Test a password or recovery key. |
| [bitlocker.decrypt](#bitlocker-decrypt)  | Decrypt a volume to a file using password, recovery key or bek. |
| [bitlocker.fve](#bitlocker-fve)  | Display information for the specified FVE block. |
| [efs.backup](#efs-backup)  | Export EFS keys in PKCS12 (pfx) format. |
| [efs.decrypt](#efs-decrypt)  | Decrypt EFS encrypted file using keys in PKCS12 (pfx) format. |
| [efs.certificate](#efs-certificate)  | List, display and export system certificates (SystemCertificates/My/Certificates). |
| [efs.key](#efs-key)  | List, display, decrypt and export private keys (Crypto/RSA). |
| [efs.masterkey](#efs-masterkey)  | List, display and decrypt masterkeys (Protect). |
| [reparse](#reparse)  | Parse and display reparse points from \$Extend\$Reparse. |
| [logfile.dump](#logfile-dump)  | Dump $LogFile file in specified format: csv, json, raw. |
| [usn.analyze](#usn-analyze)  | Analyze $UsnJrnl file with specified rules. Output : csv or json. |
| [usn.dump](#usn-dump)  | Dump $UsnJrnl file in specified format: csv, json, raw. |
| [shadow](#shadow)  | List volume shadow snapshots from selected disk and volume. |
| [streams](#streams)   | Display Alternate Data Streams |
| [undelete](#undelete)  | Search and extract deleted files for a volume. |
| [shell](#shell-1)   | Start a limited Unix-like shell |
| [smart](#smart)  | Display S.M.A.R.T data |


## Limitations

- Some unsupported cases. WIP.
- No documentation :no_mouth:.

Feel free to open an issue or ask for a new feature!

## Build
    
- Install [Visual Studio 2022](https://visualstudio.microsoft.com/fr/vs/)
    
- Install vcpkg (for required third-party libs) as described here: [vcpkg#getting-started](https://github.com/microsoft/vcpkg#getting-started)

	```
	git clone https://github.com/microsoft/vcpkg
	.\vcpkg\bootstrap-vcpkg.bat
	```

- Integrate it to your VisualStudio env:

	```
	vcpkg integrate install
	```

At build time, VisualStudio will detect the `vcpkg.json` file and install required packages automatically.

Current third-party libs:
- [openssl](https://www.openssl.org/): OpenSSL is an open source project that provides a robust, commercial-grade, and full-featured toolkit for the Transport Layer Security (TLS) and Secure Sockets Layer (SSL) protocols.
- [nlohmann-json](https://github.com/nlohmann/json): JSON for Modern C++
- [distorm](https://github.com/gdabah/distorm): Powerful Disassembler Library For x86/AMD64
- [cppcoro](https://github.com/lewissbaker/cppcoro): A library of C++ coroutine abstractions for the coroutines TS.


## Examples

### Info
<table>
<tr><td>info</td></tr>
<tr><td>

    +-------------------------------------------------------------------------------------+
    | Id | Model                     | Type      | Partition | Size                       |
    +-------------------------------------------------------------------------------------+
    | 0  | Samsung SSD 850 EVO 500GB | Fixed SSD | GPT       | 500107862016 (465.76 GiBs) |
    | 1  | ST2000DM001-1ER164        | Fixed HDD | GPT       | 2000398934016 (1.82 TiB)   |
    | 2  | 15EADS External           | Fixed HDD | MBR       | 1500301910016 (1.36 TiB)   |
    | 3  | osfdisk                   | Fixed HDD | MBR       | 536870912 (512.00 MiBs)    |
    +-------------------------------------------------------------------------------------+
</td></tr>
<tr><td>info disk=3</td></tr>
<tr><td>

    Model       : osfdisk
    Version     : 1
    Serial      :
    Media Type  : Fixed HDD
    Size        : 536870912 (512.00 MiBs)
    Geometry    : 512 bytes * 63 sectors * 255 tracks * 65 cylinders
    Volume      : MBR

    +--------------------------------------------------------------------------------------------------+
    | Id | Boot | Label     | Mounted | Filesystem | Offset           | Size                           |
    +--------------------------------------------------------------------------------------------------+
    | 1  | No   | NTFSDRIVE | F:\     | Bitlocker  | 0000000000000200 | 000000001ffffe00 (512.00 MiBs) |
    +--------------------------------------------------------------------------------------------------+   
</td></tr>
<tr><td>info disk=3 volume=1</td></tr>
<tr><td>

    Serial Number  : 0000aa60-00002eae
    Filesystem     : Bitlocker
    Bootable       : False
    Type           : Fixed
    Label          : NTFSDRIVE
    Offset         : 512 (512.00 bytes)
    Size           : 536870400 (512.00 MiBs)
    Free           : 519442432 (495.38 MiBs)
    Mounted        : True (F:\)
    Bitlocker      : True (Unlocked)
</td></tr>
</table>


### MBR
<table>
<tr><td>mbr disk=2</td></tr>
<tr><td>

    Disk signature  : e4589462
    Reserved bytes  : 0000
    
    Partition table :
    +---------------------------------------------------------------------------------------------------+
    | Id | Boot | Flags     | Filesystem   | First sector | Last sector | Offset | Sectors  | Size      |
    +---------------------------------------------------------------------------------------------------+
    | 1  | No   | Principal | NTFS / exFAT | 0 2 3        | 255 254 255 | 128    | 16771072 | 8.00 GiBs |
    +---------------------------------------------------------------------------------------------------+
    
    MBR signature  : 55aa
    
    Strings:
        [63] : Invalid partition table
        [7b] : Error loading operating system
        [9a] : Missing operating system
    
    Disassemble Bootstrap Code [y/N] ? y
    
        0000 : 33c0           : xor ax, ax
        0002 : 8ed0           : mov ss, ax
        0004 : bc007c         : mov sp, 0x7c00
        0007 : 8ec0           : mov es, ax
        0009 : 8ed8           : mov ds, ax
        000b : be007c         : mov si, 0x7c00
        000e : bf0006         : mov di, 0x600
        0011 : b90002         : mov cx, 0x200
	... 
</td></tr>
</table>


### GPT
<table>
<tr><td>gpt disk=1</td></tr>
<tr><td>

    Signature        : EFI PART
    Revision         : 1.0
    Header Size      : 92
    Header CRC32     : cc72e4d3
    Reserved         : 00000000
    Current LBA      : 1
    Backup LBA       : 3907029167
    First Usable LBA : 34
    Last Usable LBA  : 3907029134
    GUID             : {a21d6495-cd58-4b8d-b968-dc337adcf6ac}
    Entry LBA        : 2
    Entries Num      : 128
    Entries Size     : 128
    Partitions CRC32 : 0c9a0a25

    Partition table  : 2 entries
    +------------------------------------------------------------------------------------------------------------------------+
    | Id | Name                         | GUID                                   | First sector | Last sector | Flags        |
    +------------------------------------------------------------------------------------------------------------------------+
    | 1  | Microsoft reserved partition | {da0ac4a1-a78c-4053-bab5-36c70a71fe63} | 34           | 262177      | 000000000000 |
    | 2  | Basic data partition         | {4b4ea4b3-64a1-4c6d-bd4b-1c2b0e4e706f} | 264192       | 3907028991  | 000000000000 |
    +------------------------------------------------------------------------------------------------------------------------+
</td></tr>
</table>



### VBR
<table>
<tr><td>vbr disk=3 volume=1</td></tr>
<tr><td>

    Structure :
        Jump             : eb5890 (jmp 0x7c5a)
        OEM id           : -FVE-FS-
        BytePerSector    : 512
        SectorPerCluster : 8
        Reserved Sectors : 0
        Number of FATs   : 0
        Root Max Entries : 0
        Total Sectors    : 0
        Media Type       : f8
        SectorPerFat     : 8160
        SectorPerTrack   : 63
        Head Count       : 255
        FS Offset        : 1
        Total Sectors    : 0
        FAT Flags        : 0000
        FAT Version      : 0000
        Root Cluster     : 0
        FS Info Sector   : 1
        Backup BootSector: 6
        Reserved         : 00000000
        Reserved         : 00000000
        Reserved         : 00000000
        Drive Number     : 80
        Reserved         : 00
        Ext. Boot Sign   : 29
        Serial Number    : 00000000
        Volume Name      : NO NAME
        FileSystem Type  : FAT32
        Volume GUID      : {4967d63b-2e29-4ad8-8399-f6a339e3d001}
        FVE Block 1      : 0000000002100000
        FVE Block 2      : 00000000059e4000
        FVE Block 3      : 00000000092c8000
        End marker       : 55aa

    Strings:
        [00] : Remove disks or other media. 
        [1f] : Disk error 
        [2c] : Press any key to restart

    Disassemble Bootstrap Code [y/N] ? y

        7c5a : eb58           : jmp 0x7cb4
        7c5c : 90             : nop
        7c5d : 2d4656         : sub ax, 0x5646
        7c60 : 45             : inc bp
        7c61 : 2d4653         : sub ax, 0x5346
        7c64 : 2d0002         : sub ax, 0x200
        ...
</td></tr>
</table>


### Extract
<table>
<tr><td>extract disk=0 volume=4 inode=0 output=d:\mymft</td></tr>
<tr><td>

    [+] Opening \\?\Volume{ee732b26-571c-4516-b8fd-32282aa8e66b}\
    [-] Record Num  : 0 (00000000h)
    [-] Destination : d:\mymft
    [+] File extracted (5123541 bytes written)
</td></tr>
<tr><td>extract disk=3 volume=1 from=\bob.txt output=d:\bob.txt</td></tr>
<tr><td>

    [+] Opening \\?\Volume{00023d5d-0000-0000-0002-000000000000}\
    [-] Record Num  : 47 (0000002fh)
    [-] Destination : d:\bob.txt
    [+] File extracted (42 bytes written)
</td></tr>
<tr><td>extract disk=0 volume=4 --system output=d:\system</td></tr>
<tr><td>

    [+] Opening \\?\Volume{ee732b26-571c-4516-b8fd-32282aa8e66b}\
    [-] Record Num  : 623636 (00098414h)
    [-] Destination : d:\system
    [+] File extracted (19398656 bytes written)
</td></tr>
</table>

### Image
<table>
<tr><td>image disk=2 volume=2 output=d:\imagevol.raw</td></tr>
<tr><td>

    [+] Opening \\?\Volume{f095dd1d-f302-4d17-bf68-7cc8c1de3965}\
    [-] Size     : 33520128 (31.97 MiBs)
    [-] BlockSize: 4096
    [+] Copying  : [################################] 100% 0s
    [+] Done
</td></tr>
<tr><td>image disk=2 output=d:\image.raw</td></tr>
<tr><td>
    
    [+] Opening \\.\PhysicalDrive2
    [-] Size     : 67108864 (64.00 MiBs)
    [-] BlockSize: 4096
    [+] Copying  : [################################] 100% 0s
    [+] Done
</td></tr>
</table>


### MFT-dump
<table>
<tr><td>mft.dump disk=2 volume=2 output=d:\mft.raw</td></tr>
<tr><td>

    [+] $MFT size   : 1.00 MiB
    [-] Record size : 1024
    [-] Record count: 1024
    [+] Creating d:\mft.raw
    [+] Processing data: 1.00 MiB
    [+] Closing volume
</td></tr>
<tr><td>mft.dump disk=2 volume=2 output=d:\mft.csv format=csv</td></tr>
<tr><td>

    [+] $MFT size   : 1.00 MiB
    [-] Record size : 1024
    [-] Record count: 1024
    [+] Creating d:\mft.csv
    [+] Processing data: 1.00 MiB
    [+] Closing volume
</td></tr>
<tr><td>Sample of mft.csv (check the end of the last line for Zone.Identifier data)</td></tr>
<tr><td><pre>RecordIndex,InUse,Type,Filename,Ext,Size,Parents,Time_MFT,Time_Create,Time_Alter,Time_Read,Att_Archive,Att_Compressed,Att_Device,Att_Encrypted,Att_Hidden,Att_Normal,Att_NotIndexed,Att_Offline,Att_Readonly,Att_Reparse,Att_Sparse,Att_System,Att_Temp,USN,Hardlinks,ADS,ZoneId,ReferrerUrl,HostUrl
0,"True","File","$MFT","",1048576,"5","2022-03-17 01:25:10","2022-03-17 01:25:10","2022-03-17 01:25:10","2022-03-17 01:25:10","False","False","False","False","True","False","False","False","False","False","False","True","False",0,1,"","","",""
1,"True","File","$MFTMirr","",4096,"5","2022-03-17 01:25:10","2022-03-17 01:25:10","2022-03-17 01:25:10","2022-03-17 01:25:10","False","False","False","False","True","False","False","False","False","False","False","True","False",0,1,"","","",""
2,"True","File","$LogFile","",67108864,"5","2022-03-17 01:25:10","2022-03-17 01:25:10","2022-03-17 01:25:10","2022-03-17 01:25:10","False","False","False","False","True","False","False","False","False","False","False","True","False",0,1,"","","",""
3,"True","File","$Volume","",0,"5","2022-03-17 01:25:10","2022-03-17 01:25:10","2022-03-17 01:25:10","2022-03-17 01:25:10","False","False","False","False","True","False","False","False","False","False","False","True","False",0,1,"","","",""
...
397,"True","File","vswhere.exe",".exe",457824,"103911","2020-10-19 18:42:19","2019-06-11 10:07:50","2019-06-11 10:07:52","2021-12-27 14:54:49","True","False","False","False","False","False","False","False","False","False","False","False","False",35944347632,1,"Zone.Identifier","3","https://github.com/microsoft/vswhere/releases","https://github-production-release-asset-2e65be.s3.amazonaws.com/78482723/06868000-5585-11e9-9001-982f1fcb7ef1?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAIWNJYAX4CSVEH53A%2F20190611%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20190611T100747Z&X-Amz-Expires=300&X-Amz-Signature=bc494e9edaafb03874097ae46466c5562d34252f14f21140c70e6a1a1fc5e5c4&X-Amz-SignedHeaders=host&actor_id=40250307&response-content-disposition=attachment%3B%20filename%3Dvswhere.exe&response-content-type=application%2Foctet-stream"</pre>
</td></tr>
</table>


### MFT-record
<table>
<tr><td>mft.record disk=2 volume=1 inode=5 (root folder)</td></tr>
<tr><td>
  
    Signature         : FILE
    Update Offset     : 48
    Update Number     : 3
    $LogFile LSN      : 274035114
    Sequence Number   : 5
    Hardlink Count    : 1
    Attribute Offset  : 56
    Flags             : In_use | Directory
    Real Size         : 704
    Allocated Size    : 1024
    Base File Record  : 0
    Next Attribute ID : 56
    MFT Record Index  : 5
    Update Seq Number : 4461
    Update Seq Array  : 00000000

    Attributes:
    -----------

    +------------------------------------------------------------------------------------------------------------------+
    | Id | Type                   | Non-resident | Length | Overview                                                   |
    +------------------------------------------------------------------------------------------------------------------+
    | 1  | $STANDARD_INFORMATION  | False        | 72     | File Created Time       : 2009-12-02 02:03:31              |
    |    |                        |              |        | Last File Write Time    : 2020-02-24 19:42:23              |
    |    |                        |              |        | FileRecord Changed Time : 2020-02-24 19:42:23              |
    |    |                        |              |        | Last Access Time        : 2020-02-24 19:42:23              |
    |    |                        |              |        | Permissions             :                                  |
    |    |                        |              |        |   read_only     : 0                                        |
    |    |                        |              |        |   hidden        : 1                                        |
    |    |                        |              |        |   system        : 1                                        |
    |    |                        |              |        |   device        : 0                                        |
    |    |                        |              |        |   normal        : 0                                        |
    |    |                        |              |        |   temporary     : 0                                        |
    |    |                        |              |        |   sparse        : 0                                        |
    |    |                        |              |        |   reparse_point : 0                                        |
    |    |                        |              |        |   compressed    : 0                                        |
    |    |                        |              |        |   offline       : 0                                        |
    |    |                        |              |        |   not_indexed   : 1                                        |
    |    |                        |              |        |   encrypted     : 0                                        |
    |    |                        |              |        | Max Number of Versions  : 0                                |
    |    |                        |              |        | Version Number          : 0                                |
    +------------------------------------------------------------------------------------------------------------------+
    | 2  | $FILE_NAME             | False        | 68     | Parent Dir Record Index : 5                                |
    |    |                        |              |        | Parent Dir Sequence Num : 5                                |
    |    |                        |              |        | File Created Time       : 2009-12-02 02:03:31              |
    |    |                        |              |        | Last File Write Time    : 2011-12-24 03:13:12              |
    |    |                        |              |        | FileRecord Changed Time : 2011-12-24 03:13:12              |
    |    |                        |              |        | Last Access Time        : 1970-01-01 00:59:59              |
    |    |                        |              |        | Allocated Size          : 0                                |
    |    |                        |              |        | Real Size               : 0                                |
    |    |                        |              |        | ------                                                     |
    |    |                        |              |        | Name                    : .                                |
    +------------------------------------------------------------------------------------------------------------------+
    | 3  | $OBJECT_ID             | False        | 16     | Object Unique ID        : {cce8fec5-9a29-11df-be68-0017f29 |
    |    |                        |              |        |                           8268d}                           |
    +------------------------------------------------------------------------------------------------------------------+
    | 4  | $INDEX_ROOT            | False        | 152    | Attribute Type          : 00000030h                        |
    |    |                        |              |        | Collation Rule          : 1                                |
    |    |                        |              |        | Index Alloc Entry Size  : 4096                             |
    |    |                        |              |        | Cluster/Index Record    : 1                                |
    |    |                        |              |        | -----                                                      |
    |    |                        |              |        | First Entry Offset      : 16                               |
    |    |                        |              |        | Index Entries Size      : 136                              |
    |    |                        |              |        | Index Entries Allocated : 136                              |
    |    |                        |              |        | Flags                   : Large Index                      |
    +------------------------------------------------------------------------------------------------------------------+
    | 5  | $INDEX_ALLOCATION      | True         | 12288  | Index                                                      |
    |    |                        |              |        |        0000000000000004 : $AttrDef                         |
    |    |                        |              |        |        0000000000000008 : $BadClus                         |
    |    |                        |              |        |        0000000000000006 : $Bitmap                          |
    |    |                        |              |        |        0000000000000007 : $Boot                            |
    |    |                        |              |        |        000000000000000b : $Extend                          |
    |    |                        |              |        |        0000000000000002 : $LogFile                         |
    |    |                        |              |        |        0000000000000000 : $MFT                             |
    |    |                        |              |        |        0000000000000001 : $MFTMirr                         |
    |    |                        |              |        |        000000000000002d : $RECYCLE.BIN                     |
    |    |                        |              |        |        0000000000000009 : $Secure                          |
    |    |                        |              |        |        000000000000000a : $UpCase                          |
    |    |                        |              |        |        0000000000000003 : $Volume                          |
    |    |                        |              |        |        0000000000000005 : .                                |
    |    |                        |              |        |        000000000000240c : Dir1                             |
    |    |                        |              |        |        0000000000000218 : Dir2                             |
    |    |                        |              |        |        000000000000212a : Dir3                             |
    |    |                        |              |        |        0000000000000024 : Dir4                             |
    |    |                        |              |        |        0000000000000def : RECYCLER                         |
    |    |                        |              |        |        000000000000001b : System Volume Information        |
    |    |                        |              |        |        000000000000001b : SYSTEM~1                         |
    +------------------------------------------------------------------------------------------------------------------+
    | 6  | $BITMAP                | False        | 8      | Index Node Used         : 2                                |
    +------------------------------------------------------------------------------------------------------------------+
</td></tr>
</table>

### MFT-btree
<table>
<tr><td>mft.btree disk=0 volume=1 inode=5 (root folder)</td></tr>
<tr><td>

    Attributes:
    -----------
    
    +-------------------------------------------------------------------------------------------+
    | Id | Type              | Non-resident | Length | Overview                                 |
    +-------------------------------------------------------------------------------------------+
    | 1  | $INDEX_ROOT       | False        | 56     | Attribute Type          : Filename       |
    |    |                   |              |        | Collation Rule          : 1              |
    |    |                   |              |        | Index Alloc Entry Size  : 4096           |
    |    |                   |              |        | Cluster/Index Record    : 1              |
    |    |                   |              |        | -----                                    |
    |    |                   |              |        | First Entry Offset      : 16             |
    |    |                   |              |        | Index Entries Size      : 40             |
    |    |                   |              |        | Index Entries Allocated : 40             |
    |    |                   |              |        | Flags                   : Large Index    |
    +-------------------------------------------------------------------------------------------+
    | 2  | $INDEX_ALLOCATION | True         | 20480  | First VCN               : 0x000000000000 |
    |    |                   |              |        | Last VCN                : 0x000000000004 |
    +-------------------------------------------------------------------------------------------+
    
    $INDEX_ALLOCATION entries:
    --------------------------
    
    +--------------------------------------------------------------------------------------------+
    | VCN           | Raw address   | Size          | Entries                                    |
    +--------------------------------------------------------------------------------------------+
    | 000000000000h | 000000024000h | 000000001000h | 000000000004: $AttrDef                     |
    |               |               |               | 000000000008: $BadClus                     |
    |               |               |               | 000000000006: $Bitmap                      |
    						...
    |               |               |               | 000000000009: $Secure                      |
    |               |               |               | 00000000000a: $UpCase                      |
    |               |               |               | 000000000003: $Volume                      |
    +--------------------------------------------------------------------------------------------+
    | 000000000001h | 000000025000h | 000000001000h | 000000000098: randomfile - Copie (5).accdb |
    |               |               |               | 000000000097: randomfile - Copie (5).bat   |
    |               |               |               | 000000000095: randomfile - Copie (5).psd   |
    |               |               |               | 000000000096: randomfile - Copie (5).txt   |
    |               |               |               | 00000000009b: randomfile - Copie (6).accdb |
    						...
    |               |               |               | 000000000083: randomfile.accdb             |
    |               |               |               | 000000000082: randomfile.bat               |
    |               |               |               | 000000000084: randomfile.psd               |
    |               |               |               | 000000000081: randomfile.txt               |
    |               |               |               | 000000000024: System Volume Information    |
    +--------------------------------------------------------------------------------------------+
    | 000000000002h | 0000007d6000h | 000000001000h |                                            |
    +--------------------------------------------------------------------------------------------+
    | 000000000003h | 0000007d7000h | 000000001000h | 000000000005: .                            |
    |               |               |               | 000000000092: randomfile - Copie (4).txt   |
    +--------------------------------------------------------------------------------------------+
    | 000000000004h | 0000007d8000h | 000000001000h | 000000000027: random folder                |
    |               |               |               | 00000000008c: randomfile - Copie (2).accdb |
    |               |               |               | 00000000008b: randomfile - Copie (2).bat   |
    |               |               |               | 000000000089: randomfile - Copie (2).psd   |
    						...
    |               |               |               | 00000000008e: randomfile - Copie (3).txt   |
    |               |               |               | 000000000094: randomfile - Copie (4).accdb |
    |               |               |               | 000000000093: randomfile - Copie (4).bat   |
    |               |               |               | 000000000091: randomfile - Copie (4).psd   |
    +--------------------------------------------------------------------------------------------+
    
    B-tree index:
    -------------
    
    Root
    |- 000000000000:
    |---- VCN: 3
    	 |- 000000000005: .
    	 |---- VCN: 0
    		  |- 000000000004: $AttrDef
    		  |- 000000000008: $BadClus
    		  |- 000000000006: $Bitmap
    		  ....
    		  |- 000000000009: $Secure
    		  |- 00000000000a: $UpCase
    		  |- 000000000003: $Volume
    	 |- 000000000092: randomfile - Copie (4).txt
    	 |---- VCN: 4
    		  |- 000000000027: random folder
    		  |- 00000000008c: randomfile - Copie (2).accdb
    		  |- 00000000008b: randomfile - Copie (2).bat
    		  |- 000000000089: randomfile - Copie (2).psd
    		  ....
    		  |- 000000000094: randomfile - Copie (4).accdb
    		  |- 000000000093: randomfile - Copie (4).bat
    		  |- 000000000091: randomfile - Copie (4).psd
    	 |- 000000000000 (*)
    	 |---- VCN: 1
    		  |- 000000000098: randomfile - Copie (5).accdb
    		  |- 000000000097: randomfile - Copie (5).bat
    		  |- 000000000095: randomfile - Copie (5).psd
    		  ....
    		  |- 000000000084: randomfile.psd
    		  |- 000000000081: randomfile.txt
    		  |- 000000000024: System Volume Information
</td></tr>
</table>


### Bitlocker-Info
<table>
<tr><td>bitlocker.info disk=3 volume=1</td></tr>
<tr><td>

    FVE Version    : 2
    State          : ENCRYPTED
    Size           : 536870400 (512.00 MiBs)
    Encrypted Size : 536870400 (512.00 MiBs)
    Algorithm      : AES-XTS-128
    Timestamp      : 2020-02-26 16:39:17

    Volume Master Keys:
    -------------------

    +--------------------------------------------------------------------------------------------------------------------+
    | Id | Type              | GUID                                   | Details                                          |
    +--------------------------------------------------------------------------------------------------------------------+
    | 1  | Password          | {2dd368f3-37d7-414f-94e6-3c5b86fadd50} | Nonce         : 01d5ecbb00f7155000000003         |
    |    |                   |                                        | MAC           : daea96439babc5d1e7f20c8860ff1ee9 |
    |    |                   |                                        | Encrypted Key : b76281568419ec3bee89d1eddccf3169 |
    |    |                   |                                        |                 59c466b6b392f40f0875e58168d868d7 |
    |    |                   |                                        |                 0788bd366bec117b11a9fd6e         |
    |    |                   |                                        |                                                  |
    |    |                   |                                        | JtR Hash      : $bitlocker$1$16$daea96439babc5d1 |
    |    |                   |                                        |                 e7f20c8860ff1ee9$1048576$12$5015 |
    |    |                   |                                        |                 f700bbecd50103000000$60$175ec23c |
    |    |                   |                                        |                 d799e2bde9d24bf3697919feb7628156 |
    |    |                   |                                        |                 8419ec3bee89d1eddccf316959c466b6 |
    |    |                   |                                        |                 b392f40f0875e58168d868d70788bd36 |
    |    |                   |                                        |                 6bec117b11a9fd6e                 |
    +--------------------------------------------------------------------------------------------------------------------+
    | 2  | Recovery Password | {19b4a3e2-94b3-452f-a614-6212faeb1b9d} | Nonce         : 01d5ecbb00f7155000000006         |
    |    |                   |                                        | MAC           : b9963d29e1bad1f42e60c3bfb6e3bef5 |
    |    |                   |                                        | Encrypted Key : 97a43d40c695c6d190eba3956ac7c7b1 |
    |    |                   |                                        |                 f5fdbbc7f9a61a77c914fa347479c7ac |
    |    |                   |                                        |                 6124ff46865e805367f7bef1         |
    |    |                   |                                        |                                                  |
    |    |                   |                                        | JtR Hash      : $bitlocker$1$16$b9963d29e1bad1f4 |
    |    |                   |                                        |                 2e60c3bfb6e3bef5$1048576$12$5015 |
    |    |                   |                                        |                 f700bbecd50106000000$60$3a06a06f |
    |    |                   |                                        |                 db044d850ecd6faf5cf2aec997a43d40 |
    |    |                   |                                        |                 c695c6d190eba3956ac7c7b1f5fdbbc7 |
    |    |                   |                                        |                 f9a61a77c914fa347479c7ac6124ff46 |
    |    |                   |                                        |                 865e805367f7bef1                 |
    +--------------------------------------------------------------------------------------------------------------------+
</td></tr>
<tr><td>bitlocker.info disk=3 volume=1 password=badpassword</td></tr>
<tr><td>

    FVE Version    : 2
    State          : ENCRYPTED
    Size           : 536870400 (512.00 MiBs)
    Encrypted Size : 536870400 (512.00 MiBs)
    Algorithm      : AES-XTS-128
    Timestamp      : 2020-02-26 16:39:17

    Tested Password:
    ----------------

    +--------------------------------------------------------------------------------+
    | Id | Type     | GUID                                   | Password    | Result  |
    +--------------------------------------------------------------------------------+
    | 1  | Password | {2dd368f3-37d7-414f-94e6-3c5b86fadd50} | badpassword | Invalid |
    +--------------------------------------------------------------------------------+
</td></tr>
<tr><td>bitlocker.info disk=3 volume=1 password=123456789</td></tr>
<tr><td>

    FVE Version    : 2
    State          : ENCRYPTED
    Size           : 536870400 (512.00 MiBs)
    Encrypted Size : 536870400 (512.00 MiBs)
    Algorithm      : AES-XTS-128
    Timestamp      : 2020-02-26 16:39:17

    Tested Password:
    ----------------

    +--------------------------------------------------------------------------------------------------------------+
    | Id | Type     | GUID                                   | Password  | Result                                  |
    +--------------------------------------------------------------------------------------------------------------+
    | 1  | Password | {2dd368f3-37d7-414f-94e6-3c5b86fadd50} | 123456789 | Valid                                   |
    |    |          |                                        |           |                                         |
    |    |          |                                        |           | VMK  : 751bf363db63ba6f1b36fb2ecd5ff1d8 |
    |    |          |                                        |           |        f5eab77e8754a848f2743978c7615f9f |
    |    |          |                                        |           | FVEK : 35b8197e6d74d8521f49698d5f556589 |
    |    |          |                                        |           |        2cf286ae5323c65631965c905a9d7da4 |
    +--------------------------------------------------------------------------------------------------------------+
</td></tr>
</table>


### Bitlocker-Decrypt
<table>
<tr><td>bitlocker.decrypt disk=3 volume=1 output=decrypted.img fvek=35b8197e6d74d8521f49698d5f5565892cf286ae5323c65631965c905a9d7da4</td></tr>
<tr><td>
  
    [+] Opening \\?\Volume{09a02598-0000-0000-0002-000000000000}\
    [+] Reading Bitlocker VBR
    [-]   Volume State   : ENCRYPTED
    [-]   Size           : 536870400 (512.00 MiBs)
    [-]   Encrypted Size : 536870400 (512.00 MiBs)
    [-]   Algorithm      : AES-XTS-128
    [+] Decrypting sectors
    [-]   Processed data size : 512.00 MiBs (100%)
    [+] Duration : 7535ms
    [+] Closing Volume
</td></tr>
</table>

### Bitlocker-FVE
<table>
<tr><td>bitlocker.fve disk=3 volume=1 fve_block=2</td></tr>
<tr><td>
  
    Signature             : -FVE-FS-
    Size                  : 57
    Version               : 2
    Current State         : ENCRYPTED (4)
    Next State            : ENCRYPTED (4)
    Encrypted Size        : 536870400 (512.00 MiBs)
    Convert Size          : 0
    Backup Sectors        : 16
    FVE Block 1           : 0000000002100000
    FVE Block 2           : 00000000059e4000
    FVE Block 3           : 00000000092c8000
    Backup Sectors Offset : 0000000002110000

    FVE Metadata Header
    -------------------

    Size                  : 840
    Version               : 1
    Header Size           : 48
    Copy Size             : 840
    Volume GUID           : {70a57ea3-9b98-4034-8b6a-645f731e2d1e}
    Next Counter          : 10
    Algorithm             : AES-XTS-128 (8004)
    Timestamp             : 2020-02-26 16:39:17

    FVE Metadata Entries (5)
    ------------------------

    +----------------------------------------------------------------------------------------------------------------+
    | Id | Version | Size | Entry Type          | Value Type      | Value                                            |
    +----------------------------------------------------------------------------------------------------------------+
    | 1  | 1       | 72   | Drive Label         | Unicode         | String        : TWN NTFSDRIVE 26/02/2020         |
    +----------------------------------------------------------------------------------------------------------------+
    | 2  | 1       | 224  | VMK                 | VMK             | Key ID        : {2dd368f3-37d7-414f-94e6-3c5b86f |
    |    |         |      |                     |                 |                 add50}                           |
    |    |         |      |                     |                 | Last Change   : 2020-02-26 16:40:00              |
    |    |         |      |                     |                 | Protection    : Password                         |
    |    |         |      |                     |                 |                                                  |
    |    |         |      |                     |                 | Property #1 - Stretch Key - 108                  |
    |    |         |      |                     |                 | --------                                         |
    |    |         |      |                     |                 | Encryption    : STRETCH KEY                      |
    |    |         |      |                     |                 | MAC           : daea96439babc5d1e7f20c8860ff1ee9 |
    |    |         |      |                     |                 |                                                  |
    |    |         |      |                     |                 | Property #1.1 - AES-CCM - 80                     |
    |    |         |      |                     |                 | --------                                         |
    |    |         |      |                     |                 | Nonce as Hex  : 01d5ecbb00f71550                 |
    |    |         |      |                     |                 | Nonce as Time : 2020-02-26 16:39:59              |
    |    |         |      |                     |                 | Nonce Counter : 00000002                         |
    |    |         |      |                     |                 | MAC           : 1dfebdc79a966e72ca806d6a83d8c7ba |
    |    |         |      |                     |                 | Key           : eb51a188df981b54f51698c76d76a8bb |
    |    |         |      |                     |                 |                 d22afbbe27603ea6afc34c077726262e |
    |    |         |      |                     |                 |                 5ba07482053d3c36fdecf80f         |
    |    |         |      |                     |                 |                                                  |
    |    |         |      |                     |                 | Property #2 - AES-CCM - 80                       |
    |    |         |      |                     |                 | --------                                         |
    |    |         |      |                     |                 | Nonce as Hex  : 01d5ecbb00f71550                 |
    |    |         |      |                     |                 | Nonce as Time : 2020-02-26 16:39:59              |
    |    |         |      |                     |                 | Nonce Counter : 00000003                         |
    |    |         |      |                     |                 | MAC           : 175ec23cd799e2bde9d24bf3697919fe |
    |    |         |      |                     |                 | Key           : b76281568419ec3bee89d1eddccf3169 |
    |    |         |      |                     |                 |                 59c466b6b392f40f0875e58168d868d7 |
    |    |         |      |                     |                 |                 0788bd366bec117b11a9fd6e         |
    +----------------------------------------------------------------------------------------------------------------+
    | 3  | 1       | 316  | VMK                 | VMK             | Key ID        : {19b4a3e2-94b3-452f-a614-6212fae |
    |    |         |      |                     |                 |                 b1b9d}                           |
    |    |         |      |                     |                 | Last Change   : 2020-02-26 16:40:07              |
    |    |         |      |                     |                 | Protection    : Recovery Password                |
    |    |         |      |                     |                 |                                                  |
    |    |         |      |                     |                 | Property #1 - Stretch Key - 172                  |
    |    |         |      |                     |                 | --------                                         |
    |    |         |      |                     |                 | Encryption    : STRETCH KEY                      |
    |    |         |      |                     |                 | MAC           : b9963d29e1bad1f42e60c3bfb6e3bef5 |
    |    |         |      |                     |                 |                                                  |
    |    |         |      |                     |                 | Property #1.1 - AES-CCM - 64                     |
    |    |         |      |                     |                 | --------                                         |
    |    |         |      |                     |                 | Nonce as Hex  : 01d5ecbb00f71550                 |
    |    |         |      |                     |                 | Nonce as Time : 2020-02-26 16:39:59              |
    |    |         |      |                     |                 | Nonce Counter : 00000004                         |
    |    |         |      |                     |                 | MAC           : 8064d679c7d8d1fa8ae548b0844882c7 |
    |    |         |      |                     |                 | Key           : 18d21021d40e3dc99d38c8dd84faed10 |
    |    |         |      |                     |                 |                 370c32095f4f63261ad8ec40         |
    |    |         |      |                     |                 |                                                  |
    |    |         |      |                     |                 | Property #1.2 - AES-CCM - 80                     |
    |    |         |      |                     |                 | --------                                         |
    |    |         |      |                     |                 | Nonce as Hex  : 01d5ecbb00f71550                 |
    |    |         |      |                     |                 | Nonce as Time : 2020-02-26 16:39:59              |
    |    |         |      |                     |                 | Nonce Counter : 00000005                         |
    |    |         |      |                     |                 | MAC           : 3d40f2b5fc0091b894b438763fcdf4cd |
    |    |         |      |                     |                 | Key           : a0af0aeda32d977d26ac76f9fc429668 |
    |    |         |      |                     |                 |                 955d2a6a49fe4e2323751924e47e6c39 |
    |    |         |      |                     |                 |                 8c22f7fcd2d4272003cb7a4e         |
    |    |         |      |                     |                 |                                                  |
    |    |         |      |                     |                 | Property #2 - AES-CCM - 80                       |
    |    |         |      |                     |                 | --------                                         |
    |    |         |      |                     |                 | Nonce as Hex  : 01d5ecbb00f71550                 |
    |    |         |      |                     |                 | Nonce as Time : 2020-02-26 16:39:59              |
    |    |         |      |                     |                 | Nonce Counter : 00000006                         |
    |    |         |      |                     |                 | MAC           : 3a06a06fdb044d850ecd6faf5cf2aec9 |
    |    |         |      |                     |                 | Key           : 97a43d40c695c6d190eba3956ac7c7b1 |
    |    |         |      |                     |                 |                 f5fdbbc7f9a61a77c914fa347479c7ac |
    |    |         |      |                     |                 |                 6124ff46865e805367f7bef1         |
    |    |         |      |                     |                 |                                                  |
    |    |         |      |                     |                 | Property #3 - Unknown (00000015)                 |
    |    |         |      |                     |                 |  - 28                                            |
    |    |         |      |                     |                 | --------                                         |
    |    |         |      |                     |                 | Unknown Value Type (21)                          |
    +----------------------------------------------------------------------------------------------------------------+
    | 4  | 1       | 80   | FKEV                | AES-CCM         | Nonce as Hex  : 01d5ecbb00f71550                 |
    |    |         |      |                     |                 | Nonce as Time : 2020-02-26 16:39:59              |
    |    |         |      |                     |                 | Nonce Counter : 00000008                         |
    |    |         |      |                     |                 | MAC           : 2ff7d7f79920e3509fb8d20cb15b62c8 |
    |    |         |      |                     |                 | Key           : 097169b9a5c41420ed2353a4a4210763 |
    |    |         |      |                     |                 |                 a8833d1a4a88c6f7c0c45ec7c0959f25 |
    |    |         |      |                     |                 |                 2c8eac3f306e9fd1e693784a         |
    +----------------------------------------------------------------------------------------------------------------+
    | 5  | 1       | 100  | Volume Header Block | Offset and Size | Offset        : 0000000002110000                 |
    |    |         |      |                     |                 | Size          : 0000000000002000                 |
    +----------------------------------------------------------------------------------------------------------------+
</td></tr>
</table>


### EFS-backup
<table>
<tr><td>efs.backup disk=0 volume=4 password=123456</td></tr>
<tr><td>
    
    [+] Opening \\?\Volume{ee732b26-571c-4516-b8fd-32282aa8e66b}\
    [+] Listing user directories
        8 directories found
    [+] Searching for certificates
        - 8BB98DE9ED4DBDD09AA1FF467ED71F0F28ACF61B
    [+] Finding corresponding private keys
        - 5f2870d8a6f1ef6487be2e1aee746fb5_bbc401c6-854a-4d12-9b65-8d52ca66cb6a
    [+] Finding corresponding masterkeys
        - 9ac19509-54d3-48bc-8c67-4cfb01d73498
    [+] Exporting 1 certificates and keys (pass: backup)
        - ef456e5b-43e4-4eda-a80b-e234611306d4 : Ok
          Exported to 8BB98DE9ED4DBDD09AA1FF467ED71F0F28ACF61B.pfx
</td></tr>
</table>


### EFS-decrypt
<table>
<tr><td>efs.decrypt efs.decrypt disk=0 volume=4 from=c:\cat.png pfx=z:\my_backup.pfx password=backup output=c:\socute.png</td></tr>
<tr><td>

    [+] Loading PKCS12 input file
    [-] KeyID : 86598de9ed5dbdd00aa2ff467ed71f1f28acf61b
    [-] Reading record: 13525
    [+] Parsing $EFS streams
    [-] 1 data decryption field(s) found
    [+] Decrypting FEK
    [-] FEK
        +----------------------------------------------------------------------------------+
        | Property      | Value                                                            |
        +----------------------------------------------------------------------------------+
        | Entropy       | 32                                                               |
        | Algorithm     | CALG_AES_256                                                     |
        | Key (256bits) | 5BBBB8A7F9DD9B9FFFDE9E62370254979F32A9CFFDDB74212A0C1AEECCD75B4A |
        +----------------------------------------------------------------------------------+
    [+] Decrypting file
    [-] Decrypted file written to c:\socute.png (1.94 MiB)
</td></tr>
</table>

### EFS-certificate
<table>
<tr><td>efs.certificate disk=0 volume=4</td></tr>
<tr><td>

    [+] Opening \\?\Volume{ee732b26-571c-4516-b8fd-32282aa8e66b}\
    [+] Listing user directories
        8 directories found
    [+] Searching for certificates
        8 certificate(s) found
    [+] Certificates
        +-----------------------------------------------------------------------------------------------------------------------------------+
        | Id | User  | File                                                | Certificate                                                    |
        +-----------------------------------------------------------------------------------------------------------------------------------+
        |  0 | Bobby | Name     : 02728B6DF5573C5955A4DFF22319441C889C367B | Friendly Name : APNS certificate Direct                        |
        |    |       | Record   : 00000001d2d5h                            |                                                                |
        |    |       | Size     : 850.00 bytes                             |                                                                |
        |    |       |                                                     |                                                                |
        |    |       | Creation : 2019-05-11 15:59:29                      |                                                                |
        +-----------------------------------------------------------------------------------------------------------------------------------+
        |  1 | Bobby | Name     : 14BB7663C51C77FF5CAD89B4DC34495864338C67 | Friendly Name : APNS certificate                               |
        |    |       | Record   : 00000000b5a4h                            |                                                                |
        |    |       | Size     : 824.00 bytes                             |                                                                |
        |    |       |                                                     |                                                                |
        |    |       | Creation : 2021-03-03 18:02:33                      |                                                                |
        +-----------------------------------------------------------------------------------------------------------------------------------+
        |  2 | Bobby | Name     : 564481148D4DBDD09AA1FF467ED71F0F28ACF61B | Container     : ef456e5b-36e4-4eda-a80b-e234611306d4           |
        |    |       | Record   : 00000000ab23h                            | Provider      : Microsoft Enhanced Cryptographic Provider v1.0 |
        |    |       | Size     : 1.15 KiB                                 | Type          : PROV_RSA_FULL                                  |
        |    |       |                                                     | KeySpec       : AT_KEYEXCHANGE                                 |
        |    |       | Creation : 2020-08-17 13:20:03                      |                                                                |
        +-----------------------------------------------------------------------------------------------------------------------------------+
                                                                ..........
</td></tr>
<tr><td>efs.certificate disk=0 volume=4 inode=0xb5a4</td></tr>
<tr><td>
	
    [+] Opening \\?\Volume{ee732b26-571c-4516-b8fd-32282aa8e66b}\
    [+] Reading certificate file record: 46500
    [+] Certificate
        +--------------------------------------------------------------------------------------------------------------------------+
        | Id | Property                            | Value                                                                         |
        +--------------------------------------------------------------------------------------------------------------------------+
        |  0 | File                                | Creation : 2021-03-03 18:02:33                                                |
        |    |                                     | Size     : 824.00 bytes                                                       |
        +--------------------------------------------------------------------------------------------------------------------------+
        |  1 | SHA1_HASH_PROP_ID                   | 14A67663C51C66FF5CAD89B4DC34495864338C67                                      |
        +--------------------------------------------------------------------------------------------------------------------------+
        |  2 | FRIENDLY_NAME_PROP_ID               | APNS certificate                                                              |
        +--------------------------------------------------------------------------------------------------------------------------+
        |  3 | KEY_IDENTIFIER_PROP_ID              | 82B87AE4F2251242252A2644D98169F34F909CA8                                      |
        +--------------------------------------------------------------------------------------------------------------------------+
        |  4 | SUBJECT_PUBLIC_KEY_MD5_HASH_PROP_ID | DB532C4794A15E5D0392C7C605FCBCA8                                              |
        +--------------------------------------------------------------------------------------------------------------------------+
        |  5 | CERTIFICATE_FILE                    | Data:                                                                         |
        |    |                                     |     Version: 3 (0x2)                                                          |
        |    |                                     |     Serial Number:                                                            |
        |    |                                     |         01:20:cb:ab:28:8a:97:ee:99:cc                                         |
        |    |                                     |     Signature Algorithm: sha1WithRSAEncryption                                |
        |    |                                     |     Issuer: C=US, O=Apple Inc., OU=Apple iPhone, CN=Apple iPhone Device CA    |
        |    |                                     |     Validity                                                                  |
        |    |                                     |         Not Before: Mar  3 15:57:33 2021 GMT                                  |
        |    |                                     |         Not After : Mar  3 16:02:33 2022 GMT                                  |
        |    |                                     |     Subject: CN=1A6032AA-91A2-4B1D-B6AF-5509FC173686                          |
        |    |                                     |     Subject Public Key Info:                                                  |
        |    |                                     |         Public Key Algorithm: rsaEncryption                                   |
        |    |                                     |             RSA Public-Key: (1024 bit)                                        |
        |    |                                     |             Modulus:                                                          |
        |    |                                     |                 00:a2:75:db:69:8d:c9:b3:fd:96:4d:28:b9:43:94:                 |
        |    |                                     |                 db:7d:73:53:88:c9:79:e9:fa:de:e4:12:14:2c:de:                 |
                                                          ...
        |    |                                     |                 a7:6b:d0:01:9e:dc:66:27:ef:2e:20:7e:e5:2a:42:                 |
        |    |                                     |                 9e:6f:85:9c:b6:8f:be:d3:05                                    |
        |    |                                     |             Exponent: 65537 (0x10001)                                         |
        |    |                                     |     X509v3 extensions:                                                        |
        |    |                                     |         X509v3 Authority Key Identifier:                                      |
        |    |                                     |             keyid:B2:FE:21:23:44:86:95:6A:79:D5:81:26:8E:73:10:D8:A7:4C:8E:74 |
        |    |                                     |         X509v3 Subject Key Identifier:                                        |
        |    |                                     |             82:B8:7A:E4:F2:25:12:42:25:2A:26:44:D9:81:69:F3:4F:90:9C:A8       |
        |    |                                     |         X509v3 Basic Constraints: critical                                    |
        |    |                                     |             CA:FALSE                                                          |
        |    |                                     |         X509v3 Key Usage: critical                                            |
        |    |                                     |             Digital Signature, Key Encipherment                               |
        |    |                                     |         X509v3 Extended Key Usage: critical                                   |
        |    |                                     |             TLS Web Server Authentication, TLS Web Client Authentication      |
        |    |                                     |         1.2.840.113635.100.6.10.6:                                            |
        |    |                                     |             ..                                                                |
        |    |                                     | Signature Algorithm: sha1WithRSAEncryption                                    |
        |    |                                     |      28:54:6c:d9:4e:97:f5:dd:1f:79:4a:6a:74:42:ad:6e:a1:11:                   |
                                                     ...
        |    |                                     |      27:58:3b:d5:1e:c3:71:af:6b:bd:fe:5d:ad:4d:bd:82:fa:53:                   |
        |    |                                     |      ff:0c                                                                    |
        +--------------------------------------------------------------------------------------------------------------------------+
</td></tr>
<tr><td>efs.certificate disk=0 volume=4 inode=0xb5a4 output=mycert</td></tr>
<tr><td>
    
    [+] Opening \\?\Volume{ee732b26-571c-4516-b8fd-32282aa8e66b}\
    [+] Reading certificate file record: 46500
    [+] Certificate exported to mycert.pem
</td></tr>
</table>

### EFS-key
<table>
<tr><td>efs.key disk=0 volume=4</td></tr>
<tr><td>
	
	[+] Opening \\?\Volume{ee732b26-571c-4516-b8fd-32282aa8e66b}
	[+] Listing user directories: 
	    8 directories found
	[+] Searching for keys
	    9713 key(s) found
	[+] Keys
	+------------------------------------------------------------------------------------------------------------------+
	| Id | User  | Keyfile                              | Name                                   | Creation Date       |
	+------------------------------------------------------------------------------------------------------------------+
	|  0 | User1 | Name   : 0004f7ed30db...017ee8d52ca6 | {15676EB3-D258-410F-85CB-9AB29E642CB3} | 2021-05-19 14:10:15 |
	|    |       | Record : 0000000246c5h               |                                        |                     |
	|    |       | Size   : 4.00 KiBs                   |                                        |                     |
	+------------------------------------------------------------------------------------------------------------------+
	|  1 | User1 | Name   : 0016875547ba...f7a9606b4177 | {BA4B66DC-8C1D-4FDF-A1EF-78B64411D1AD} | 2020-02-03 19:37:39 |
	|    |       | Record : 000000019f19h               |                                        |                     |
	|    |       | Size   : 4.00 KiBs                   |                                        |                     |
	+------------------------------------------------------------------------------------------------------------------+
	|  2 | User1 | Name   : 002a02ec680e...9a0a8d52ca67 | {3A3E1CF2-5AC2-4717-8006-D7C0F2936435} | 2019-06-26 15:50:50 |
                                                           ..........
</td></tr>
<tr><td>efs.key disk=0 volume=4 inode=742107</td></tr>
<tr><td>

	[+] Opening \\?\Volume{ee732b26-571c-4516-b8fd-32282aa8e66b}\
	[+] Reading key file record: 742107
	[+] Key
	+------------------------------------------------------------------------------------------------------------------+
	| Id | Property             | Value                                                                                |
	+------------------------------------------------------------------------------------------------------------------+
	|  0 | File                 | Creation : 2021-09-23 22:16:43                                                       |
	|    |                      | Size     : 4.00 KiBs                                                                 |
	+------------------------------------------------------------------------------------------------------------------+
	|  1 | Version              | 0                                                                                    |
	+------------------------------------------------------------------------------------------------------------------+
	|  2 | Name                 | ef456e5b-43e4-4eda-a80b-e234611306d4                                                 |
	+------------------------------------------------------------------------------------------------------------------+
	|  3 | Flags                | 00000000h                                                                            |
	+------------------------------------------------------------------------------------------------------------------+
	|  4 | PublicKey            | Magic       : 31415352h (RSA1)                                                       |
	|    |                      | Size        : 2048                                                                   |
	|    |                      | Exponent    : 65537                                                                  |
	|    |                      |                                                                                      |
	|    |                      | Permissions : CRYPT_ENCRYPT                                                          |
	|    |                      |               CRYPT_DECRYPT                                                          |
	|    |                      |               CRYPT_EXPORT                                                           |
	|    |                      |               CRYPT_READ                                                             |
                                                            ...
	|    |                      |                                                                                      |
	|    |                      | Modulus     : 96883F07FF78DA8354D037A94F897BD7                                       |
							    ...
	|    |                      |               FA77A3D04DD10D044761E65355B335B5                                       |
	+------------------------------------------------------------------------------------------------------------------+
	|  5 | Encrypted PrivateKey | Version           : 1                                                                |
	|    |                      | Provider GUID     : {df9d8cd0-1501-11d1-8c7a-00c04fc297eb}                           |
	|    |                      | MasterKey Version : 1                                                                |
	|    |                      | MasterKey GUID    : {9ac19509-54d3-48bc-8c67-4cfb01d73498}                           |
	|    |                      |                                                                                      |
	|    |                      | Description       : Clé privée CryptoAPI                                             |
	|    |                      | Flags             : 00000000h                                                        |
	|    |                      |                                                                                      |
	|    |                      | Encryption Alg    : CALG_AES_256                                                     |
	|    |                      | Hash Alg          : CALG_SHA_512                                                     |
	|    |                      |                                                                                      |
	|    |                      | Salt              : ABABD5324CCE0254BC726C3BF5A777D38BC4D75CACC2360EF3276EB4DC42FF6A |
	|    |                      |                                                                                      |
	|    |                      | HMAC              : -                                                                |
	|    |                      | HMAC2             : D24F0B0AF684AE986F1328EAAFC01DA346D2BADE2B84CBE3C94CCB338D449EA6 |
	|    |                      |                                                                                      |
	|    |                      | Encrypted Data    : D7DAD9229C91DBC9608852A4411527D7                                 |
	|    |                      |                     58DB27E19596DD118F2D70F68CC7913C                                 |
							    ...
	|    |                      |                     7870F6C68DA1B9139BF6E39725F4E72E                                 |
	|    |                      |                     4EC435C947F127CA3E333CB5E2F43978                                 |
	|    |                      |                                                                                      |
	|    |                      | Signature Data    : 6077C027E6714A81C2710C5D334758F9AD463117DA4CBA8D0D05B5845A662E8F |
	|    |                      |                     5E38DCCAB05DA5DD6C8328F5CF925F378F229790D30A2BCC91D5E3370AE50FED |
	+------------------------------------------------------------------------------------------------------------------+
	|  6 | Hash                 | 0000000000000000000000000000000000000000                                             |
	+------------------------------------------------------------------------------------------------------------------+
	|  7 | ExportFlag           | Version           : 1                                                                |
	|    |                      | Provider GUID     : {df9d8cd0-1501-11d1-8c7a-00c04fc297eb}                           |
	|    |                      | MasterKey Version : 1                                                                |
	|    |                      | MasterKey GUID    : {9ac19509-54d3-48bc-8c67-4cfb01d73498}                           |
	|    |                      |                                                                                      |
	|    |                      | Description       : Export Flag                                                      |
	|    |                      | Flags             : 00000000h                                                        |
	|    |                      |                                                                                      |
	|    |                      | Encryption Alg    : CALG_AES_256                                                     |
	|    |                      | Hash Alg          : CALG_SHA_512                                                     |
	|    |                      |                                                                                      |
	|    |                      | Salt              : 772935C3582F625367716CE87D9626A524F15B9B7FF07166BB2C704B1223CB06 |
	|    |                      |                                                                                      |
	|    |                      | HMAC              : -                                                                |
	|    |                      | HMAC2             : 3BCA74ED2C83767F06D9FF907817FE85FBA65FDB72A94E9D8F2C7CF1D8E7DCA2 |
	|    |                      |                                                                                      |
	|    |                      | Encrypted Data    : 875A6429226F11DFD3690D43BE633287                                 |
	|    |                      |                                                                                      |
	|    |                      | Signature Data    : FD97F69A214C37D0DA968B5AA18EE7C80D475F72F650C8DCAE887C97E850DCD6 |
	|    |                      |                     9FA17D397A2375E362DE6F17193E3D084C06B0DCDB38E6C746150C1056145178 |
	+------------------------------------------------------------------------------------------------------------------+
</td></tr>
<tr><td> efs.key disk=0 volume=4 inode=742107 masterkey=34fac126105ce30...178c5bff4979eb</td></tr>
<tr><td>
	
    [+] Opening \\?\Volume{ee732b26-571c-4516-b8fd-32282aa8e66b}\
    [+] Reading key file record: 742107
    [-] Key
	    Encryption Algorithm : CALG_AES_256
	    Hash Algorithm       : CALG_SHA_512
	    Salt                 : ABABD5324CCE0254BC726C33F5A777D38BC4D75CACC2360EF3276EB4DC42FF6A
    [+] Decrypting key
    [+] Key successfully decrypted
    [+] Export flags         : 00000001 (ALLOW_EXPORT_FLAG)
    [+] Clear key (2048bits) :
	    +----------------------------------------------------------+
	    | Id | Property         | Value                            |
	    +----------------------------------------------------------+
	    |  0 | Magic            | RSA2                             |
	    +----------------------------------------------------------+
	    |  1 | Bitsize          | 2048                             |
	    +----------------------------------------------------------+
	    |  2 | Exponent         | 65537                            |
	    +----------------------------------------------------------+
	    |  3 | Modulus          | 96883F07FF78DA8354D037A94F897BD7 |
                                      ...
	    |    |                  | FA77A3D04DD10D044761E65355B335B5 |
	    +----------------------------------------------------------+
	    |  4 | Prime1           | C02F585644ED6326FF82368B0AD9ECD4 |
                                      ...
	    |    |                  | 65F7DE6D173FEBEF95BE491FB222E07B |
	    +----------------------------------------------------------+
	    |  5 | Prime2           | C884376BBC50C2A14C495894FBF980DE |
                                      ...
	    |    |                  | 6759E812B6385B9151EBED8DCD65238F |
	    +----------------------------------------------------------+
	    |  6 | Exponent1        | 0E33B17876918051427271EB667AE238 |
                                      ...
	    |    |                  | 69349EF83ACE9B75D20004D155CDA3FF |
	    +----------------------------------------------------------+
	    |  7 | Exponent2        | 5BF265077E1EFA60C47E8DA423B751A4 |
                                      ...
	    |    |                  | E7008F2EA5684A74E4BFEEFAAB48C979 |
	    +----------------------------------------------------------+
	    |  8 | Coefficient      | 7D68AA3844F096959C23BD59E4BE3147 |
                                      ...
	    |    |                  | 592ABC1BEDEBA6F5B4BDE3D0F9BEF7C5 |
	    +----------------------------------------------------------+
	    |  9 | Private Exponent | 2462A061AD85A7C3B0DF7764CC5DDDFA |
	    |    |                  | 40D83B3FBF0D9D016C419E6B6744AD73 |
                                      ...
	    |    |                  | 47685BDEB0FABDC21AF5CABBA13D138D |
	    |    |                  | F39FC063F1F20323E3220229E29FA42D |
	    +----------------------------------------------------------+
</td></tr>
<tr><td> efs.key disk=0 volume=4 inode=742107 masterkey=34...eb output=mykey</td></tr>
<tr><td>
	
    [+] Opening \\?\Volume{ee732b26-571c-4516-b8fd-32282aa8e66b}\
    [+] Reading key file record: 742107
    [-] Key
        Encryption Algorithm : CALG_AES_256
        Hash Algorithm       : CALG_SHA_512
        Salt                 : ABABD5324CCE0254BC726C33F5A777D38BC4D75CACC2360EF3276EB4DC42FF6A
    [+] Decrypting key
    [+] Key successfully decrypted
    [+] Public key exported to mykey.pub.pem.	    
    [+] Private key exported to mykey.priv.pem.	    
</td></tr>
</table>

### EFS-masterkey
<table>
<tr><td>efs.masterkey disk=0 volume=4</td></tr>
<tr><td>
	
    [+] Opening \\?\Volume{ee732b26-571c-4516-b8fd-32282aa8e66b}\
    [+] Listing user directories
        8 directories found
    [+] Searching for keys
        19 key(s), 2 preferred file(s) found
    [+] MasterKeys
        +--------------------------------------------------------------------------------------------------------------------------------------------------+
        | Id | User           | Keyfile                                       | Key(s)                                               | Creation Date       |
        +--------------------------------------------------------------------------------------------------------------------------------------------------+
        |  0 | DefaultAppPool | Name   : e4ed144f-6522-4471-8893-a6e29e175ba6 | MasterKey                                            | 2021-08-17 14:54:41 |
        |    |                | Record : 000000031848h                        |     Version : 2                                      |                     |
        |    |                | Size   : 468.00 bytes                         |     Algo    : CALG_SHA_512 - CALG_AES_256            |                     |
        |    |                |                                               |     Salt    : FA737C82899CC3F61A3B332B15FDC241       |                     |
        |    |                |                                               |     Rounds  : 8000                                   |                     |
        |    |                |                                               | BackupKey                                            |                     |
        |    |                |                                               |     Version : 2                                      |                     |
        |    |                |                                               |     Algo    : CALG_SHA_512 - CALG_AES_256            |                     |
        |    |                |                                               |     Salt    : DF0651C903763132BC3043BF144A7DDD       |                     |
        |    |                |                                               |     Rounds  : 8000                                   |                     |
        |    |                |                                               | CredHist                                             |                     |
        |    |                |                                               |     Version : 3                                      |                     |
        |    |                |                                               |     GUID    : {00000000-0000-0000-0000-000000000000} |                     |
        +--------------------------------------------------------------------------------------------------------------------------------------------------+
        |  1 | DefaultAppPool | Name   : Preferred                            | Preferred                                            | 2021-08-17 14:54:41 |
        |    |                | Record : 00000003184ah                        |     GUID    : {e4ed144f-6522-4471-8893-a6e29e175ba6} |                     |
        |    |                | Size   : 24.00 bytes                          |     Renew   : 2021-11-15 12:54:41                    |                     |
        +--------------------------------------------------------------------------------------------------------------------------------------------------+
        |  2 | Bob            | Name   : 26bd8b3d-e87f-4df3-a1af-18f434788090 | MasterKey                                            | 2021-03-05 01:16:42 |
        |    |                | Record : 000000004f4ah                        |     Version : 2                                      |                     |
        |    |                | Size   : 468.00 bytes                         |     Algo    : CALG_SHA_512 - CALG_AES_256            |                     |
        |    |                |                                               |     Salt    : 39B575D1816DE8224B9E11C38E35EB34       |                     |
        |    |                |                                               |     Rounds  : 8000                                   |                     |
        |    |                |                                               | BackupKey                                            |                     |
                                                                ..........
</td></tr>
<tr><td>efs.masterkey disk=0 volume=4 inode=0x80544</td></tr>
<tr><td>
	
    [+] Opening \\?\Volume{ee732b26-571c-4516-b8fd-32282aa8e66b}\
    [+] Reading masterkey file record: 525636
    [+] MasterKey
        +--------------------------------------------------------------------+
        | Id | Property  | Value                                             |
        +--------------------------------------------------------------------+
        |  0 | File      | Creation : 2020-07-06 05:56:06                    |
        |    |           | Size     : 468.00 bytes                           |
        +--------------------------------------------------------------------+
        |  1 | Version   | 2                                                 |
        +--------------------------------------------------------------------+
        |  2 | GUID      | 9ac19509-54d3-48bc-8c67-4cfb01d73498              |
        +--------------------------------------------------------------------+
        |  3 | Policy    | 00000005h                                         |
        +--------------------------------------------------------------------+
        |  4 | MasterKey | Version  : 2                                      |
        |    |           | Salt     : 3ED4CDBCC4073D6724A512061D0597E1       |
        |    |           | Rounds   : 8000                                   |
        |    |           | Hash Alg : CALG_SHA_512                           |
        |    |           | Enc Alg  : CALG_AES_256                           |
        |    |           | Enc Key  : 3610946FE1A7B9099D0AFA7658325014       |
        |    |           |            296D1F0E5BA93249858BE3ACCC8FD7A8       |
        |    |           |            F62DB6808833FC303095C6588BDE3826       |
        |    |           |            80ABF391222CD77661BCCB637DDAC490       |
        |    |           |            B5FC02C854EF45490EE10851EF524DE2       |
        |    |           |            85DD508F905216D528D3DC3336830FF9       |
        |    |           |            690472730A03D64CF892E06B9AA35692       |
        |    |           |            AB7679E908D487119030B73CB87E6F9F       |
        |    |           |            731F65609CB8ACA972BCC9042B27B9B4       |
        +--------------------------------------------------------------------+
        |  5 | BackupKey | Version  : 2                                      |
        |    |           | Salt     : B60E21F9578D02A97964D7B10151BE69       |
        |    |           | Rounds   : 8000                                   |
        |    |           | Hash Alg : CALG_SHA_512                           |
        |    |           | Enc Alg  : CALG_AES_256                           |
        |    |           | Enc Key  : CD5D3684873D6A1D66520FB1642779E1       |
        |    |           |            D78A649F02DDFE7C069F9B5F8FF9F005       |
        |    |           |            7DC01E0A6AA9A815C8887BC1BF5B88E6       |
        |    |           |            E797DC5F4A3A0535B3217BADC7FAD38E       |
        |    |           |            798C1846423C8631DE472D790B308B2D       |
        |    |           |            F15340B87FCD55A98DAEE92196235CF9       |
        |    |           |            B328FAF475C05A911DF19C99D54D5A3C       |
        +--------------------------------------------------------------------+
        |  6 | CredHist  | Version  : 3                                      |
        |    |           | GUID     : {20e0b482-797f-429e-b4a0-30020731ef0a} |
        +--------------------------------------------------------------------+
</td></tr>
<tr><td> efs.masterkey disk=0 volume=4 inode=0x80544 sid="S-1-5-21-1521398...3175218-1001" password="ntfst00l"</td></tr>
<tr><td>
	
    [+] Opening \\?\Volume{ee732b26-571c-4516-b8fd-32282aa8e66b}\
    [+] Reading masterkey file record: 525636
    [-] Masterkey
        Encryption Algorithm : CALG_AES_256
        Hash Algorithm       : CALG_SHA_512
        Rounds               : 8000
        Salt                 : 3ED4CDBCC4073D6724A512061D0597E1
    [+] Decrypting masterkey
    [+] Clear masterkey (256bits):
        34FAC126105CE302421A0FC7E3933FEC5639AA6BFF95000E6DA83AE67522EAB6
        0AF58A27D834883B65611878B258AAAECD8983E3718E00F276178C5BFF4979EB
</td></tr>
</table>


### Reparse
<table>
<tr><td>reparse disk=0 volume=4</td></tr>
<tr><td>

    [+] Opening \\?\Volume{ee732b26-571c-4516-b8fd-32282aa8e66b}\
    [+] Reading $Extend\$Reparse
    [+] 104 entries found
    +----------------------------------------------------------------------------------------------------------------+
    | Id  | MFT Index | Filename                    | Type                        | Target/Data                      |
    +----------------------------------------------------------------------------------------------------------------+
    | 0   | 00000eb3  | debian.exe                  | AppExecLink                 | TheDebianProject.DebianGNULinux_ |
    |     |           |                             |                             | 76v4gfsz19hv4                    |
    |     |           |                             |                             |                                  |
    |     |           |                             |                             | TheDebianProject.DebianGNULinux_ |
    |     |           |                             |                             | 76v4gfsz19hv4!debian             |
    |     |           |                             |                             |                                  |
    |     |           |                             |                             | C:\Program Files\WindowsApps\The |
    |     |           |                             |                             | DebianProject.DebianGNULinux_1.2 |
    |     |           |                             |                             | .0.0_x64__76v4gfsz19hv4\debian.e |
    |     |           |                             |                             | xe                               |
    +----------------------------------------------------------------------------------------------------------------+
    ...
    +----------------------------------------------------------------------------------------------------------------+
    | 13  | 000007f9  | BaseLayer                   | Mount Point                 | \??\Volume{629458e4-0000-0000-00 |
    |     |           |                             |                             | 00-010000000000}\                |
    +----------------------------------------------------------------------------------------------------------------+
    | 14  | 00013e24  | Watchdog                    | Mount Point                 | \??\C:\Program Files\NVIDIA Corp |
    |     |           |                             |                             | oration\NvContainer\Watchdog     |
    +----------------------------------------------------------------------------------------------------------------+
    ...
    +----------------------------------------------------------------------------------------------------------------+
    | 102 | 00035861  | C2R64.dll                   | Symbolic Link               | \??\C:\Program Files\Common File |
    |     |           |                             |                             | s\Microsoft Shared\ClickToRun\C2 |
    |     |           |                             |                             | R64.dll                          |
    +----------------------------------------------------------------------------------------------------------------+
    | 103 | 000986b0  | All Users                   | Symbolic Link               | \??\C:\ProgramData               |
    +----------------------------------------------------------------------------------------------------------------+
</td></tr>
</table>


### Logfile-dump
<table>
<tr><td>logfile.dump disk=4 volume=1 output=logfile.csv format=csv</td></tr>
<tr><td>

    [+] Opening \\?\Volume{00000001-0000-0000-0000-000000000000}\
    [+] Reading $LogFile record
    [-]     $LogFile size : 4.14 MiBs
    [+] Parsing $LogFile Restart Pages
    [-]     Newest Restart Page LSN : 5274485
    [-]     Volume marked as cleanly unmounted
    [-]     Client found : [1] NTFS
    [+] Parsing $LogFile Record Pages
    [-]     $LogFile Record Page Count: 86
    [+] Parsing $LogFile Records: 601
    [+] Closing volume
</td></tr>
<tr><td>Sample of logfile.csv</td></tr>
<tr><td><pre>LSN,ClientPreviousLSN,UndoNextLSN,ClientID,RecordType,TransactionID,RedoOperation,UndoOperation,MFTClusterIndex,TargetVCN,TargetLCN
5269000,5268967,5268967,0,1,24,SetNewAttributeSizes,SetNewAttributeSizes,2,10,43700
5269019,5269000,5269000,0,1,24,UpdateNonresidentValue,Noop,0,0,37594
5269044,5269019,5269019,0,1,24,SetNewAttributeSizes,SetNewAttributeSizes,2,10,43700
5269063,5269044,5269044,0,1,24,SetNewAttributeSizes,SetNewAttributeSizes,2,10,43700
5269082,5269063,5269063,0,1,24,UpdateNonresidentValue,Noop,0,0,37594
5269103,5269082,5269082,0,1,24,SetNewAttributeSizes,SetNewAttributeSizes,2,10,43700
5269122,5269103,0,0,1,24,ForgetTransaction,CompensationLogRecord,0,0,18446744073709551615
5269133,0,0,0,1,24,UpdateResidentValue,UpdateResidentValue,2,13,43703</pre>
</td></tr>
</table>


### USN-analyze
<table>
	<tr><td>From dump : usn.analyze from=usn_dump rules=d:\rules.json output=d:\usn_analyze_results.csv format=csv</td></tr>
	<tr></tr>
	<tr><td>From running system : usn.analyze disk=4 volume=1 rules=d:\rules.json output=d:\usn_analyze_results.csv format=csv</td></tr>
<tr><td>


    [+] Loading rules from: d:\rules.json
    [-] 4 rules loaded
    [+] Creating d:\usn_analyze_results.csv
    [-] Mode: fast
    [+] Opening \\?\Volume{498eed94-0000-0000-007e-000000000000}\
    [+] Searching for $Extend\$UsnJrnl
    [-] Found in file record: 116
    [-] $J stream size: 31.70 KiBs (could be sparse)
    [+] Processing USN records: 192 (31.70 KiBs) - 9 matches
    [+] Closing volume
    [+] Summary:
        +------------------------------------------------------+
        | Index | Category      |               Value |      % |
        +------------------------------------------------------+
        | 0     | file creation |                 125 |  65.10 |
        | 1     | file deletion |                   0 |   0.00 |
        | 2     | file rename   |                   8 |   4.17 |
        | 3     | latest        | 2022-03-28 23:23:12 |        |
        | 4     | oldest        | 2022-03-28 13:20:08 |        |
        | 5     | records count |                 192 | 100.00 |
        +------------------------------------------------------+
    [+] Rules results:
        +------------------------------------------+
        | Index | Rule ID           | Count |    % |
        +------------------------------------------+
        | 0     | executable-create |     9 | 4.69 |
        | 1     | ccleaner          |     2 | 1.04 |
        | 2     | lsass-dump        |     1 | 0.52 |
        +------------------------------------------+
</td></tr>
</table>


### USN-dump
<table>
<tr><td>usn.dump disk=4 volume=1 output=usn.csv format=csv</td></tr>
<tr><td>
  
    [+] Opening \\?\Volume{ee732b26-571c-4516-b8fd-32282aa8e66b}\
    [+] Finding $Extend\$UsnJrnl record
    [+] Found in file record: 88008
    [+] $J stream size: 60.24 GiBs (could be sparse)
    [+] Creating d:\mft_c.csv
    [+] Loading $MFT records
    [+] Processing $MFT records: 1.37 GiB
    [+] 1436928 record loaded
    [+] Processing entry: 322667 (34.12 MiBs)
    [+] Closing volume
</td></tr>
<tr><td>Sample of usn.csv</td></tr>
<tr><td><pre>MajorVersion,MinorVersion,FileReferenceNumber,FileReferenceSequenceNumber,ParentFileReferenceNumber,ParentFileReferenceSequenceNumber,Usn,Timestamp,Reason,SourceInfo,SecurityId,FileAttributes,Filename
2,0,53,4,5,5,0,2020-02-26 21:43:36,FILE_CREATE,0,0,DIRECTORY,volume:\Nouveau dossier
2,0,53,4,5,5,96,2020-02-26 21:43:36,FILE_CREATE+CLOSE,0,0,DIRECTORY,volume:\Nouveau dossier
2,0,53,4,5,5,192,2020-02-26 21:43:38,RENAME_OLD_NAME,0,0,DIRECTORY,volume:\Nouveau dossier
2,0,53,4,5,5,288,2020-02-26 21:43:38,RENAME_NEW_NAME,0,0,DIRECTORY,volume:\test
2,0,53,4,5,5,360,2020-02-26 21:43:38,RENAME_NEW_NAME+CLOSE,0,0,DIRECTORY,volume:\test
2,0,53,4,5,5,432,2020-02-26 21:43:39,OBJECT_ID_CHANGE,0,0,DIRECTORY,volume:\test
2,0,53,4,5,5,504,2020-02-26 21:43:39,OBJECT_ID_CHANGE+CLOSE,0,0,DIRECTORY,volume:\test
2,0,54,2,53,4,576,2020-02-26 21:43:41,FILE_CREATE,0,0,ARCHIVE,volume:\test\Nouveau document texte.txt</pre>
</td></tr>
</table>



### Shadow
<table>
<tr><td>shadow disk=0 volume=4</td></tr>
<tr><td>
  
    [+] Opening \\?\Volume{ee732b26-571c-4516-b8fd-32282aa8e66b}\
    [+] VSS header found at 0x1e00

    +---------------------------------------------------------------------------------------------------------------+
    | SetID/ID                               | Count | Date                | Details                                |
    +---------------------------------------------------------------------------------------------------------------+
    | {857c9ac4-ee4f-4bc6-b822-59e935a7120f} | 1     | 2020-09-21 00:15:38 | Service Machine    : WORK-PC10         |
    |                                        |       |                     | Originating Machine: WORK-PC10         |
    | {3d102db1-8de2-4e7d-8ba5-e0dd4f67740d} |       |                     | State              : Created           |
    |                                        |       |                     | Flags              : 0x0042000d        |
    |                                        |       |                     |                    - Persistent        |
    |                                        |       |                     |                    - Client Accessible |
    |                                        |       |                     |                    - No Auto Release   |
    |                                        |       |                     |                    - Differential      |
    |                                        |       |                     |                    - Auto Recover      |
    +---------------------------------------------------------------------------------------------------------------+
    | {83bc8af4-8802-4466-ae38-717f6474616a} | 1     | 2020-09-22 06:10:00 | Service Machine    : WORK-PC10         |
    |                                        |       |                     | Originating Machine: WORK-PC10         |
    | {e668c329-66a2-4ebd-beef-3c6bca81cbf7} |       |                     | State              : Created           |
    |                                        |       |                     | Flags              : 0x0042000d        |
    |                                        |       |                     |                    - Persistent        |
    |                                        |       |                     |                    - Client Accessible |
    |                                        |       |                     |                    - No Auto Release   |
    |                                        |       |                     |                    - Differential      |
    |                                        |       |                     |                    - Auto Recover      |
    +---------------------------------------------------------------------------------------------------------------+
</td></tr>
</table>

### Streams
<table>
<tr><td>streams disk=0 volume=4 from=c:\test.pdf</td></tr>
<tr><td>
  
    [+] Opening \\?\Volume{ee732b26-571c-4516-b8fd-32282aa8e66b}\
    [-] Source      : c:\test.pdf
    [-] Record Num  : 13525 (000034d5h)
    [+] Alternate data stream(s):
        +-----------------------------+
        | Id | Name            | Size |
        +-----------------------------+
        |  0 | Zone.Identifier |   27 |
        +-----------------------------+
</td></tr>
</table>

### Undelete
<table>
<tr><td>undelete disk=4 volume=1</td></tr>
<tr><td>

    [+] Opening \\?\Volume{00000001-0000-0000-0000-000000000000}\
    [+] Reading $MFT record
    [+] $MFT size : 256.00 KiBs (~256 records)
    [+] Reading $BITMAP record
    [+] $BITMAP size : 16.00 KiBs
    [+] Searching deleted files
    [+] Processed data size : 262144 (100%)
    [+] Duration : 7ms

    Deleted Files Found
    -------------------

    +---------------------------------------------------------------------------------------------------------------+
    | Id | MFT Index | Flag | Filename                          | Size        | Deletion Date       | % Recoverable |
    +---------------------------------------------------------------------------------------------------------------+
    | 0  | 00000029  |      | .\$RECYCLE.BIN\[...]\$RAV85W4.jpg | 5.10 KiBs   | 2020-02-26 21:29:03 | 100.00        |
    +---------------------------------------------------------------------------------------------------------------+
    | 1  | 00000035  |      | .\$RECYCLE.BIN\[...]\$IAV85W4.jpg | 58.00 bytes | 2020-02-26 21:29:03 | 100.00        |
    +---------------------------------------------------------------------------------------------------------------+

</td></tr>
<tr><td>undelete disk=4 volume=1 inode=41 output=restored_kitten.jpg</td></tr>
<tr><td>

    [+] Opening \\?\Volume{00000001-0000-0000-0000-000000000000}\
    [+] Reading file record : 41
    [+] Extracting $RAV85W4.jpg to restored_kitten.jpg
    [+] 5219 bytes written
</td></tr>
</table>


### Shell
<table>
<tr><td>shell disk=4 volume=1</td></tr>
<tr><td>

    disk4:volume1:> ls

    Inode | Type | Name                      | Size      | Creation Date       | Attributes
    ---------------------------------------------------------------------------------------
        4 |      | $AttrDef                  |      2560 | 2020-02-26 16:35:29 | Hi Sy
        8 |      | $BadClus                  |         0 | 2020-02-26 16:35:29 | Hi Sy
          | ADS  |   $Bad                    | 536866816 |                     |
        6 |      | $Bitmap                   |     16384 | 2020-02-26 16:35:29 | Hi Sy
        7 |      | $Boot                     |      8192 | 2020-02-26 16:35:29 | Hi Sy
       11 | DIR  | $Extend                   |           | 2020-02-26 16:35:29 | Hi Sy
        2 |      | $LogFile                  |   4341760 | 2020-02-26 16:35:29 | Hi Sy
        0 |      | $MFT                      |    262144 | 2020-02-26 16:35:29 | Hi Sy
        1 |      | $MFTMirr                  |      4096 | 2020-02-26 16:35:29 | Hi Sy
       50 | DIR  | $RECYCLE.BIN              |           | 2020-02-26 16:40:34 | Hi Sy
        9 |      | $Secure                   |         0 | 2020-02-26 16:35:29 | Hi Sy
          | ADS  |   $SDS                    |    264200 |                     |
       10 |      | $UpCase                   |    131072 | 2020-02-26 16:35:29 | Hi Sy
          | ADS  |   $Info                   |        32 |                     |
        3 |      | $Volume                   |         0 | 2020-02-26 16:35:29 | Hi Sy
        5 | DIR  | .                         |           | 2020-02-26 16:35:29 | Hi Sy
    85010 |      | 7z1900-x64.exe            |   1447178 | 2020-07-29 17:19:49 | Ar
          | ADS  |   Zone.Identifier         |       123 |                     | 
       42 |      | hello.txt                 |         5 | 2020-02-26 21:27:33 | Ar
       39 |      | kitten1.jpg               |     23486 | 2020-02-26 16:37:23 | Ar
          | ADS  |   Zone.Identifier         |       154 |                     |
       40 |      | kitten2.jpg               |     79678 | 2020-02-26 16:37:55 | Ar
          | ADS  |   Zone.Identifier         |       303 |                     |
       41 |      | kitten3.jpg               |      5219 | 2020-02-26 16:38:16 | Ar
          | ADS  |   Zone.Identifier         |       262 |                     |
       36 | DIR  | System Volume Information |           | 2020-02-26 16:35:29 | Hi Sy

    disk4:volume1:> pwd
    \
    disk4:volume1:> cat hello.txt
    Hey !
    disk4:volume1:> cat 7z1900-x64.exe:Zone.Identifier
    [ZoneTransfer]
    ZoneId=3
    ReferrerUrl=https://www.7-zip.org/download.html
    HostUrl=https://www.7-zip.org/a/7z1900-x64.exe

    disk4:volume1:> cp kitten3.jpg z:\custestkitten.jpg
    1 file copied
    disk4:volume1:> exit
    
</td></tr>
</table>


### SMART
<table>
<tr><td>smart disk=1</td></tr>
<tr><td>

    Version          : 1 revision 1
    Type             : SATA/IDE Master on primary channel
    Capabilities     : ATA, ATAPI, S.M.A.R.T

    Status           : Passed

    -- Device ID
    +---------------------------------------------------------------------------------------------------+
    | Property                                               | Value                                    |
    +---------------------------------------------------------------------------------------------------+
    | General Configuration                                  | 0040h                                    |
    | Number of Cylinders                                    | 16383                                    |
    | Reserved                                               | c837h                                    |
    | Number Of Heads                                        | 16                                       |
    | Bytes Per Track                                        | 0                                        |
    | Bytes Per Sector                                       | 0                                        |
    | Sectors Per Track                                      | 63                                       |
    | Vendor Unique                                          |                                          |
    | Seria Number                                           | S2RBNX0H606448W                          |
    | Buffer Type                                            | 0                                        |
    | Buffer Size                                            | 0                                        |
    | ECC Size                                               | 0                                        |
    | Firmware Revision                                      | EMT02B6Q                                 |
    | Model Number                                           | Samsung SSD 850 EVO 500GB                |
    | Maximum Number of Sectors On R/W                       | 32769                                    |
    | Double Word IO                                         | 16385                                    |
    | Capabilities                                           | Reserved                 : 0000h         |
    |                                                        | DMA Support              : True          |
    |                                                        | LBA Support              : True          |
    |                                                        | DisIORDY                 : True          |
    |                                                        | IORDY                    : True          |
    |                                                        | Requires ATA soft start  : False         |
    |                                                        | Overlap Operation support: True          |
    |                                                        | Command Queue Support    : False         |
    |                                                        | Interleaved DMA Support  : False         |
    | Reserved1                                              | 4000h                                    |
    | PIO Timing                                             | 512                                      |
    | DMA Timing                                             | 512                                      |
    | Field Validity                                         | CHS Number               : True          |
    |                                                        | Cycle Number             : True          |
    |                                                        | Ultra DMA                : True          |
    | Current numbers of cylinders                           | 16383                                    |
    | Current numbers of heads                               | 16                                       |
    | Current numbers of sectors per track                   | 63                                       |
    | Multiple Sector Setting                                | 16514064                                 |
    | Total Number of Sectors Addressable (LBA)              | 268435455                                |
    | Singleword DMA Transfer Support                        | 0                                        |
    | Multiword DMA Transfer Support                         | Mode 0 (4.17Mb/s)                        |
    |                                                        | Mode 1 (13.3Mb/s)                        |
    |                                                        | Mode 2 (16.7Mb/s)                        |
    | Advanced PIO Modes                                     | 0003h                                    |
    | Minimum Multiword DMA Transfer Cycle Time per Word     | 120                                      |
    | Recommended Multiword DMA Transfer Cycle Time per Word | 120                                      |
    | Minimum PIO Transfer Cycle Time (No Flow Control)      | 120                                      |
    | Minimum PIO Transfer Cycle Time (Flow Control)         | 120                                      |
    | ATA Support                                            | ATA-2                                    |
    |                                                        | ATA-3                                    |
    |                                                        | ATA-4                                    |
    |                                                        | ATA/ATAPI-5                              |
    |                                                        | ATA/ATAPI-6                              |
    |                                                        | ATA/ATAPI-7                              |
    |                                                        | ATA/ATAPI-8                              |
    |                                                        | ATA/ATAPI-9                              |
    | Ultra DMA Transfer Support                             | Mode 0 (16.7MB/s)                        |
    |                                                        | Mode 1 (25.0MB/s)                        |
    |                                                        | Mode 2 (33.3MB/s)                        |
    |                                                        | Mode 3 (44.4MB/s)                        |
    |                                                        | Mode 4 (66.7MB/s)                        |
    |                                                        | Mode 5 (100.0MB/s) (selected)            |
    |                                                        | Mode 6 (133.0MB/s)                       |
    +---------------------------------------------------------------------------------------------------+

    -- Attributes
    +-------------------------------------------------------------------------------------------------------------------+
    | Index | Name                                         | Flags | Raw           | Value | Worst | Threshold | Status |
    +-------------------------------------------------------------------------------------------------------------------+
    |   05h | Reallocated Sector Count                     | 0033h | 000000000000h |   100 |   100 |        10 |     Ok |
    |   09h | Power-On Hours Count                         | 0032h | 000000008d54h |    92 |    92 |         0 |     Ok |
    |   0ch | Power Cycle Count                            | 0032h | 0000000000f5h |    99 |    99 |         0 |     Ok |
    |   b1h | Wear Range Delta                             | 0013h | 00000000005eh |    95 |    95 |         0 |     Ok |
    |   b3h | Used Reserved Block Count (Total)            | 0013h | 000000000000h |   100 |   100 |        10 |     Ok |
    |   b5h | Program Fail Count Total                     | 0032h | 000000000000h |   100 |   100 |        10 |     Ok |
    |   b6h | Erase Fail Count                             | 0032h | 000000000000h |   100 |   100 |        10 |     Ok |
    |   b7h | Sata Down Shift Error Count                  | 0013h | 000000000000h |   100 |   100 |        10 |     Ok |
    |   bbh | Reported Uncorrectable Errors                | 0032h | 000000000000h |   100 |   100 |         0 |     Ok |
    |   beh | Temperature Difference From 100              | 0032h | 000000000020h |    68 |    50 |         0 |     Ok |
    |   c3h | Hardware Ecc Recovered                       | 001ah | 000000000000h |   200 |   200 |         0 |     Ok |
    |   c7h | Udma Crc Error Rate                          | 003eh | 000000000000h |   100 |   100 |         0 |     Ok |
    |   ebh | Good Block Count And System Free Block Count | 0012h | 000000000071h |    99 |    99 |         0 |     Ok |
    |   f1h | Lifetime Writes From Host Gib                | 0032h | 00154bf298c9h |    99 |    99 |         0 |     Ok |
    +-------------------------------------------------------------------------------------------------------------------+
 
</td></tr>
</table>
