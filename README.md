# ntfstool

[![GitHub license](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE.MIT)
[![Language: C++](https://img.shields.io/badge/Language-C%2B%2B-brightgreen.svg?tyle=flat-square)](#)
[![x64](https://img.shields.io/badge/Windows-64_bit-0078d7.svg)](#)
[![x86](https://img.shields.io/badge/Windows-32_bit-0078d7.svg)](#)
[![v1.2](https://img.shields.io/badge/Version-1.3-ff5733.svg)](#)
![Build](https://github.com/thewhiteninja/ntfstool/workflows/Build/badge.svg)

<br />

NTFSTool is a forensic tool to play with disks and NTFS volumes.
It supports reading partition info (mbr, partition table, vbr) but also information on bitlocker encrypted partition (fve).
See examples below to see some of the features!

## Features

### Forensics

NTFSTool displays the complete structure of master boot record, volume boot record, partition table and MFT file record.
It is also possible to dump any file (even hidden $mft) or parse $usnjrnl, $logfile including file from Alternate Data Stream (ADS).
The undelete command will search for any file record marked as "not in use" and allow you to retrieve the file (or part of the file if it was already rewritten).
It support input from image file or live disks. You can also use tools like [OSFMount][3] to mount your disk image.
Sparse and compressed files are also (partially) supported. 

### Bitlocker support

For bitlocked partition, it can display FVE records, check a password and support 3 formats (bek, password, recovery key), extract VMK and FVEK.
There is no bruteforcing feature because GPU-based cracking is better (see [Bitcracker][1] and [Hashcat][2]).

[1]: https://arxiv.org/pdf/1901.01337
[2]: https://hashcat.net/hashcat/

### Shell

There is a limited shell with few commands (exit, cd, ls , cat , pwd, cp).

## Help & Examples

the help command displays some examples for each command.

    ntfstool help [command]
    
| Command | Description |
| --- | --- |
| [info](#info) | Display information for all disks and volumes |
| [mbr](#mbr) | Display MBR structure, code and partitions for a disk |
| [gpt](#gpt) | Display GPT structure, code  and partitions for a disk |
| [vbr](#vbr)  | Display VBR structure and code for a specidifed volume (ntfs, fat32, fat1x, bitlocker supported) |
| [extract](#extract)  | Extract a file from a volume. |
| [image](#image)  | Create an image file of a disk or volume. |
| [mft](#mft)  | Display FILE record details for a specified MFT inode. Almost all attribute types supported |
| [bitlocker](#bitlocker)  | Display detailed information and hash ($bitlocker$) for all VMK. It is possible to test a password or recovery key. If it is correct, the decrypted VMK and FVEK is displayed. |
| [bitdecrypt](#bitdecrypt)  | Decrypt a volume to a file using password, recovery key or bek. |
| [fve](#fve)  | Display information for the specified FVE block (0, 1, 2) |
| [reparse](#reparse)  | Parse and display reparse points from \$Extend\$Reparse. |
| [logfile](#logfile)  | Dump $LogFile file in specified format: csv, json, raw. |
| [usn](#usn)  | Dump $UsnJrnl file  in specified format: csv, json, raw. |
| [shadow](#shadow)  | List volume shadow snapshots from selected disk and volume. |
| [undelete](#undelete)  | Search and extract deleted files for a volume. |
| [smart](#smart)  | Display S.M.A.R.T data |


## Limitations

- May contains bugs and unsupported cases.
- No documentation :no_mouth:.

## Third-parties

- [openssl](https://www.openssl.org/) (vcpkg): OpenSSL is an open source project that provides a robust, commercial-grade, and full-featured toolkit for the Transport Layer Security (TLS) and Secure Sockets Layer (SSL) protocols.
- [nlohmann-json](https://github.com/nlohmann/json) (vcpkg): JSON for Modern C++
- [distorm](https://github.com/gdabah/distorm) (vcpkg): Powerful Disassembler Library For x86/AMD64
- [cppcoro](https://github.com/lewissbaker/cppcoro) (vcpkg): A library of C++ coroutine abstractions for the coroutines TS.
  

[3]: https://www.osforensics.com/tools/mount-disk-images.html

## Output examples

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
<tr><td>mbr disk=3</td></tr>
<tr><td>

    Disk signature  : 9825a009
    Reserved bytes  : 0000

    Partition table :
    +--------------------------------------------------------------------------+
    | Id | Boot | Type         | First sector | Last sector | Offset | Size    |
    +--------------------------------------------------------------------------+
    | 1  | No   | NTFS / exFAT | 0 2 0        | 254 63 64   | 1      | 1048575 |
    +--------------------------------------------------------------------------+

    MBR signature  : 55aa

    Strings:
        No strings found

    Disassemble Bootstrap Code [y/N] ? y
        Empty code
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
        Serial Nuumber   : 00000000
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
        [...]
</td></tr>
</table>


### Extract
<table>
<tr><td>extract disk=3 volume=1 from=\bob.txt output=d:\bob.txt</td></tr>
<tr><td>

    Extract file from \\.\PhysicalDrive3 > Volume:1
    -----------------------------------------------

    [+] Opening \\?\Volume{00023d5d-0000-0000-0002-000000000000}\
    [-] Source      : \bob.txt
    [-] Destination : d:\bob.txt
    [-] Record Num  : 47 (0000002fh)
    [+] File extracted (42 bytes written)
    
</td></tr>
<tr><td>extract disk=0 volume=4 --system output=d:\system</td></tr>
<tr><td>

    Extract file from \\.\PhysicalDrive0 > Volume:4
    -----------------------------------------------

    [+] Opening \\?\Volume{ee732b26-571c-4516-b8fd-32282aa8e66b}\
    [-] Source      : c:\windows\system32\config\system
    [-] Destination : d:\system
    [-] Record Num  : 623636 (00098414h)
    [+] File extracted (19398656 bytes written)
    
</td></tr>
</table>



### Image
<table>
<tr><td>image disk=2 volume=2 output=d:\imagevol.raw</td></tr>
<tr><td>

    Image from \\.\PhysicalDrive2 > Volume:2
    ----------------------------------------

    [+] Opening \\?\Volume{f095dd1d-f302-4d17-bf68-7cc8c1de3965}\
    [-] Size     : 33520128 (31.97 MiBs)
    [-] BlockSize: 4096
    [+] Copying  : [################################] 100% 0s
    [+] Done
    
</td></tr>
<tr><td>image disk=2 output=d:\image.raw</td></tr>
<tr><td>
    
    Image from \\.\PhysicalDrive2
    -----------------------------

    [+] Opening \\.\PhysicalDrive2
    [-] Size     : 67108864 (64.00 MiBs)
    [-] BlockSize: 4096
    [+] Copying  : [################################] 100% 0s
    [+] Done
    
</td></tr>
</table>


### MFT
<table>
<tr><td>mft disk=2 volume=1 inode=5 (root folder)</td></tr>
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


### Bitlocker
<table>
<tr><td>bitlocker disk=3 volume=1</td></tr>
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
<tr><td>bitlocker disk=3 volume=1 password=badpassword</td></tr>
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
<tr><td>bitlocker disk=3 volume=1 password=123456789</td></tr>
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


### Bitdecrypt
<table>
<tr><td>bitdecrypt disk=3 volume=1 output=decrypted.img fvek=35b8197e6d74d8521f49698d5f5565892cf286ae5323c65631965c905a9d7da4</td></tr>
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


### FVE
<table>
<tr><td>fve disk=3 volume=1 fve_block=2</td></tr>
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
    | 1  | 1       | 72   | Drive Label         | Unicode         | String        : TWN NTFSDRIVE 26/02/2020  |
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


### reparse
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


### logfile
<table>
<tr><td>logfile disk=4 volume=1 output=logfile.csv format=csv</td></tr>
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
<tr><td><pre>    LSN,ClientPreviousLSN,UndoNextLSN,ClientID,RecordType,TransactionID,RedoOperation,UndoOperation,MFTClusterIndex,TargetVCN,TargetLCN
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


### usn
<table>
<tr><td>usn disk=4 volume=1 output=usn.csv format=csv</td></tr>
<tr><td>
  
    [+] Opening \\?\Volume{00000001-0000-0000-0000-000000000000}\
    [+] Finding $Extend\$UsnJrnl record
    [+] Found in file record : 41
    [+] Data stream $J size : 2.66 KiBs
    [+] Reading $J
    [+] Processing entry : 32
    [+] Closing volume
</td></tr>
<tr><td>Sample of usn.csv</td></tr>
<tr><td><pre>MajorVersion,MinorVersion,FileReferenceNumber,FileReferenceSequenceNumber,ParentFileReferenceNumber,ParentFileReferenceSequenceNumber,Usn,Timestamp,Reason,SourceInfo,SecurityId,FileAttributes,Filename
2,0,53,4,5,5,0,2020-02-26 21:43:36,FILE_CREATE,0,0,DIRECTORY,Nouveau dossier
2,0,53,4,5,5,96,2020-02-26 21:43:36,FILE_CREATE+CLOSE,0,0,DIRECTORY,Nouveau dossier
2,0,53,4,5,5,192,2020-02-26 21:43:38,RENAME_OLD_NAME,0,0,DIRECTORY,Nouveau dossier
2,0,53,4,5,5,288,2020-02-26 21:43:38,RENAME_NEW_NAME,0,0,DIRECTORY,test
2,0,53,4,5,5,360,2020-02-26 21:43:38,RENAME_NEW_NAME+CLOSE,0,0,DIRECTORY,test
2,0,53,4,5,5,432,2020-02-26 21:43:39,OBJECT_ID_CHANGE,0,0,DIRECTORY,test
2,0,53,4,5,5,504,2020-02-26 21:43:39,OBJECT_ID_CHANGE+CLOSE,0,0,DIRECTORY,test
2,0,54,2,53,4,576,2020-02-26 21:43:41,FILE_CREATE,0,0,ARCHIVE,Nouveau document texte.txt</pre>
</td></tr>
</table>



### shadow
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

### undelete
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


### shell
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

    disk4:volume1:> exit
    
</td></tr>
</table>


### smart
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
