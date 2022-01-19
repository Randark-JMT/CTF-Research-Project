# Volatility2用法详细说明

> Volatility目前稳定发行版是2.6，但是3.0版本正在开发。在3.0版本稳定发布之后另作介绍，目前这里仅介绍Volatility2.6的使用

首先，偷懒一下，贴一份Volatility自带的help上来：

```shell
┌──(kali㉿kali)-[~/volatility]
└─$ python vol.py -h
Volatility Foundation Volatility Framework 2.6.1
Usage: Volatility - A memory forensics analysis platform.

Options:
  -h, --help            list all available options and their default values.
                        Default values may be set in the configuration file
                        (/etc/volatilityrc)
  --conf-file=/home/kali/.volatilityrc
                        User based configuration file
  -d, --debug           Debug volatility
  --plugins=PLUGINS     Additional plugin directories to use (colon separated)
  --info                Print information about all registered objects
  --cache-directory=/home/kali/.cache/volatility
                        Directory where cache files are stored
  --cache               Use caching
  --tz=TZ               Sets the (Olson) timezone for displaying timestamps
                        using pytz (if installed) or tzset
  -C 4000, --confsize=4000
                        Config data size
  -Y YARAOFFSET, --yaraoffset=YARAOFFSET
                        YARA start offset
  -f FILENAME, --filename=FILENAME
                        Filename to use when opening an image
  --profile=WinXPSP2x86
                        Name of the profile to load (use --info to see a list
                        of supported profiles)
  -l LOCATION, --location=LOCATION
                        A URN location from which to load an address space
  -w, --write           Enable write support
  --dtb=DTB             DTB Address
  --shift=SHIFT         Mac KASLR shift address
  --output=text         Output in this format (support is module specific, see
                        the Module Output Options below)
  --output-file=OUTPUT_FILE
                        Write output in this file
  -v, --verbose         Verbose information
  --physical_shift=PHYSICAL_SHIFT
                        Linux kernel physical shift address
  --virtual_shift=VIRTUAL_SHIFT
                        Linux kernel virtual shift address
  -g KDBG, --kdbg=KDBG  Specify a KDBG virtual address (Note: for 64-bit
                        Windows 8 and above this is the address of
                        KdCopyDataBlock)
  --force               Force utilization of suspect profile
  --cookie=COOKIE       Specify the address of nt!ObHeaderCookie (valid for
                        Windows 10 only)
  -k KPCR, --kpcr=KPCR  Specify a specific KPCR address

        Supported Plugin Commands:

                amcache         Print AmCache information
                apihooks        Detect API hooks in process and kernel memory
                atoms           Print session and window station atom tables
                atomscan        Pool scanner for atom tables
                auditpol        Prints out the Audit Policies from HKLM\SECURITY\Policy\PolAdtEv
                bigpools        Dump the big page pools using BigPagePoolScanner
                bioskbd         Reads the keyboard buffer from Real Mode memory
                cachedump       Dumps cached domain hashes from memory
                callbacks       Print system-wide notification routines
                clipboard       Extract the contents of the windows clipboard
                cmdline         Display process command-line arguments
                cmdscan         Extract command history by scanning for _COMMAND_HISTORY
                connections     Print list of open connections [Windows XP and 2003 Only]
                connscan        Pool scanner for tcp connections
                consoles        Extract command history by scanning for _CONSOLE_INFORMATION
                crashinfo       Dump crash-dump information
                deskscan        Poolscaner for tagDESKTOP (desktops)
                devicetree      Show device tree
                dlldump         Dump DLLs from a process address space
                dlllist         Print list of loaded dlls for each process
                driverirp       Driver IRP hook detection
                drivermodule    Associate driver objects to kernel modules
                driverscan      Pool scanner for driver objects
                dumpcerts       Dump RSA private and public SSL keys
                dumpfiles       Extract memory mapped and cached files
                dumpregistry    Dumps registry files out to disk 
                editbox         Displays information about Edit controls. (Listbox experimental.)
                envars          Display process environment variables
                eventhooks      Print details on windows event hooks
                evtlogs         Extract Windows Event Logs (XP/2003 only)
                filescan        Pool scanner for file objects
                gahti           Dump the USER handle type information
                gditimers       Print installed GDI timers and callbacks
                gdt             Display Global Descriptor Table
                getservicesids  Get the names of services in the Registry and return Calculated SID
                getsids         Print the SIDs owning each process
                handles         Print list of open handles for each process
                hashdump        Dumps passwords hashes (LM/NTLM) from memory
                hibinfo         Dump hibernation file information
                hivedump        Prints out a hive
                hivelist        Print list of registry hives.
                hivescan        Pool scanner for registry hives
                hpakextract     Extract physical memory from an HPAK file
                hpakinfo        Info on an HPAK file
                idt             Display Interrupt Descriptor Table
                iehistory       Reconstruct Internet Explorer cache / history
                imagecopy       Copies a physical address space out as a raw DD image
                imageinfo       Identify information for the image 
                impscan         Scan for calls to imported functions
                joblinks        Print process job link information
                kdbgscan        Search for and dump potential KDBG values
                kpcrscan        Search for and dump potential KPCR values
                lastpass        Extract lastpass data from process. 
                ldrmodules      Detect unlinked DLLs
                lsadump         Dump (decrypted) LSA secrets from the registry
                machoinfo       Dump Mach-O file format information
                malfind         Find hidden and injected code
                mbrparser       Scans for and parses potential Master Boot Records (MBRs) 
                memdump         Dump the addressable memory for a process
                memmap          Print the memory map
                messagehooks    List desktop and thread window message hooks
                mftparser       Scans for and parses potential MFT entries 
                mimikatz        mimikatz offline
                moddump         Dump a kernel driver to an executable file sample
                modscan         Pool scanner for kernel modules
                modules         Print list of loaded modules
                multiscan       Scan for various objects at once
                mutantscan      Pool scanner for mutex objects
                notepad         List currently displayed notepad text
                objtypescan     Scan for Windows object type objects
                patcher         Patches memory based on page scans
                poolpeek        Configurable pool scanner plugin
                printkey        Print a registry key, and its subkeys and values
                privs           Display process privileges
                procdump        Dump a process to an executable file sample
                pslist          Print all running processes by following the EPROCESS lists 
                psscan          Pool scanner for process objects
                pstree          Print process list as a tree
                psxview         Find hidden processes with various process listings
                qemuinfo        Dump Qemu information
                raw2dmp         Converts a physical memory sample to a windbg crash dump
                screenshot      Save a pseudo-screenshot based on GDI windows
                servicediff     List Windows services (ala Plugx)
                sessions        List details on _MM_SESSION_SPACE (user logon sessions)
                shellbags       Prints ShellBags info
                shimcache       Parses the Application Compatibility Shim Cache registry key
                shutdowntime    Print ShutdownTime of machine from registry
                sockets         Print list of open sockets
                sockscan        Pool scanner for tcp socket objects
                ssdt            Display SSDT entries
                strings         Match physical offsets to virtual addresses (may take a while, VERY verbose)
                svcscan         Scan for Windows services
                symlinkscan     Pool scanner for symlink objects
                thrdscan        Pool scanner for thread objects
                threads         Investigate _ETHREAD and _KTHREADs
                timeliner       Creates a timeline from various artifacts in memory 
                timers          Print kernel timers and associated module DPCs
                truecryptmaster Recover TrueCrypt 7.1a Master Keys
                truecryptpassphrase     TrueCrypt Cached Passphrase Finder
                truecryptsummary        TrueCrypt Summary
                unloadedmodules Print list of unloaded modules
                usbstor         Parse USB Data from the Registry
                userassist      Print userassist registry keys and information
                userhandles     Dump the USER handle tables
                vaddump         Dumps out the vad sections to a file
                vadinfo         Dump the VAD info
                vadtree         Walk the VAD tree and display in tree format
                vadwalk         Walk the VAD tree
                vboxinfo        Dump virtualbox information
                verinfo         Prints out the version information from PE images
                vmwareinfo      Dump VMware VMSS/VMSN information
                volshell        Shell in the memory image
                windows         Print Desktop Windows (verbose details)
                wintree         Print Z-Order Desktop Windows Tree
                wndscan         Pool scanner for window stations
                yarascan        Scan process or kernel memory with Yara signatures
```

然后对每个插件和参数，以及工作流，做一下解析：

<u>*这里使用 HDCTF2019-你能发现什么蛛丝马迹吗 作为演示样本。*</u>

## imageinfo-映像信息

```shell
┌──(kali㉿kali)-[~/volatility]
└─$ python vol.py -f /home/kali/memory.img imageinfo                                            
Volatility Foundation Volatility Framework 2.6.1
INFO    : volatility.debug    : Determining profile based on KDBG search...
          Suggested Profile(s) : Win2003SP0x86, Win2003SP1x86, Win2003SP2x86
                     AS Layer1 : IA32PagedMemoryPae (Kernel AS)
                     AS Layer2 : FileAddressSpace (/home/kali/memory.img)
                      PAE type : PAE
                           DTB : 0xe02000L
                          KDBG : 0x8088e3e0L
          Number of Processors : 1
     Image Type (Service Pack) : 1
                KPCR for CPU 0 : 0xffdff000L
             KUSER_SHARED_DATA : 0xffdf0000L
           Image date and time : 2019-04-25 08:43:06 UTC+0000
     Image local date and time : 2019-04-25 16:43:06 +0800
```

`imageinfo`这个参数可以导出映像信息，其中最重要的莫过于平台架构信息，因为后续的分析需要指定架构参数。

***需要注意，这些信息只是一种猜测，后续分析如果报错，需要继续尝试可能结果。***

## pslist-进程列表

```shell
┌──(kali㉿kali)-[~/volatility]
└─$ python vol.py -f /home/kali/memory.img --profile=Win2003SP1x86 pslist                       
Volatility Foundation Volatility Framework 2.6.1
Offset(V)  Name                    PID   PPID   Thds     Hnds   Sess  Wow64 Start                          Exit                          
---------- -------------------- ------ ------ ------ -------- ------ ------ ------------------------------ ------------------------------
0x81f8f020 System                    4      0     56      319 ------      0                                                              
0xfe2f8448 smss.exe                380      4      3       18 ------      0 2018-12-07 16:20:54 UTC+0000                                 
0xfe2caa60 csrss.exe               516    380     12      509      0      0 2018-12-07 16:21:00 UTC+0000                                 
0xfe304298 winlogon.exe            580    380     25      504      0      0 2018-12-07 16:21:04 UTC+0000                                 
0xfe2fdd88 services.exe            648    580     16      303      0      0 2018-12-07 16:21:05 UTC+0000                                 
0xfe2e5530 lsass.exe               660    580     38      458      0      0 2018-12-07 16:21:05 UTC+0000                                 
0xfe2f9290 vmacthlp.exe            880    648      1       26      0      0 2018-12-07 16:21:06 UTC+0000                                 
0xfe34d658 svchost.exe             932    648      6       93      0      0 2018-12-07 16:21:07 UTC+0000                                 
0xfde05020 svchost.exe             984    648     10      268      0      0 2018-12-07 16:21:07 UTC+0000                                 
0xfddf4c08 svchost.exe            1040    648     10      138      0      0 2018-12-07 16:21:08 UTC+0000                                 
0xfddeb020 svchost.exe            1072    648     15      168      0      0 2018-12-07 16:21:08 UTC+0000                                 
0xfdde9a70 svchost.exe            1096    648     79     1271      0      0 2018-12-07 16:21:08 UTC+0000                                 
0x81e5a7d0 spoolsv.exe            1668    648     14      151      0      0 2018-12-07 16:21:26 UTC+0000                                 
0xfe7385e8 msdtc.exe              1700    648     16      166      0      0 2018-12-07 16:21:26 UTC+0000                                 
0xfddb7b18 svchost.exe            1800    648      2       54      0      0 2018-12-07 16:21:27 UTC+0000                                 
0xfddb1020 svchost.exe            1848    648      2       37      0      0 2018-12-07 16:21:27 UTC+0000                                 
0xfdda8020 VGAuthService.e        1920    648      2       65      0      0 2018-12-07 16:21:28 UTC+0000                                 
0xfdc6eb18 vmtoolsd.exe            300    648      8      244      0      0 2018-12-07 16:21:36 UTC+0000                                 
0xfe3d5600 svchost.exe             484    648     16      135      0      0 2018-12-07 16:21:40 UTC+0000                                 
0xfe3d4cb0 dllhost.exe             736    648     22      239      0      0 2018-12-07 16:21:41 UTC+0000                                 
0xfe30ed88 dllhost.exe            1052    648     22      236      0      0 2018-12-07 16:21:42 UTC+0000                                 
0xfdc40638 wmiprvse.exe           1368    932      9      215      0      0 2018-12-07 16:21:44 UTC+0000                                 
0xfdc1bb18 explorer.exe           1992   1664     16      386      0      0 2018-12-07 16:21:50 UTC+0000                                 
0xfdc1ad88 vssvc.exe              2040    648      7      112      0      0 2018-12-07 16:21:51 UTC+0000                                 
0xfdbd3418 vmtoolsd.exe           1596   1992      6      166      0      0 2018-12-07 16:22:01 UTC+0000                                 
0xfdbd2110 ctfmon.exe             1840   1992      1       69      0      0 2018-12-07 16:22:01 UTC+0000                                 
0xfdbbc330 conime.exe             1792   1636      1       32      0      0 2018-12-07 16:22:16 UTC+0000                                 
0xfdba5320 wmiprvse.exe           1128    932      8      165      0      0 2018-12-07 16:22:24 UTC+0000                                 
0xfdb90930 wuauclt.exe            2224   1096      5      116      0      0 2018-12-07 16:22:44 UTC+0000                                 
0xfdb6a638 DumpIt.exe             3660   1992      1       26      0      0 2019-04-25 08:43:04 UTC+0000    
```

`pslist`这个参数可以显示内存中的所有进程，并给出了数据的位置信息。

## hivelist-注册表信息

```shell
┌──(kali㉿kali)-[~/volatility]
└─$ python vol.py -f /home/kali/memory.img --profile=Win2003SP1x86 hivelist                                                                                      1 ⨯
Volatility Foundation Volatility Framework 2.6.1
Virtual    Physical   Name
---------- ---------- ----
0xe1cec320 0x0687a320 \Device\HarddiskVolume1\Documents and Settings\NetworkService\NTUSER.DAT
0xe1cf5008 0x06dc8008 \Device\HarddiskVolume1\Documents and Settings\NetworkService\Local Settings\Application Data\Microsoft\Windows\UsrClass.dat
0xe1d10a80 0x03445a80 \Device\HarddiskVolume1\Documents and Settings\LocalService\NTUSER.DAT
0xe1d17290 0x067d2290 \??\C:\Documents and Settings\LocalService\Local Settings\Application Data\Microsoft\Windows\UsrClass.dat
0xe1500a80 0x05951a80 \Device\HarddiskVolume1\Documents and Settings\Administrator\NTUSER.DAT
0xe19d3008 0x05c8e008 \Device\HarddiskVolume1\Documents and Settings\Administrator\Local Settings\Application Data\Microsoft\Windows\UsrClass.dat
0xe1008750 0x07b14750 [no name]
0xe101a558 0x07aa1558 \Device\HarddiskVolume1\WINDOWS\system32\config\system
0xe12f68d0 0x077ff8d0 [no name]
0xe165f008 0x02993008 \Device\HarddiskVolume1\WINDOWS\system32\config\SECURITY
0xe166d008 0x028fa008 \SystemRoot\System32\Config\SAM
0xe166aa80 0x028b6a80 \Device\HarddiskVolume1\WINDOWS\system32\config\default
0xe165f690 0x02993690 \Device\HarddiskVolume1\WINDOWS\system32\config\software
```

`hivelist`这个参数可以显示出来内存中的注册表数据

## cmdscan-命令行记录

```shell
┌──(kali㉿kali)-[~/volatility]
└─$ python vol.py -f /home/kali/memory.img --profile=Win2003SP1x86 cmdscan 
Volatility Foundation Volatility Framework 2.6.1
**************************************************
CommandProcess: csrss.exe Pid: 516
CommandHistory: 0x398fba8 Application: DumpIt.exe Flags: Allocated
CommandCount: 0 LastAdded: -1 LastDisplayed: -1
FirstCommand: 0 CommandCountMax: 50
ProcessHandle: 0x6e4
```

## netscan-网络连接信息

```shell
┌──(kali㉿kali)-[~/volatility]
└─$ python vol.py -f /home/kali/memory.img --profile=Win2003SP1x86 netscan
Volatility Foundation Volatility Framework 2.6.1
ERROR   : volatility.debug    : This command does not support the profile Win2003SP1x86
```

~~不做任何评价~~

## iehistory-IE历史数据

```shell
┌──(kali㉿kali)-[~/volatility]
└─$ python vol.py -f /home/kali/memory.img --profile=Win2003SP1x86 iehistory                                                                                        1 ⨯
Volatility Foundation Volatility Framework 2.6.1
**************************************************
Process: 1992 explorer.exe
Cache type "DEST" at 0x167215
Last modified: 2019-04-25 16:43:00 UTC+0000
Last accessed: 2019-04-25 08:43:02 UTC+0000
URL: Administrator@file:///C:/Documents%20and%20Settings/Administrator/Lhb/flag.png
**************************************************
Process: 1992 explorer.exe
Cache type "DEST" at 0x16748d
Last modified: 2019-04-25 16:43:00 UTC+0000
Last accessed: 2019-04-25 08:43:02 UTC+0000
URL: Administrator@file:///C:/Documents%20and%20Settings/Administrator/Lhb/flag.png
**************************************************
Process: 1992 explorer.exe
Cache type "URL " at 0x1875000
Record length: 0x100
Location: Visited: Administrator@file:///C:/Documents%20and%20Settings/Administrator/????/flag.png
Last modified: 2019-04-25 08:43:00 UTC+0000
Last accessed: 2019-04-25 08:43:00 UTC+0000
File Offset: 0x100, Data Offset: 0x0, Data Length: 0xc4
**************************************************
Process: 1992 explorer.exe
Cache type "URL " at 0x1875100
Record length: 0x100
Location: Visited: Administrator@about:Home
Last modified: 2006-01-30 08:25:51 UTC+0000
Last accessed: 2006-01-30 08:25:51 UTC+0000
File Offset: 0x100, Data Offset: 0x0, Data Length: 0x8c
**************************************************
Process: 1992 explorer.exe
Cache type "URL " at 0x1ce5000
Record length: 0x100
Location: :2019042520190426: Administrator@file:///C:/Documents%20and%20Settings/Administrator/????/flag.png
Last modified: 2019-04-25 16:43:00 UTC+0000
Last accessed: 2019-04-25 08:43:00 UTC+0000
File Offset: 0x100, Data Offset: 0x0, Data Length: 0x0
**************************************************
Process: 1992 explorer.exe
Cache type "URL " at 0x1ce5100
Record length: 0x100
Location: :2019042520190426: Administrator@:Host: ????????
Last modified: 2019-04-25 16:43:00 UTC+0000
Last accessed: 2019-04-25 08:43:00 UTC+0000
File Offset: 0x100, Data Offset: 0x0, Data Length: 0x0
```

说是IE历史数据，其实文件浏览器本身的历史数据也算是IE历史数据的一部分。

## filescan-内存中的文件数据

~~这个指令的输出太多了，这个建议结合grep指令一起使用~~

```shell
┌──(kali㉿kali)-[~/volatility]
└─$ python vol.py -f /home/kali/memory.img --profile=Win2003SP1x86 filescan|grep "桌面"
Volatility Foundation Volatility Framework 2.6.1
0x000000000012f228      3      1 R--rwd \Device\HarddiskVolume1\Documents and Settings\Administrator\桌面\DumpIt
0x00000000026fb868      1      0 R--r-d \Device\HarddiskVolume1\Documents and Settings\Administrator\桌面\DumpIt\DumpIt.exe
0x000000000484f900      1      0 R--r-- \Device\HarddiskVolume1\Documents and Settings\Administrator\桌面\flag.png
0x0000000005390520      1      1 RW-rw- \Device\HarddiskVolume1\Documents and Settings\Administrator\桌面\DumpIt\WIN2003-STD-VM-20190425-084304.raw
0x00000000054db3f8      3      1 R--rwd \Device\HarddiskVolume1\Documents and Settings\Administrator\桌面
0x000000000588b0e8      1      0 R--rw- \Device\HarddiskVolume1\Documents and Settings\Administrator\桌面\DumpIt\DumpIt.exe
0x00000000059a2e18      1      1 R--rw- \Device\HarddiskVolume1\Documents and Settings\Administrator\桌面\DumpIt
0x0000000006b9c440      1      0 R--rwd \Device\HarddiskVolume1\Documents and Settings\All Users\桌面\desktop.ini
0x0000000006bff2c0      3      1 R--rwd \Device\HarddiskVolume1\Documents and Settings\All Users\桌面
0x00000000071ac3a8      1      0 R--r-d \Device\HarddiskVolume1\Documents and Settings\All Users\桌面\安全配置向导.lnk
```

## dumpfiles-基于位置Dump数据

```shell
┌──(kali㉿kali)-[~/volatility]
└─$ python vol.py -f /home/kali/memory.img --profile=Win2003SP1x86 dumpfiles -Q 0x00000000071ac3a8 -D /home/kali                                                    2 ⨯
Volatility Foundation Volatility Framework 2.6.1
DataSectionObject 0x071ac3a8   None   \Device\HarddiskVolume1\Documents and Settings\All Users\桌面\安全配置向导.lnk
```

## memdump-基于进程Dump数据

```shell
┌──(kali㉿kali)-[~/volatility]
└─$ python vol.py -f /home/kali/memory.img --profile=Win2003SP1x86 memdump -p 1992 -D /home/kali
Volatility Foundation Volatility Framework 2.6.1
************************************************************************
Writing explorer.exe [  1992] to 1992.dmp
```

## dumpregistry-基于位置Dump注册表数据

```shell
┌──(kali㉿kali)-[~/volatility]
└─$ python vol.py -f /home/kali/memory.img --profile=Win2003SP1x86 dumpregistry -o 0x05951a80 -D /home/kali     
Volatility Foundation Volatility Framework 2.6.1
**************************************************
Writing out registry: registry.0x5951a80.-.reg

**************************************************
```

## bigpllos-键盘缓冲区数据

## clipboard-剪贴板数据

```shell
┌──(kali㉿kali)-[~/volatility]
└─$ python vol.py -f /home/kali/memory.img --profile=Win2003SP1x86 clipboard
Volatility Foundation Volatility Framework 2.6.1
Session    WindowStation Format                 Handle Object     Data                                              
---------- ------------- ------------------ ---------- ---------- --------------------------------------------------
```

## mimikatz-密码提取

```shell
┌──(kali㉿kali)-[~/volatility]
└─$ python vol.py -f /home/kali/memory.img --profile=Win2003SP1x86 mimikatz 
Volatility Foundation Volatility Framework 2.6.1
Module   User             Domain           Password                                
-------- ---------------- ---------------- ----------------------------------------P
```

## usbstor-扫描注册表查找插入系统的USB设备

```shell
┌──(kali㉿kali)-[~/volatility]
└─$ python vol.py -f /home/kali/memory.img --profile=Win2003SP1x86 usbstor 
Volatility Foundation Volatility Framework 2.6.1
Reading the USBSTOR Please Wait
USBSTOR Not found in SYSTEM Hive
```

## screenshot-查看窗口信息

```┌──(kali㉿kali)-[~/volatility]shell
┌──(kali㉿kali)-[~/volatility]
└─$ python vol.py -f /home/kali/memory.img --profile=Win2003SP1x86 screenshot -D /home/kali 
Volatility Foundation Volatility Framework 2.6.1
Wrote /home/kali/session_0.Service-0x0-3e7$.Default.png
Wrote /home/kali/session_0.Service-0x0-3e4$.Default.png
Wrote /home/kali/session_0.Service-0x0-3e5$.Default.png
Wrote /home/kali/session_0.SAWinSta.SADesktop.png
Wrote /home/kali/session_0.WinSta0.Default.png
Wrote /home/kali/session_0.WinSta0.Disconnect.png
Wrote /home/kali/session_0.WinSta0.Winlogon.png
```

这个指令看窗口的时候极其好使

## envars-环境变量

```shell
┌──(kali㉿kali)-[~/volatility]
└─$ python vol.py -f /home/kali/memory.img --profile=Win2003SP1x86 envars|grep "DumpIt"   
Volatility Foundation Volatility Framework 2.6.1
    3660 DumpIt.exe           0x00010000 ALLUSERSPROFILE                C:\Documents and Settings\All Users
    3660 DumpIt.exe           0x00010000 APPDATA                        C:\Documents and Settings\Administrator\Application Data
    3660 DumpIt.exe           0x00010000 ClusterLog                     C:\WINDOWS\Cluster\cluster.log
    3660 DumpIt.exe           0x00010000 CommonProgramFiles             C:\Program Files\Common Files
    3660 DumpIt.exe           0x00010000 COMPUTERNAME                   WIN2003-STD-VM
    3660 DumpIt.exe           0x00010000 ComSpec                        C:\WINDOWS\system32\cmd.exe
    3660 DumpIt.exe           0x00010000 FP_NO_HOST_CHECK               NO
    3660 DumpIt.exe           0x00010000 HOMEDRIVE                      C:
    3660 DumpIt.exe           0x00010000 HOMEPATH                       \Documents and Settings\Administrator
    3660 DumpIt.exe           0x00010000 LOGONSERVER                    \\WIN2003-STD-VM
    3660 DumpIt.exe           0x00010000 NUMBER_OF_PROCESSORS           1
    3660 DumpIt.exe           0x00010000 OS                             Windows_NT
    3660 DumpIt.exe           0x00010000 Path                           C:\WINDOWS\system32;C:\WINDOWS;C:\WINDOWS\System32\Wbem
    3660 DumpIt.exe           0x00010000 PATHEXT                        .COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH
    3660 DumpIt.exe           0x00010000 PROCESSOR_ARCHITECTURE         x86
    3660 DumpIt.exe           0x00010000 PROCESSOR_IDENTIFIER           x86 Family 6 Model 60 Stepping 3, GenuineIntel
    3660 DumpIt.exe           0x00010000 PROCESSOR_LEVEL                6
    3660 DumpIt.exe           0x00010000 PROCESSOR_REVISION             3c03
    3660 DumpIt.exe           0x00010000 ProgramFiles                   C:\Program Files
    3660 DumpIt.exe           0x00010000 SESSIONNAME                    Console
    3660 DumpIt.exe           0x00010000 SystemDrive                    C:
    3660 DumpIt.exe           0x00010000 SystemRoot                     C:\WINDOWS
    3660 DumpIt.exe           0x00010000 TEMP                           C:\DOCUME~1\ADMINI~1\LOCALS~1\Temp
    3660 DumpIt.exe           0x00010000 TMP                            C:\DOCUME~1\ADMINI~1\LOCALS~1\Temp
    3660 DumpIt.exe           0x00010000 USERDOMAIN                     WIN2003-STD-VM
    3660 DumpIt.exe           0x00010000 USERNAME                       Administrator
    3660 DumpIt.exe           0x00010000 USERPROFILE                    C:\Documents and Settings\Administrator
    3660 DumpIt.exe           0x00010000 windir                         C:\WINDOWS
```
