*These notes will come handy in exam.*

# Perimeter Defense - Email Security

## Email Spoofing

### SPF - Sender Policy Framework

Check the SPF records of the domain name by checking its DNS TXT records,

```bash
dig <domain> TXT | grep spf
```

#### Mechanisms

Mechanisms display the IP being matched and prefixed with Qualifiers that state what action should be taken if that mechanism (i.e., IP address) is matched. 

| **Mechanism** |        **Example SPF Record**        |                                      **Explanation**                                      |
|:-------------:|:------------------------------------:|:-----------------------------------------------------------------------------------------:|
|      ip4      |     `v=spf1 ip4:10.0.0.1/24`     |                    Authorized server IPs are in the 10.0.0.1/24 range                     |
|       a       |      `v=spf1 a:example.com`      |            Authorized servers' IPs are in the DNS **A** record of example.com             |
|      mx       |     `v=spf1 mx:example.com`      | Authorized servers IPs are the IPs of the servers in the DNS **MX** record of example.com |
|    include    | `v=spf1 include:_spf.domain.com` |  Authorized servers' IPs are in another SPF/TXT record (`_spf.domain.com` in that case)   |
|      all      |           `v=spf1 all`           |                           Authorized servers' IPs match any IP.                           |

#### Qualifiers

Each of the above mechanisms should be prefixed with a qualifier to state the action upon matching the provided IP. 

| **Qualifier** |    **Example SPF Record**     |                             **Explanation**                             |                                  **Action**                                  |
|:-------------:|:-----------------------------:|:-----------------------------------------------------------------------:|:----------------------------------------------------------------------------:|
|   + (pass)    | `v=spf1 +ip4:10.0.0.1/24` |   Pass SPF check If the sender server IP is in the 10.0.0.1/24 range    |              Accept the message (This is an authentic message)               |
|   - (fail)    | `v=spf1 -ip4:10.0.0.1/24` |   Fail SPF check If the sender server IP is in the 10.0.0.1/24 range    |                Reject the message (This is a spoofed message)                |
| ~ (softfail)  | `v=spf1 ~ip4:10.0.0.1/24` | SoftFail SPF checks If the sender server IP is in the 10.0.0.1/24 range | Accept the message but flag it as spam or junk (probably a spoofed message). |
|? (neutral)|`v=spf1 ?ip4:10.0.0.1/24`|Neither pass nor fail If the sender server IP is in the 10.0.0.1/24 range|Accept the message (Not sure whether this is a spoofed or authentic message)|

### DKIM - DomainKeys Identified Mail

DKIM records have a standard format of 

```md
<selector>._domainkey.<domain>.
```

For example, the DKIM public key for cyberdefenders.org is published at  

```md
google._domainkey.cyberdefenders.org
```

and can be queried using  

```bash
dig google._domainkey.cyberdefenders.org TXT | grep DKIM
```

### DMARC - Domain-based Message Authentication, Reporting & Conformance

DMARC records are published as TXT records in the DNS server, just like DKIM and SPF. To check the DMARC record for a domain, we query the DNS server for `_dmarc.<domain>`,

```bash
dig _dmarc.nsa.gov TXT | grep dmarc
```

#### DMARC Record Creation

##### Monitor Mode

To start monitoring and collecting all sending servers, we only need to create a DMARC record with the policy set to **none** and publish it in the DNS server, 

```md
v=DMARC1; p=none; rua=mailto:dmarc-inbox@yourdomain.com
```

##### Receiving Mode

The receiving server/report generators will have to verify that the service provider is waiting for your reports to come by querying the DMARC record at,

```bash
dig <your-company.com>._report._dmarc.<service-provider.com> | grep dmarc
```

---

## Analyzing Artifacts

1. **Visualization Tools** - [URL2PNG](https://www.url2png.com/), [URLScan](https://urlscan.io/), [AbuseIPDB](https://www.abuseipdb.com/), [Criminalip.io](https://www.criminalip.io/en), [ThreatBook.io](https://threatbook.io/), [IPQuality Score](https://www.ipqualityscore.com/), 
2. **URL Reputation Tools** - [VirusTotal](https://www.virustotal.com/gui/), [URLScan](https://urlscan.io/), [URLhaus](https://urlhaus.abuse.ch/), [WannaBrowser](https://www.wannabrowser.net/)
3. **File Reputation Tools** - [VirusTotal](https://www.virustotal.com/gui/), [Talos File Reputation](https://www.talosintelligence.com/talos_file_reputation)
4. **Malware Sandboxing** - [Hybrid Analysis](https://www.hybrid-analysis.com/), [Any.run](https://any.run/), [VirusTotal](https://www.virustotal.com/), [Joe Sandbox](https://www.joesandbox.com/), [Tri.ge](https://tria.ge/).

---
---

# Digital Forensics

## Acquisition

### Memory Acquisition

#### Linux

Determine the kernel version on a Linux machine, you can use the command 

```bash
uname -a
```

Download [LiME](https://github.com/504ensicsLabs/LiME),

```bash
sudo apt update && sudo apt install build-essential git
git clone https://github.com/504ensicsLabs/LiME.git
cd LiME/src/
make
```

Capture memory using LiME,

```bash
sudo insmod ./lime.ko "path=/home/user/Desktop/dump.mem format=lime timout=0" 
```

#### Windows

We can use various tools like [FTK Imager](https://www.exterro.com/ftk-imager), [Belkasoft](https://belkasoft.com/ram-capturer), [DumpIt](http://www.toolwar.com/2014/01/dumpit-memory-dump-tools.html).

### Checking Disk Encryption

Use a command line tool called "[Encrypted Disk Detector](https://www.magnetforensics.com/resources/encrypted-disk-detector/),"  to detect encrypted drives. 

```powershell
.\EDDv310.exe
```

### Triage Image Acquisition

1. Obtaining Triage Image with [KAPE](https://www.kroll.com/en/insights/publications/cyber/kroll-artifact-parser-extractor-kape) is convenient. 
2. Another tool [CyLR](https://github.com/orlikoski/CyLR), which can acquire triage images on Windows, Linux, and OSX systems. It comes with a list of essential artifacts to collect from each system.

### Disk Acquisition

#### Windows

Using [FTK Imager](https://www.exterro.com/ftk-imager), Disk Images can be acquired. 

#### Linux

**Note: Do not run `dd` on the host system; run it from an external drive and save the output image to the same drive.**

First, determine all mounted disks, and we will specifically choose one of them to image,

```bash
df -h
```

Now, proceed to the acquisition,

```bash
sudo dd if=/dev/sb1 of=/home/user/Desktop/file.img bs=512
```

### Mounting

To mount different image types, use [Arsenal Image Mounter](https://arsenalrecon.com/), [FTK Imager](https://www.exterro.com/ftk-imager).

---

## Windows Disk Forensics

### Windows Event Logs

By default, Windows Event Logs are stored at '`C:\Windows\system32\winevt\logs`' as **.evtx** files.

We can use [Event log explorer](https://eventlogxp.com/) or [Full Event Log view](https://www.nirsoft.net/utils/full_event_log_view.html).

### Artifacts

By default, Windows Event Logs are stored at '`C:\Windows\system32\winevt\logs`' as **.evtx** files.

#### Important Artifacts

|**Live System**|**Dead System**|**Investigation Tool**|
|:---:|:---:|:---:|
|HKEY_LOCAL_MACHINE/SYSTEM|`C:\Windows\System32\config\SYSTEM`|Registry Explorer/RegRipper|
|HKEY_LOCAL_MACHINE/SOFTWARE|`C:\Windows\System32\config\SOFTWARE`|Registry Explorer/RegRipper|
|HKEY_USERS|`C:\Windows\System32\config\SAM`|Registry Explorer/RegRipper|
|HKEY_CURRENT_USER|`C:\Users<USER>\NTUSER.dat` `C:\Users<user>\Local Settings\Application Data\Microsoft\Windows\UsrClass.dat`|Registry Explorer/RegRipper|
|Amcache.hve|`C:\Windows\appcompat\Programs\Amcache.hve`|Registry Explorer/RegRipper|
|Event Viewer -> Windows Logs -> SECURITY|`C:\Windows\winevt\Logs\Security.evtx`|Event logs Explorer|
|Event Viewer -> Windows Logs -> SYSTEM|`C:\Windows\winevt\Logs\SYSTEM.evtx`|Event logs Explorer|
|Event Viewer -> Windows Logs -> Application|`C:\Windows\winevt\Logs\Application.evtx`|Event logs Explorer|
|Event viewer -> Applications & service logs -> Microsoft -> Windows -> TaskScheduler -> Operational|`Microsoft-Windows-TaskScheduler%4Operational.evtx`|Event logs Explorer|

#### System Information

|**What To Look For**|**Where To Find It**|**Investigation Tool**|
|:---:|:---:|:---:|
|Windows version and installation date|`SOFTWARE\Microsoft\Windows NT\CurrentVersion`|Registry Explorer/RegRipper|
|Computer Name|`SYSTEM\ControlSet001\Control\ComputerName\ComputerName`|Registry Explorer/RegRipper|
|Timezone|`SYSTEM\ControlSet001\Control\TimeZoneInformation`|Registry Explorer/RegRipper|

#### Network Information

|**What To Look For**|**Where To Find It**|**Investigation Tool**|
|:---:|:---:|:---:|
|Identify physical cards|`SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkCards`|Registry Explorer/RegRipper|
|Identify interface configuration|`SYSTEM\ControlSet001\Services\Tcpip\Parameters\Interfaces`|Registry Explorer/RegRipper|
|Connections History|`SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Unmanaged` `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles` `Microsoft-Windows-WLAN-AutoConfig%4Operational.evtx`|WifiHistoryView|

#### Users Information

|**What To Look For**|**Where To Find It**|**Investigation Tool**|
|:---:|:---:|:---:|
|Username, creation date ,login date, SID|SAM|Registry Explorer/RegRipper|
|Login, logout, deletion, creation|Security.evtx|Event Log Explorer|
||4624 -> Successful logon event|
||4625 -> failed logon event|
||4634 -> Session terminated|
||4647 -> User initiated logoff|
||4672 -> Special privilege logon|
||4648 -> User run program as another user (Runas administrator)|
||4720/4726 -> Account creation/deletion|

#### File Activities - What happened?

|**What To Look For**|**Where To Find It**|**Investigation Tool**|
|:---:|:---:|:---:|
|File name, path, timestamps, actions (i.e rename)|`$MFT, $LogFile, $UsnJrnl:$J`|NTFS Log Tracker|
|Information about deleted files|`$I30`|INDXRipper|

#### File Activities - Who did it?

|**What To Look For**|**Where To Find It**|**Investigation Tool**|
|:---:|:---:|:---:|
|Failed/Succesful object access|Securit.evtx|Event Log Explorer|
||4656 -> User tried to access an object||
||4660 -> object was deleted||
||4663 -> User accessed the object successfully||
||4658 -> the user closed the opened object (file)||
|Recently used files/folders|NTUSER.dat|Registry Explorer/RegRipper|
||`Software\Microsoft\Office\15.0<Office application>\File MRU`||
||`Software\Microsoft\Office\15.0<Office application>\Place MRU`||
||`Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU\*`||
||`Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs`||
||`Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU`||
||`Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths`||
|Accessed folders|ShellBags|ShellBags Explorer|
||NTUSER.dat||
||USRCLASS.dat||
|Accessed files, its path, metadata, timestamps, drive letter|LNK files|LECmd|
||`C:\Users<User>\Appdata\Roaming\Microsoft\Windows\Recent`||
||`C:\Users<User>\Desktop`||
||`C:\Users<User>\AppData\Roaming\Microsoft\Office\Recent\`||
|Frequently accessed files|JumpLists|JumpLists Explorer|
||`C:\Users<User>\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations`||
||`C:\Users<User>\AppData\Roaming\Microsoft\ Windows\Recent\CustomDestinations`||
|Recover Deleted Files from Recycle Bin|`INFO2/$I`|RBCmd|

#### Connected Devices

|**What To Look For**|**Where To Find It**|**Investigation Tool**|
|:---:|:---:|:---:|
|Vendor ID, Product ID, Serial Number, Device name|`SYSTEM\ControlSet001\Enum\USB`|Registry Explorer/RegRipper|
|Serial Number, First connection time, last connection time, last removal time|`SYSTEM\ControlSet001\USBSTOR`|Registry Explorer/RegRipper|
|USB Label|`SYSTEM\ControlSet001\Enum\SWD\WPDBUSENUM`|Registry Explorer/RegRipper|
|GUID, TYPE, serial number|`SYSTEM\ControlSet001\Control\DeviceClasses`|Registry Explorer/RegRipper|
|VolumeGUID, Volume letter, serial number|`SYSTEM\MountedDevices` `SOFTWARE\Microsoft\Windows Portable Devices\Devices` `SOFTWARE\Microsoft\Windows Search\VolumeInfoCache`|Registry Explorer/RegRipper|
|Serial number, first connection time|`setupapi.dev.log`|notepad++|
|Serial number, connections times, drive letter|**SYSTEM.evtx**: 20001 -> a new device is installed|Event Log Explorer|
||**Security.evtx**: 6416 -> new externel device recognized||
||Microsoft-Windows-Ntfs%4Operational.evtx||
|Automation|Registry|USBDeviceForenics, USBDetective|
||Event Logs||
||setupapi.dev.log||

#### Execution Activities

|**What To Look For**|**Where To Find It**|**Investigation Tool**|
|:---:|:---:|:---:|
|Windows Services executable, date added|`SYSTEM\CurrentControlSet\Services`|Registry Explorer/RegRipper|
|Service installation time, Service crashed, stop/start service event|**Security.evtx**: 4697 -> service gets installed|Event Log Explorer|
||**SYSTEM.evtx**: 7034 -> Service crashed||
||7035 -> start/stop requests||
||7036 -> service stoppped/started||
|Autorun applications|`SOFTWARE\Microsoft\Windows\CurrentVersion\Run`|Registry Explorer/RegRipper|
||`SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`||
||`SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run`||
||`SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce`||
||`NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Run`||
||`NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\RunOnce`||
|Frequently run programs, last time, number of execution|UserAssist|UserAssist by Didier Steven|
||`NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist`||
|Run of older applications on newer system|`SYSTEM\CurrentControlSet\Control\SessionManager\AppCompatCache\AppCompatCache`|ShimCache Parser|
|Files path, md5 & sha1 hash|`Amcache.hve`|Amcache Parser|
|Background applications|`BAM & DAM`|Registry Explorer/RegRipper|
||`SYSTEM\ControlSet001\Services\bam\State\UserSettings`||
|Filename, size, run count, each run timestamp, path|`Prefetch`|WinPrefetchView|
||`C:\Windows\Prefetch`||
|Program network usage, memory usage|`SRUM`|SrumECmd|
||`C:\Windows\System32\sru\SRUDB.dat`||
|Scheduled task|`C:\Windows\Tasks`|Task Scheduler Viewer|
||`Software\Microsoft\Windows NT\CurrentVersion\Schedule\Taskcache\Tasks`||
||`Software\Microsoft\Windows NT\CurrentVersion\Schedule\Taskcache\Tree`||
||`Microsoft-Windows-TaskScheduler%4Operational.evtx`||

---

## Windows Memory Forensics with Volatility

### Image Identification

#### imageinfo Plugin

To determine the profile of an image,

```bash
python vol.py -f memory.dmp imageinfo
```

#### kdbgscan Plugin

To determine the kdbg signature of an image, first ran the command,

```bash
python vol.py -f memory.dmp imageinfo
```

Then identify the profile to be used later in the process, and use the plugin,

```bash
python vol.py -f memory.dmp --profile=<profile> kdbgscan
```

Determine the KdCopyDataBlock offset as we will use it in the next step with any other plugin, *let us say `pslist`*,

```bash
python vol.py -f memory.dmp --profile=<profile> -g <offset> pslist
```

### Processes and DLLs

#### pslist Plugin

To determine the process in the memory dump,

```bash
python vol.py -f memory.dmp --profile=<profile> -g <offset> pslist
```

#### psscan Plugin

To enumerate processes using pool tag scanning,

```bash
python vol.py -f memory.dmp --profile=<profile> -g <offset> psscan
```

#### dlllist Plugin

To display a process's loaded DLLs,

```bash
python vol.py -f memory.dmp --profile=<profile> -g <offset> dlllist
```

To display the process's loaded DLLs of a particular process with PID XXXX,

```bash
python vol.py -f memory.dmp --profile=<profile> -g <offset> dlllist -p XXXX
```

#### pstree Plugin

To determine the parent-child process like which process is the parent process and which process is the child process,

```bash
python vol.py -f memory.dmp --profile=<profile> -g <offset> pstree
```

Use verbose mode of the `pstree` plugin to list detailed information,

```bash
python vol.py -f memory.dmp --profile=<profile> -g <offset> pstree -v
```

#### psxview Plugin

To find the hidden processes that are concealed from standard processes,

```bash
python vol.py -f memory.dmp --profile=<profile> -g <offset> psxview
```

#### psinfo Plugin

To find the detailed process information,

```bash
python vol.py -f memory.dmp --profile=<profile> -g <offset> psinfo -o <process_offset>
```

#### getsids plugin

To find the process privileges and identify the SIDs of the users,

```bash
python vol.py -f memory.dmp --profile=<profile> -g <offset> getsids -o <process_offset>
```

#### handles Plugin

To find open handles in a process,

```bash
python vol.py -f memory.dmp --profile=<profile> -g <offset> handles
```

To find open handles of a particular process with PID XXXX,

```bash
python vol.py -f memory.dmp --profile=<profile> -g <offset> handles -p XXXX
```

#### privs Plugin

To display which process privileges are present, enabled, and/or enabled by default,

```bash
python vol.py -f memory.dmp --profile=<profile> -g <offset> privs
```

#### consoles Plugin

To detect the commands that attackers typed into cmd.exe,

```bash
python vol.py -f memory.dmp --profile=<profile> -g <offset> consoles
```

#### cmdscan Plugin

To detect the commands that attackers entered through a console shell, cmd.exe.

```bash
python vol.py -f memory.dmp --profile=<profile> -g <offset> cmdscan
```

#### ldrmodules Plugin

To list the DLLs in WoW64 processes,

```bash
python vol.py -f memory.dmp --profile=<profile> -g <offset> ldrmodules
```

### Networking

#### netscan Plugin

To find the network-relevant information,

```bash
python vol.py -f memory.dmp --profile=<profile> -g <offset> netscan
```

#### connscan Plugin

To detect connections that have since been terminated, or active ones,

```bash
python vol.py -f memory.dmp --profile=<profile> -g <offset> connscan
```

### Registry 

#### hivelist Plugin

To list all registry hives in memory, their virtual space along with the full path, use the following plugin,

```bash
python vol.py -f memory.dmp --profile=<profile> -g <offset> hivelist
```

#### printkey Plugin

To detect the persistence techniques in Registry key, utilize the following plugin,

```bash
python vol.py -f memory.dmp --profile=<profile> -g <offset> printkey -K <registry-key>
```

#### winesap Plugin

To automate the inspecting persistence-related registry keys, utilize the following plugin,

```bash
volatility -f <memory_dump> --profile=<profile> -g <offset> winesap
```

Use the following parameter to display suspicious entries,

```bash
volatility -f <memory_dump> --profile=<profile> -g <offset> winesap --match
```

### File System

#### mftparser Plugin

To extract MFT entries in memory, utilize the following plugin,

```bash
volatility -f <memory_dump> --profile=<profile> -g <offset> mftparser
```

### Process Memory

#### procdump Plugin

To dump the process's executable of a particular process with PID XXXX,

```bash
python vol.py -f memory.dmp --profile=<profile> -g <offset> procdump -p XXXX --dump-dir=/<output-directory>
```

#### memdump Plugin

To dump the memory resident pages of a particular process with PID XXXX,

```bash
python vol.py -f memory.dmp --profile=<profile> -g <offset> memdump -p XXXX --dump-dir=/<output-directory>
```

#### vaddump Plugin

To extract the range of pages described by a VAD node,

```bash
python vol.py -f memory.dmp --profile=<profile> -g <offset> vaddump --dump-dir=/<output-directory>
```

### Kernel Memory and Objects

#### filescan Plugin

To find all the files in the physical memory,

```bash
python vol.py -f memory.dmp --profile=<profile> -g <offset> filescan
```

### Miscellaneous

#### volshell Plugin

Interactively explore an image,

```bash
python vol.py -f memory.dmp --profile=<profile> -g <offset> volshell
```

#### timeliner Plugin

To create a timeline from various artifacts in memory from the following sources,

```bash
python vol.py -f memory.dmp --profile=<profile> -g <offset> timeliner
```

#### malfind Plugin

To find the hidden or injected DLLs in the memory,

```bash
volatility -f <memory_dump> --profile=<profile> -g <offset> malfind
```

#### yarscan Plugin

To locate any sequence of bytes, or determine the malicious nature of a process with PID XXXX, provided we have included the rule (yara rule file) we created, 

```bash
volatility -f <memory_dump> --profile=<profile> -g <offset> yarascan -y rule.yar -P XXXX
```

---
---

# Threat Hunting

#### Elastic Common Schema (ECS)

|Field|Description|KQL Examples|
|:---:|:---:|:---:|
|event.category|It looks for similar events from various data sources that can be grouped together for viewing or analysis.|event.category: authentication|
|||event.category: process|
|||event.category: network|
|||event.category: (malware or intrusion_detection)|
|event.type|It serves as a sub-categorization that, when combined with the "event.category" field, allows for filtering events to a specific level.|event.type: start|
|||event.type: creation|
|||event.type: access|
|||event.type: deletion|
|event.outcome|It indicates whether the event represents a successful or a failed outcome|event.outcome: success|
|||event.outcome : failure|

#### Common search fields

|Field|Description|KQL Examples|
|:---:|:---:|:---:|
|@timestamp|@timestamp: 2023-01-26|Events that happened in 26th|
||@timestamp <= "2023-01-25"|Events that happened with a date less than or equal to 25th of Jan|
||@timestamp >= "2023-01-26" and @timestamp <= "2023-01-27"|Events that happened between 26th and the 27th of Jan|
|agent.name|agent.name: `DESKTOP-*`|Look for events from the agent name that starts with DESKTOP|
|message|message: powershell|Look for any message with the word powershell|

#### Process Related Fields

|Field|Description|KQL Examples|
|:---:|:---:|:---:|
|process.name|`event.category: process and process.name: powershell.exe`|Look for powershell.exe as a process|
|process.command_line|`event.category: process and process.command_line.text:*whoami*`|Look for a commandline that has whoami on it|
|process.pid|`event.category: process and process.pid: 6360`|Look for process id: 6360|
|process.parent.name|`event.category: process and process.parent.name: cmd.exe`|Looks for cmd.exe as a parent process|
|process.parent.pid|`host.name: DESKTOP-* and event.category: process and process.command_line.text: powershell and process.parent.pid: 12620`|Looks for a process command line that has powershell and the parent process id is 12620 on a hostname that starts with DESKTOP|

#### Network related fields

|Field|Description|KQL Examples|
|:---:|:---:|:---:|
|source.ip|`source.ip: 127.0.0.1`|Looks for any logs originated from the loopback IP address|
|destination.ip|`destination.ip: 23.194.192.66`|Looks for any logs originating to IP 23.194.192.66|
|destination.port|`destination.port: 443`|Looks for any logs originating towards port 443|
|dns.question.name|`dns.question.name: "www.youtube.com"`|Look for any DNS resolution towards www.youtube.com|
|dns.response_code|`dns.response_code: "NXDOMAIN"`|Looks for DNS traffic towards non existing domain names|
|destination.geo.country_name|`destination.geo.country_name: "Canada"`|Looks for any outbound traffic toward Canada|

#### Authentication related fields

|Field|Description|KQL Examples|
|:---:|:---:|:---:|
|user.name|`event.category: "authentication" and user.name: administrator and event.outcome: failure`|Looks for failed login attempt targeting username administrator|
|winlog.logon.type|`event.category : "authentication" and winlog.logon.type: "Network"`|Look for authentication that happened over the network|
||`event.category : "authentication" and winlog.logon.type: "RemoteInteractive"`|Look for RDP authentication|
|winlog.event_data.AuthenticationPackageName|`event.category : "authentication" and event.action: logged-in and winlog.logon.type: "Network" and user.name.text: administrator and event.outcome: success and winlog.event_data.AuthenticationPackageName: NTLM`|Look for successful network authentication events against the user administrator, and the  authentication package is NTLM.|

---

## Endpoint Threat Hunting

Detecting Persistence using Scheduled Tasks,

```kql
technique_id=T1053,technique_name=Scheduled Task
```

Detect PsExec Activity in the Network,

```kql
event.code: 1 and process.name.text: psexec*
```

Detecting Mimikatz Activity in Network,

```kql
event.code: 10 and winlog.event_data.TargetImage: *\\lsass.exe
```

---

## Network Threat Hunting

To detect data exfiltration through DNS,

```kql
agent.type: "packetbeat" and type: dns AND not dns.response_code: "NOERROR"
```

---
---

# Few Commands for quick start

### Eric Zimmerman Tools

#### MFTCmd

Extract the `$MFT` file from the `C:\$MFT` directory,

```cmd
MFTECmd.exe -f "/path/to/$MFT" --csv "<output-directory>" --csvf results.csv
```

#### PECmd

Extract the Prefetch directory from the `C:\Windows\Prefetch` path using FTK Imager,

```cmd
PECmd.exe -f "/path/to/Prefetch" --csv "<output-directory>" --csvf results.csv
```

#### LECmd

Extract the LNK file(s) from `C:\Users\$USER$\AppData\Roaming\Microsoft\Windows\Recent` using FTK Imager,

```cmd
LECmd.exe -f "C:\Users\user\AppData\Roaming\Microsoft\Windows\Recent\file.lnk"
```

#### RBCmd

Restore the deleted file from the Recycle Bin,

```cmd
RBCmd.exe -f "path/to/file" --csv "<output-directory>" --csvf results.csv
```

#### WxtCmd

Analyze the Timeline database and parse it into a CSV file using WxtCmd. The file can be found at `C:\Users<user>\AppData\Local\ConnectedDevicesPlatform\<user>\ActivitiesCache.db`

```cmd
WxTCmd.exe -f "C:\Users<user>\AppData\Local\ConnectedDevicesPlatform\<user>\ActivitiesCache.db" --csv "C:\Users\<user>\Desktop" --csvf results.csv
```

#### Amcache Parser

Parsing the AmCache.hve file to identify any suspicious entries or determine the malicious nature. The file can be found at `C:\Windows\appcompat\Programs\Amcache.hve`

```cmd
AmcacheParser.exe -f "C:\Windows\appcompat\Programs\Amcache.hve" --csv "C:\Users\<user>\Desktop\" --csvf results.csv
```

#### SrumECmd

Parse the SRUDB.dat file to find the system resource usage, network and process, etc. The file can be found at `C:\Windows\System32\sru\SRUDB.dat`

```cmd
SrumECmd.exe -f "C:\Users\Administrator\Desktop\SRUDB.dat" --csv "C:\Users\<user>\Desktop\" --csvf results.csv
```

#### AppCompatCacheParser

To parse the ShimCache from the registry hive,

```cmd
AppCompatCacheParser.exe -f "</path/to/SYSTEM/hive>" --csv "C:\Users\<user>\Desktop\" --csvf results.csv
```

#### ShimCacheParser

Parse the ShimCache with ShimCacheParser,

```bash
python ShimCacheParser.py -i <SYSTEM-hive> -o results.csv
```

### Hashing the files

#### Windows

Utilizing the great PowerShell, we can find the hash of the file,

```powershell
# generate SHA256 hash by-default
get-filehash <file>

# generate MD5 hash
get-filehash -algorithm MD5 <file>

#  generate SHA1 hash
get-filehash -algorithm SHA1 <file>
```

#### Linux

With Linux terminal, we can find the hash of the file,

```bash
# generate MD5 hash
md5sum <file>

# generate SHA1 hash
sha1sum <file>

# generate SHA256 hash
sha256sum <file>
```

### File Extraction and Analysis

Use Binwalk tool to extract the files and analysis,

```bash
binwalk -e <file>
```

### Bulk Extractor

Use bulk_extractor tool to extract the information without parsing file system,

```bash
bulk_extractor -o dump/ memory.dmp
```

### Strings Command

To print the strings of printable characters,

```bash
strings <file>
```

---
---

# Tools Utilized

Here is the list of all the tools utilized during the completion of the Certification. More tools can be added in coming future.

|**Tool Name**|**Resource Link**|**Purpose**|
|:---:|:---:|:---:|
|LiME|https://github.com/504ensicsLabs/LiME|Memory Acquisition on Linux devices.|
|FTK Imager|https://www.exterro.com/ftk-imager|Memory Acquisition on range of devices.|
|Belkasoft|https://belkasoft.com/ram-capturer|Memory Acquisition.|
|DumpIt|http://www.toolwar.com/2014/01/dumpit-memory-dump-tools.html|Memory Acquisition.|
|Encrypted Disk Detector|https://www.magnetforensics.com/resources/encrypted-disk-detector/|Quickly checks for encrypted volumes on a system.|
|KAPE|https://www.kroll.com/en/insights/publications/cyber/kroll-artifact-parser-extractor-kape|Used for fast acquisition of data.|
|CyLR|https://github.com/orlikoski/CyLR|Forensics artifacts collection tool.|
|dd|https://man7.org/linux/man-pages/man1/dd.1.html|Used to create a disk image of a Linux OS.|
|Arsenal Image Mounter|https://arsenalrecon.com/|Used to mount different image types.|
|Event log explorer|https://eventlogxp.com/|Used for Windows event log analysis.|
|Full Event Log view|https://www.nirsoft.net/utils/full_event_log_view.html|Used to display a table that details all events from the event logs of Windows.|
|Volatility|https://www.volatilityfoundation.org/|Used for Memory Analysis.|
|AbuseIPDB|https://www.abuseipdb.com/|Detect abusive activity of IP address.|
|IPQuality Score|https://www.ipqualityscore.com/|checks for IP addresses reputation.|
|Any.run|https://app.any.run/|Malware Sandbox.|
|VirusTotal|https://www.virustotal.com/gui/home/upload|Malware Sandbox.|
|Tri.ge|https://tria.ge/|Malware Sandbox.|
|EZ Tools|https://ericzimmerman.github.io/#!index.md|Set of digital forensics tools.|
|NTFS Log Tracker|https://sites.google.com/site/forensicnote/ntfs-log-tracker|Used to parse `$LogFile`, `$UsnJrnl:$J` of NTFS and carve `UsnJrnl` record in multiple files.|
|UserAssist|https://blog.didierstevens.com/programs/userassist/|Used to display a table of programs executed on a Windows machine, run count, last execution date & time.|
|R-Studio|https://www.r-studio.com/Data_Recovery_Download.shtml|Used to recover lost files.|
|Wireshark|https://www.wireshark.org/|Used for Network Traffic analysis.|
|CobaltStrikeParser|https://github.com/Sentinel-One/CobaltStrikeParser|A python parser for CobaltStrike Beacon's configuration.|
|Suricata|https://suricata.io/|A popular open-source IDS.|
|RITA|https://github.com/activecm/rita|An open source framework for detecting C2 through network traffic analysis.|
|Sysmon|https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon|Windows system service and device driver that logs system activity to Windows Event Log.|
|Velociraptor|https://www.rapid7.com/products/velociraptor/|Used for collecting collect, monitor, and hunt on a single endpoint, a group of endpoints, or an entire network.|
|Gophish|https://getgophish.com/|Open-Source, advanced Phishing Simulation framework.|
|Epoch & Unix Timestamp Conversion Tools|https://www.epochconverter.com/|Convert epoch to human-readable date and vice versa.|
|OSSEC|https://www.ossec.net/|A powerful host-based intrusion detection system.|
|Nessus|https://www.tenable.com/downloads/nessus?loginAttempted=true|Popular Vulnerability Assessment Scanner.|
|Microsoft Sentinel|https://azure.microsoft.com/en-in/products/microsoft-sentinel/|A cloud native SIEM solution|
|Open Threat Exchange (OTX)|https://otx.alienvault.com/|Open Threat Intelligence Community|
|Canary Tokens|https://canarytokens.org/generate|Used for tracking anything.|
|Elastic SIEM|https://www.elastic.co/security/siem|Used for aggregating data, logging, monitoring.|
|Yara|https://virustotal.github.io/yara/|Used my malware researchers to identify and classify malware sample.|
|SQLite Browser|https://sqlitebrowser.org/|A high quality, visual, open source tool to create, design, and edit database files compatible with SQLite.|
|RegRipper|https://github.com/keydet89/RegRipper3.0|Used to surgically extract, translate, and display information from Registry-formatted files via plugins in the form of Perl-scripts.|
|Binwalk|https://github.com/ReFirmLabs/binwalk|Used for for analyzing, reverse engineering, and extracting firmware images.|
|MFTDump.py|https://github.com/mcs6502/mftdump/blob/master/mftdump.py|Used for parsing and displaying Master File Table (MFT) files.|
|Prefetchruncounts.py|https://github.com/dfir-scripts/prefetchruncounts|Used for Parsing and extracting a sortable list of basic Windows Prefetch file information based on "last run" timestamps.|
|parseMFT|https://pypi.org/project/parseMFT/#files|Parse the $MFT from an NTFS filesystem.|
|Brim|https://www.brimdata.io/|Used for network troubleshooting and security incident response.|
|NetworkMiner|https://www.netresec.com/?page=networkminer|Used to extract artifacts, such as files, images, emails and passwords, from captured network traffic in PCAP files.|
|Autopsy|https://www.autopsy.com/download/|Used for analyzing forensically-sound images.|
|Capa-Explorer|https://github.com/mandiant/capa|Used to identify capabilities in executable files.|
|IDA|https://hex-rays.com/ida-free/|Used for Reverse engineering the binary samples.|
|TurnedOnTimesView|https://www.nirsoft.net/utils/computer_turned_on_times.html|Used to analyze the windows event logs and detect time ranges that a computer was turned on.|
|USB Forensic Tracker|http://orionforensics.com/forensics-tools/usb-forensic-tracker|Used to extracts USB device connection artefacts from a range of locations.|
|WinDbg|https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/debugger-download-tools|Used for debugging.|
|Outlook Forensics Wizard|https://forensiksoft.com/outlook-forensics.html|Used to open, search, analyze, & export outlook data files of any size.|
|FakeNet|https://github.com/mandiant/flare-fakenet-ng|Used for dynamic network analysis.|
|oletools|https://github.com/decalage2/oletools|Set of tools used for malware analysis, forensics, and debugging.|
|scdbg|http://sandsprite.com/blogs/index.php?uid=7&pid=152|Used to display to the user all of the Windows API the shellcode attempts to call.|
|Resource Hacker|http://angusj.com/resourcehacker|A freeware resource compiler & decompiler for Windows applications.|
|Hashcat|https://hashcat.net/hashcat/|Used to crack the hashes to obtain plain-text password.|
|John The Ripper|https://www.openwall.com/john/|Used to crack the hashes to obtain plain-text password.|
|Bulk Extractor|https://downloads.digitalcorpora.org/downloads/bulk_extractor/|Used to extract useful information without parsing the file system.|
|jq|https://stedolan.github.io/jq/download|A command line JSON processor|
|AWS-CLI|https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html|Used to interact with AWS via Command Line.|
|HindSight|https://github.com/obsidianforensics/hindsight|Used for Web browser forensics for Google Chrome/Chromium|
|xxd|https://linux.die.net/man/1/xxd|Creates a HEX dump of a file/input|
|ShimCacheParser|https://github.com/mandiant/ShimCacheParser|Used to parse the Application Compatibility Shim Cache stored in the Windows registry|
