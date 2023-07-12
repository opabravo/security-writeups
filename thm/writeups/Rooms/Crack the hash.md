## Level 1
---

https://crackstation.net/

### Hashcat Rules

Hash: `279412f945939ba78ce0758d3fd83daa`

Need to use rules to crack the hash in some cases

Hashcat Rules Dir: `/usr/share/hashcat/rules/`

```bash
┌──(kali㉿kali)-[~/thm]
└─$ echo '279412f945939ba78ce0758d3fd83daa' > hash

┌──(kali㉿kali)-[~/thm]
└─$ hashcat hash /opt/wordlists/rockyou.txt -r /opt/wordlists/OneRuleToRuleThemAll.rule -m 900
```

Another useful rule : 

- `/usr/share/hashcat/rules/best64.rule`

> `279412f945939ba78ce0758d3fd83daa:Eternity22`

## Level 2
---

### Sha-1 With Salt
  
Hash: e5d8870e5bdd26602cab8dbe07a942c8669e56d6

Salt: tryhackme

```bash
┌──(kali㉿kali)-[~]
└─$ hash-identifier e5d8870e5bdd26602cab8dbe07a942c8669e56d6
Possible Hashs:
[+] SHA-1
[+] MySQL5 - SHA-1(SHA-1($pass))
...
```

Looks like the salt is the key, not just appending to hash like this format `sha1($salt.$pass)`

Hashcat requests the following format for known salt hash

```bash
┌──(kali㉿kali)-[~/thm]
└─$ echo 'e5d8870e5bdd26602cab8dbe07a942c8669e56d6:tryhackme' > hash
```

```bash

      # | Name                                                       | Category
  ======+============================================================+======================================
    110 | sha1($pass.$salt)                                          | Raw Hash salted and/or iterated
    120 | sha1($salt.$pass)                                          | Raw Hash salted and/or iterated
   4900 | sha1($salt.$pass.$salt)                                    | Raw Hash salted and/or iterated
   4520 | sha1($salt.sha1($pass))                                    | Raw Hash salted and/or iterated
  24300 | sha1($salt.sha1($pass.$salt))                              | Raw Hash salted and/or iterated
    140 | sha1($salt.utf16le($pass))                                 | Raw Hash salted and/or iterated
   4710 | sha1(md5($pass).$salt)                                     | Raw Hash salted and/or iterated
  21100 | sha1(md5($pass.$salt))                                     | Raw Hash salted and/or iterated
   4510 | sha1(sha1($pass).$salt)                                    | Raw Hash salted and/or iterated
   5000 | sha1(sha1($salt.$pass.$salt))                              | Raw Hash salted and/or iterated
    130 | sha1(utf16le($pass).$salt)                                 | Raw Hash salted and/or iterated
    150 | HMAC-SHA1 (key = $pass)                                    | Raw Hash authenticated
    160 | HMAC-SHA1 (key = $salt)                                    | Raw Hash authenticated
   5800 | Samsung Android Password/PIN                               | Operating System
    121 | SMF (Simple Machines Forum) > v1.1                         | Forums, CMS, E-Commerce
```

Choose `HMAC-SHA1 (key = $salt)`

```bash
hashcat hash /opt/wordlists/rockyou.txt -m 160
```

> `e5d8870e5bdd26602cab8dbe07a942c8669e56d6:tryhackme:481616481616`