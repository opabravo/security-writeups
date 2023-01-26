# security-writeups

Some security research during the internship at GSS corp.

Plus some writeups of Hack The Box CTFs in my spare time.

## GSS Internship

- [DVWA (Damn Vulnerable Web Application)](./gss/DVWA.md)
- [Metasploit Practice](./gss/metasploit.md)
- [WebAp Penetration Testing](./gss/WebAp-PT.md)
- Zimbra
  - [How To Setup Zimbra CTF](https://medium.com/@opabravo/frist-time-deploying-a-ctf-challenge-c13871d45970)
  - [Zimbra CTF Writeup : Sneaky Way (Manually)](https://medium.com/@opabravo/zimbra-ctf-writeup-manually-6afe91be52a0)
  - [Zimbra CTF 說明](./gss/Zimbra-CTF-Intro.pdf)
  - [Zimbra CVE Reproduce](./gss/Zimbra.pdf)

## Hack The Box

Hack The Box is an online platform allowing you to test your penetration testing skills and exchange ideas and methodologies with other members of similar interests.

### Goal

I am doing a self-challenge:

- 2 Machines a week
- 3 challenges a week

### Password

Active machine writeups/walkthroughs are encrypted with passwords, due to Hack The Box's rules.

Password is the flag(root) from the machine/challenge!

- Example: `HTB{flag}`

### Machine Writeup/Walkthrough

- [Soccer](./htb/Machines/Soccer.pdf)
- [UpDown](./htb/Machines/Updown.pdf)
- [Photobomb](./htb/Machines/Photobomb.pdf)
- [Shoppy](./htb/Machines/Shoppy.pdf)

### Challenges Writeup/Walkthrough

- [A Nightmare On Math Street](./htb/Challenges/A-Nightmare-On-Math-Street.pdf)

## Try Hack Me

TryHackMe is an online platform to learn and practice ethical hacking.

### Script

> [thm.py](./thm/thm.py)

I wrote a script to renew tryhackme machine automatically.

It will generate SSH command to let me quckly connect to the machine.

I usually add `-D 1080` to open socks5 proxy for burp suite or proxychains to access labs, very useful!

#### `thm.py` Demo

![THM Script](./img/thm_script.png)

#### SSH Command with Port Forwarding

```bash
sshpass -p 319175dd4bf50537 ssh root@52.30.170.133 -o "StrictHostKeyChecking no" -D 1080
```
