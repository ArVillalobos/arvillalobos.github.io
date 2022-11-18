e---
title: Attacking Common Services
date: 2022-08-12 13:25:30 +/-TTTT
categories: [UTILITIES]
tags: []     # TAG names should always be lowercase
---
En este apartado estaremos viendo los principales servicios que uno se puede encontrar al realizar un pentesting, una lista de ejemplos serían

|Categoría|	Aplicaciones|
|:--------|-----------------|
|Gestión de contenidos web|	Joomla, Drupal, WordPress, DotNetNuke, etc.|
|Servidores de aplicaciones|	Apache Tomcat, Phusion Passenger, Oracle WebLogic, IBM WebSphere, etc.|
|Información de Seguridad y Gestión de Eventos (SIEM)|	Splunk, Trustwave, LogRhythm, etc.|
|Administración de redes|	PRTG Network Monitor, ManageEngine Opmanger, etc.|
|Gestión de TI|	Nagios, Puppet, Zabbix, ManageEngine ServiceDesk Plus, etc.|
|Marcos de software|	JBoss, Axis2, etc.|
|Gestión de Atención al Cliente|	osTicket, Zendesk, etc.|
|Los motores de búsqueda|	Elasticsearch, Apache Solr, etc.|
|Gestión de configuración de software|	Atlassian JIRA, GitHub, GitLab, Bugzilla, Bugsnag, Bitbucket, etc.|
|Herramientas de desarrollo de software|	Jenkins, Atlassian Confluence, phpMyAdmin, etc.|
|Integración de aplicaciones empresariales|	Oracle Fusion Middleware, BizTalk Server, Apache ActiveMQ, etc.|

Lo primero es idenfiticar los servicios que se tienen corriendo en el servidor, para eso se puede utilizar `EyeWitness` y `Aquatone`, para eso le pasamos el archivo xml que obtuvimos de nmap
para eso podríamos usar los puertos de los servicios más comunes.

```shell
nmap -p 80,443,8000,8080,8180,8888,1000 --open -oA web_discovery -iL scope_list
sudo nmap -p 80,443,8000,8080,8180,8888,1000 --open -oA web_discovery -iL hosts
Starting Nmap 7.92 ( https://nmap.org ) at 2022-11-05 21:02 CST
Nmap scan report for app.inlanefreight.local (10.129.42.195)
Host is up (0.16s latency).
Not shown: 6 closed tcp ports (reset)
PORT   STATE SERVICE
80/tcp open  http

Nmap scan report for dev.inlanefreight.local (10.129.42.195)
Host is up (0.16s latency).
rDNS record for 10.129.42.195: app.inlanefreight.local
Not shown: 6 closed tcp ports (reset)
PORT   STATE SERVICE
80/tcp open  http

Nmap scan report for drupal-dev.inlanefreight.local (10.129.42.195)
Host is up (0.16s latency).
rDNS record for 10.129.42.195: app.inlanefreight.local
Not shown: 6 closed tcp ports (reset)
PORT   STATE SERVICE
80/tcp open  http

Nmap scan report for drupal-qa.inlanefreight.local (10.129.42.195)
Host is up (0.16s latency).
rDNS record for 10.129.42.195: app.inlanefreight.local
Not shown: 6 closed tcp ports (reset)
PORT   STATE SERVICE
80/tcp open  http
```
```shell
eyewitness --web -x web_discovery.xml -d inlanefreight_eyewitness

################################################################################
#                                  EyeWitness                                  #
################################################################################
#           FortyNorth Security - https://www.fortynorthsecurity.com           #
################################################################################

Starting Web Requests (26 Hosts)
Attempting to screenshot http://app.inlanefreight.local
Attempting to screenshot http://app-dev.inlanefreight.local
Attempting to screenshot http://app-dev.inlanefreight.local:8000
Attempting to screenshot http://app-dev.inlanefreight.local:8080
```
![imagen1](/assets/images/Academy/services.png)

Y luego tenemos aquatone

```shell
cat ../web_discovery.xml | ./aquatone -nmap
aquatone v1.7.0 started at 2022-11-05T21:18:22-06:00

Targets    : 15
Threads    : 8
Ports      : 80, 443, 8000, 8080, 8443
Output dir : .

http://drupal-dev.inlanefreight.local/: 200 OK
http://drupal-acc.inlanefreight.local/: 200 OK
http://app.inlanefreight.local/: 200 OK
http://app.inlanefreight.local/: 200 OK
http://app.inlanefreight.local/: 200 OK
http://blog.inlanefreight.local/: 200 OK
http://app.inlanefreight.local/: 200 OK
http://app.inlanefreight.local/: 200 OK
http://drupal-qa.inlanefreight.local/: 200 OK
http://app.inlanefreight.local/: 200 OK
http://dev.inlanefreight.local/: 200 OK
```
![imagen2](/assets/images/Academy/services2.png)

## Wordpress

Es importante saber aspectos de wordpress como plugins y temas ya que podemos obtener vulnerabilidades de ellas

```shell
$ curl -s http://blog.inlanefreight.local/ | grep themes
$ curl -s http://blog.inlanefreight.local/ | grep plugins
```

Haciendo una recapitulación de lo que se puede obtener, sería muy útil hacer una lista

- El sitio parece estar ejecutando WordPress core versión 5.8
- El tema instalado es Business Gravity
- Los siguientes complementos están en uso: Formulario de contacto 7, mail-masta, wpDiscuz
- La versión de wpDiscuz parece ser 7.0.4, que sufre una vulnerabilidad de ejecución remota de código no autenticado
- La versión de mail-masta parece ser 1.0.0, que sufre una vulnerabilidad de inclusión de archivo local
- El sitio de WordPress es vulnerable a la enumeración de usuarios y adminse confirma que el usuario es un usuario válido

Otra herramienta muy útil sería wpscan, para hacer uso de esta necesitamos una wp token que se obtiene de WPVulnDB

```shell
$ wpscan -h

_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.7
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

Usage: wpscan [options]
        --url URL                                 The URL of the blog to scan
                                                  Allowed Protocols: http, https
                                                  Default Protocol if none provided: http
                                                  This option is mandatory u
```
```shell
sudo wpscan --url http://blog.inlanefreight.local --enumerate --api-token dEOFB<SNIP>

<SNIP>

[+] URL: http://blog.inlanefreight.local/ [10.129.42.195]
[+] Started: Thu Sep 16 23:11:43 2021

Interesting Finding(s):

[+] Headers
 | Interesting Entry: Server: Apache/2.4.41 (Ubuntu)
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://blog.inlanefreight.local/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access

[+] WordPress readme found: http://blog.inlanefreight.local/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] Upload directory has listing enabled: http://blog.inlanefreight.local/wp-content/uploads/
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
```

Para enumerar usuarios de forma agresiva

```shell
 sudo wpscan --url 'http://blog.inlanefreight.local' -e u aggressive --api-token mLzoqbswF7hPHdaXKL5KyscJtTW3Or6ljQLZsQ3ptMg
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.21
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[+] URL: http://blog.inlanefreight.local/ [10.129.110.175]
[+] Started: Sun Nov  6 00:27:09 2022

Interesting Finding(s):

[+] Headers
 | Interesting Entry: Server: Apache/2.4.41 (Ubuntu)
 | Found By: Headers (Passive Detection)


## PARA BRUTEFORCEAR EL PASSWORD

$ sudo wpscan --password-attack xmlrpc -t 20 -U john -P /usr/share/wordlists/rockyou.txt --url http://blog.inlanefreight.local

[+] URL: http://blog.inlanefreight.local/ [10.129.42.195]
[+] Started: Wed Aug 25 11:56:23 2021

<SNIP>

[+] Performing password attack on Xmlrpc against 1 user/s
[SUCCESS] - john / firebird1                                                                                           
Trying john / bettyboop Time: 00:00:13 <                                      > (660 / 14345052)  0.00%  ETA: ??:??:??

[!] Valid Combinations Found:
 | Username: john, Password: firebird1

[!] No WPVulnDB API Token given, as a result vulnerability data has not been output.
[!] You can get a free API token with 50 daily requests by registering at https://wpvulndb.com/users/sign_up

```
Dentro de wordpress podemos modificar el tema 404.php para tener ejecución remmota de comandos.


## Joomla

Podemos enumerar manualmente lo que tiene joomla con:

```shell
$ curl -s http://dev.inlanefreight.local/ | grep Joomla

	<meta name="generator" content="Joomla! - Open Source Content Management" />


<SNIP>

$ curl -s http://dev.inlanefreight.local/administrator/manifests/files/joomla.xml | xmllint --format -

<?xml version="1.0" encoding="UTF-8"?>
<extension version="3.6" type="file" method="upgrade">
  <name>files_joomla</name>
  <author>Joomla! Project</author>
  <authorEmail>admin@joomla.org</authorEmail>
  <authorUrl>www.joomla.org</authorUrl>
  <copyright>(C) 2005 - 2019 Open Source Matters. All rights reserved</copyright>
  <license>GNU General Public License version 2 or later; see LICENSE.txt</license>
  <version>3.9.4</version>
  <creationDate>March 2019</creationDate>
  
 <SNIP>

```
Podemos usar la herramienta `droopscan` o  `joomlascan`

```shell
droopescan scan joomla --url http://dev.inlanefreight.local/

[+] Possible version(s):                                                        
    3.8.10
    3.8.11
    3.8.11-rc
    3.8.12
    3.8.12-rc
    3.8.13
    3.8.7
    3.8.7-rc
    3.8.8
    3.8.8-rc
    3.8.9
    3.8.9-rc

[+] Possible interesting urls found:
    Detailed version information. - http://dev.inlanefreight.local/administrator/manifests/files/joomla.xml
    Login page. - http://dev.inlanefreight.local/administrator/
    License file. - http://dev.inlanefreight.local/LICENSE.txt
    Version attribute contains approx version - http://dev.inlanefreight.local/plugins/system/cache/cache.xml

[+] Scan finished (0:00:01.523369 elapsed)
```
JOOMLASCAN

```shell
python2.7 joomlascan.py -u http://dev.inlanefreight.local

-------------------------------------------
      	     Joomla Scan                  
   Usage: python joomlascan.py <target>    
    Version 0.5beta - Database Entries 1233
         created by Andrea Draghetti       
-------------------------------------------
Robots file found: 	 	 > http://dev.inlanefreight.local/robots.txt
No Error Log found

Start scan...with 10 concurrent threads!
Component found: com_actionlogs	 > http://dev.inlanefreight.local/index.php?option=com_actionlogs
	 On the administrator components
Component found: com_admin	 > http://dev.inlanefreight.local/index.php?option=com_admin
	 On the administrator components
Component found: com_ajax	 > http://dev.inlanefreight.local/index.php?option=com_ajax
	 But possibly it is not active or protected
	 LICENSE file found 	 > http://dev.inlanefreight.local/administrator/components/com_actionlogs/actionlogs.xml
	 LICENSE file found 	 > http://dev.inlanefreight.local/administrator/components/com_admin/admin.xml
	 LICENSE file found 	 > http://dev.inlanefreight.local/administrator/components/com_ajax/ajax.xml
```
Para hacer bruteforce para logearnos podemos usar 

```shell
$ sudo python3 joomla-brute.py -u http://dev.inlanefreight.local -w /usr/share/metasploit-framework/data/wordlists/http_default_pass.txt -usr admin
 
admin:admin
```
Dentro del CMS podemos entrar al apartado de templates y al igual que wordpress modificar uno para que nos mandemos una reverse shell.

## Drupal

Podemos usar la misma herramienta que en joomla para recopilar información de este cms

```shell
$ droopescan scan drupal -u http://drupal.inlanefreight.local

[+] Plugins found:                                                              
    php http://drupal.inlanefreight.local/modules/php/
        http://drupal.inlanefreight.local/modules/php/LICENSE.txt

[+] No themes found.

[+] Possible version(s):
    8.9.0
    8.9.1

[+] Possible interesting urls found:
    Default admin - http://drupal.inlanefreight.local/user/login

[+] Scan finished (0:03:19.199526 elapsed)
```
## Splunk

Para esta aplicación podemos crear un archivo que pueda interpretar por ejemplo.

```shell
$ tree splunk_shell/

splunk_shell/
├── bin
└── default

2 directories, 0 files
```
Podemos descargarnos el molde en esta repo `https://github.com/0xjpuff/reverse_shell_splunk` solo hay que hacerle unas modificaciones al payload. Y terminando creamos un archivo spl

```shell
$ tar -cvzf updater.tar.gz splunk_shell/

splunk_shell/
splunk_shell/bin/
splunk_shell/bin/rev.py
splunk_shell/bin/run.bat
splunk_shell/bin/run.ps1
splunk_shell/default/
splunk_shell/default/inputs.conf
```
Instalamos desde un archivos, nos ponemos en escucha y presionamos upload.


