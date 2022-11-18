---
title: TheNotebook
date: 2022-07-31 13:25:30 +/-TTTT
categories: [HTB MACHINES, Linux]
tags: []     # TAG names should always be lowercase
---

```shell
$ nmap -sCV -p22,80 10.10.10.230 -oN targeted
Starting Nmap 7.92 ( https://nmap.org ) at 2022-11-05 14:36 CST
Nmap scan report for 10.10.10.230
Host is up (0.086s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 86:df:10:fd:27:a3:fb:d8:36:a7:ed:90:95:33:f5:bf (RSA)
|   256 e7:81:d6:6c:df:ce:b7:30:03:91:5c:b5:13:42:06:44 (ECDSA)
|_  256 c6:06:34:c7:fc:00:c4:62:06:c2:36:0e:ee:5e:bf:6b (ED25519)
80/tcp open  http    nginx 1.14.0 (Ubuntu)
|_http-title: The Notebook - Your Note Keeper
|_http-server-header: nginx/1.14.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.88 seconds
```
Aquí vemos una página donde podemos subir notas de texto, al ir revisando la página vemos que en burpsuite nos encontramos una cookie en formato JWT.

![imagen1](/assets/images/thenotebook/thenotebook1.png)

![imagen2](/assets/images/thenotebook/thenotebook2.png)

Revisando en la página jwt.io vemos que tenemos un payload interesante de admin y un header que llama a una privKey.key localmente. Lo que procedemos a hacer es crear nuestra propia privKey 
apuntando a nuestra máquina.

![imagen3](/assets/images/thenotebook/thenotebook3.png)

```shell
openssl genrsa
Generating RSA private key, 2048 bit long modulus (2 primes)
.....+++++
............................................................+++++
e is 65537 (0x010001)
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAqZcvTTagC3QQTXIpCb+JiKcMC9VPvf7xJXjdrqDuXnQqW0U9
z1SJfvFpZ2NdQcBmE4Yhsnpc5FtG1S2Lq2uxV0jeF6+U4phnOMQxPqrWV56A3SyH
TLTUUS9YYs5FHxYGDz7mYWNhouWYk/O/RGLefZ+ki9XywiFr/fis29zreXDc+xig
jF//p/uDlyWF1wqQKNxvC+0mnUBT8ZtBe9sLNX8xpc9j87jpFr6G3LbkOf9pMQQb
fZW8/j+w3zTnntEteSb9wmVHgK9co3f7wOxZFY1QOmAwvudHfNT/mlXNDGZ5FWIr
Kd3olpGFbo+RliFTEhOm1IoVZCOStleKJMqrNQIDAQABAoIBAE0B8KGwH0Z0In74

<SNIP>
```
![imagen4](/assets/images/thenotebook/thenotebook4.png)

Lo introducimos en el apartado de private key, cambiamos el valor de administrado a 1 y cambiamos el valor de kid a nuestra ip. Dentro del servicio web cambiamos nuestra cookie, montamos un servicio
con python para compartir el archivo y recargamos la página para obtener acceso como administrador.

Dentro encontramos con una panel de administrador donde podemos subir archivos

![imagen5](/assets/images/thenotebook/thenotebook5.png)

Subimos un archivo php sin ningún bypass, nos mandamos una shell y estamos dentro. Adentro nos encontramos con un directorio backups y archivos en formato gzip, hay uno en particular que dice home
lo pasamos a formato base64 para copiarlo a nuestra máquina y así descomprimirlo, dentro del comprimido encontramos un binario, usando strings podemos ver que contiene la id_rsa del usuario 
noah.

```shell
www-data@thenotebook:/var/backups$ ls
apt.extended_states.0	 apt.extended_states.2.gz  home.tar.gz
apt.extended_states.1.gz  apt.extended_states.3.gz
www-data@thenotebook:/var/backups$ gzip -d home.tar.gz 
gzip: home.tar: Permission denied
www-data@thenotebook:/var/backups$ cat home.tar.gz | base64 -w 0
H4sIALrbLGAAA+06aXfa2JL52voVGsenHYdgrSDsHM+0ALHvqyHJ5Gi5QgIhCS2AmLz57VNXAhucdKd7XpbzXlPn2Ei
```
Vemos los permisos SUID que tenemos y vemos que podemos ejecutar comandos dentro del contenedor Docker. No parece útil y no se encontró nada adentro que nos pueda servir, buscamos vulnerabilidades
de la versión del docker que se está utilizando.

```shell
noah@thenotebook:~$ sudo -l
Matching Defaults entries for noah on thenotebook:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User noah may run the following commands on thenotebook:
    (ALL) NOPASSWD: /usr/bin/docker exec -it webapp-dev01*
noah@thenotebook:~$ sudo /usr/bin/docker exec -it webapp-dev01 whoami
root

noah@thenotebook:~$ docker --version
Docker version 18.06.0-ce, build 0ffa825
```
Encontramos un script en github de `Frichetten/CVE-2019-5736-PoC` donde se ve cómo elevar los privilegios.

![imagen6](/assets/images/thenotebook/thenotebook6.png)
