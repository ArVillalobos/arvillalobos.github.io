---
title: "Windows Event Logs & Finding Evil"
date: 2024-03-09 13:25:30 +/-TTTT
categories: [SOC Analyst]
tags: []     # TAG names should always be lowercase
---

**Windows System Logs**
    
    - [Event ID 1074](https://serverfault.com/questions/885601/windows-event-codes-for-startup-shutdown-lock-unlock) `(System Shutdown/Restart)`: This event log indicates when and why the system was shut down or restarted. By monitoring these events, you can determine if there are unexpected shutdowns or restarts, potentially revealing malicious activity such as malware infection or unauthorized user access.
    - [Event ID 6005](https://superuser.com/questions/1137371/how-to-find-out-if-windows-was-running-at-a-given-time) `(The Event log service was started)`: This event log marks the time when the Event Log Service was started. This is an important record, as it can signify a system boot-up, providing a starting point for investigating system performance or potential security incidents around that period. It can also be used to detect unauthorized system reboots.
    - [Event ID 6006](https://learn.microsoft.com/en-us/answers/questions/235563/server-issue) `(The Event log service was stopped)`: This event log signifies the moment when the Event Log Service was stopped. It is typically seen when the system is shutting down. Abnormal or unexpected occurrences of this event could point to intentional service disruption for covering illicit activities.
    - [Event ID 6013](https://serverfault.com/questions/885601/windows-event-codes-for-startup-shutdown-lock-unlock) `(Windows uptime)`: This event occurs once a day and shows the uptime of the system in seconds. A shorter than expected uptime could mean the system has been rebooted, which could signify a potential intrusion or unauthorized activities on the system.
    - [Event ID 7040](https://www.slideshare.net/Hackerhurricane/finding-attacks-with-these-6-events) `(Service status change)`: This event indicates a change in service startup type, which could be from manual to automatic or vice versa. If a crucial service's startup type is changed, it could be a sign of system tampering.
**Windows Security Logs**
    
    - [Event ID 1102](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=1102) `(The audit log was cleared)`: Clearing the audit log is often a sign of an attempt to remove evidence of an intrusion or malicious activity.
    - [Event ID 1116](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/troubleshoot-microsoft-defender-antivirus?view=o365-worldwide) `(Antivirus malware detection)`: This event is particularly important because it logs when Defender detects a malware. A surge in these events could indicate a targeted attack or widespread malware infection.
    - [Event ID 1118](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/troubleshoot-microsoft-defender-antivirus?view=o365-worldwide) `(Antivirus remediation activity has started)`: This event signifies that Defender has begun the process of removing or quarantining detected malware. It's important to monitor these events to ensure that remediation activities are successful.
    - [Event ID 1119](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/troubleshoot-microsoft-defender-antivirus?view=o365-worldwide) `(Antivirus remediation activity has succeeded)`: This event signifies that the remediation process for detected malware has been successful. Regular monitoring of these events will help ensure that identified threats are effectively neutralized.
    - [Event ID 1120](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/troubleshoot-microsoft-defender-antivirus?view=o365-worldwide) `(Antivirus remediation activity has failed)`: This event is the counterpart to 1119 and indicates that the remediation process has failed. These events should be closely monitored and addressed immediately to ensure threats are effectively neutralized.
    - [Event ID 4624](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=4624) `(Successful Logon)`: This event records successful logon events. This information is vital for establishing normal user behavior. Abnormal behavior, such as logon attempts at odd hours or from different locations, could signify a potential security threat.
    - [Event ID 4625](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=4625) `(Failed Logon)`: This event logs failed logon attempts. Multiple failed logon attempts could signify a brute-force attack in progress.
    - [Event ID 4648](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=4648) `(A logon was attempted using explicit credentials)`: This event is triggered when a user logs on with explicit credentials to run a program. Anomalies in these logon events could indicate lateral movement within a network, which is a common technique used by attackers.
    - [Event ID 4656](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=4656) `(A handle to an object was requested)`: This event is triggered when a handle to an object (like a file, registry key, or process) is requested. This can be a useful event for detecting attempts to access sensitive resources.
    - [Event ID 4672](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=4672) `(Special Privileges Assigned to a New Logon)`: This event is logged whenever an account logs on with super user privileges. Tracking these events helps to ensure that super user privileges are not being abused or used maliciously.
    - [Event ID 4698](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=4698) `(A scheduled task was created)`: This event is triggered when a scheduled task is created. Monitoring this event can help you detect persistence mechanisms, as attackers often use scheduled tasks to maintain access and run malicious code.
    - [Event ID 4700](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=4700) & [Event ID 4701](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=4701) `(A scheduled task was enabled/disabled)`: This records the enabling or disabling of a scheduled task. Scheduled tasks are often manipulated by attackers for persistence or to run malicious code, thus these logs can provide valuable insight into suspicious activities.
    - [Event ID 4702](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=4702) `(A scheduled task was updated)`: Similar to 4698, this event is triggered when a scheduled task is updated. Monitoring these updates can help detect changes that may signify malicious intent.
    - [Event ID 4719](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=4719) `(System audit policy was changed)`: This event records changes to the audit policy on a computer. It could be a sign that someone is trying to cover their tracks by turning off auditing or changing what events get audited.
    - [Event ID 4738](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=4738) `(A user account was changed)`: This event records any changes made to user accounts, including changes to privileges, group memberships, and account settings. Unexpected account changes can be a sign of account takeover or insider threats.
    - [Event ID 4771](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=4771) `(Kerberos pre-authentication failed)`: This event is similar to 4625 (failed logon) but specifically for Kerberos authentication. An unusual amount of these logs could indicate an attacker attempting to brute force your Kerberos service.
    - [Event ID 4776](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=4776) `(The domain controller attempted to validate the credentials for an account)`: This event helps track both successful and failed attempts at credential validation by the domain controller. Multiple failures could suggest a brute-force attack.
    - [Event ID 5001](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/troubleshoot-microsoft-defender-antivirus?view=o365-worldwide) `(Antivirus real-time protection configuration has changed)`: This event indicates that the real-time protection settings of Defender have been modified. Unauthorized changes could indicate an attempt to disable or undermine the functionality of Defender.
    - [Event ID 5140](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=5140) `(A network share object was accessed)`: This event is logged whenever a network share is accessed. This can be critical in identifying unauthorized access to network shares.
    - [Event ID 5142](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=5142) `(A network share object was added)`: This event signifies the creation of a new network share. Unauthorized network shares could be used to exfiltrate data or spread malware across a network.
    - [Event ID 5145](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=5145) `(A network share object was checked to see whether client can be granted desired access)`: This event indicates that someone attempted to access a network share. Frequent checks of this sort might indicate a user or a malware trying to map out the network shares for future exploits.
    - [Event ID 5157](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=5157) `(The Windows Filtering Platform has blocked a connection)`: This is logged when the Windows Filtering Platform blocks a connection attempt. This can be helpful for identifying malicious traffic on your network.
    - [Event ID 7045](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=7045) `(A service was installed in the system)`: A sudden appearance of unknown services might suggest malware installation, as many types of malware install themselves as services.


```xml
<QueryList>  
<Query Id="0">  
<Select Path="Security">  
*[EventData[Data[@Name='SubjectUserName'] and (Data='test9')]]  
</Select>  
</Query>  
</QueryList>
```

```xml
<QueryList>
<Query Id="0">
<Select Path="Security">
(*[EventData[Data[@Name='SubjectUserName']='test5']]
or
*[EventData[Data[@Name='SubjectUserName']='test9')]])
and
*[System[(EventID='4663')]]
</Select>
</Query>
</QueryList>
```

## Sysmon

```shell-session
C:\Tools\Sysmon> sysmon.exe -i -accepteula -h md5,sha256,imphash -l -n
```

To utilize a custom Sysmon configuration, execute the following after installing Sysmon.

```shell-session
C:\Tools\Sysmon> sysmon.exe -c filename.xml
```

Podemos usar esto para filtrar del 1 al 99, dll es el número 7 y algún ejecutable como mimikatz sería 10.

## WinEvent

```powershell
PS C:\Users\Administrator> Get-WinEvent -ListLog * | Select-Object LogName, RecordCount, IsClassicLog, IsEnabled, LogMode, LogType | Format-Table -AutoSize

LogName                                                                                RecordCount IsClassicLog IsEnabled  LogMode        LogType
-------                                                                                ----------- ------------ ---------  -------        -------
Windows PowerShell                                                                            2916         True      True Circular Administrative
System                                                                                        1786         True      True Circular Administrative
Security                                                                                      8968         True      True Circular Administrative
Key Management Service                                                                           0         True      True Circular Administrative
Internet Explorer                                                                                0         True      True Circular Administrative
HardwareEvents                                                                                   0         True      True Circular Administrative
Application                                                                                   2079         True      True Circular Administrative
Windows Networking Vpn Plugin Platform/OperationalVerbose                                                 False     False Circular    Operational
Windows Networking Vpn Plugin Platform/Operational                                                        False     False Circular    Operational
SMSApi                                                                                           0        False      True Circular    Operational
Setup                                                                                           16        False      True Circular    Operational
OpenSSH/Operational                                                                              0        False      True Circular    Operational
OpenSSH/Admin                                                                                    0        False      True Circular Administrative
Network Isolation Operational                                                                             False     False Circular    Operational
Microsoft-WindowsPhone-Connectivity-WiFiConnSvc-Channel                                          0        False      True Circular    Operational
Microsoft-Windows-WWAN-SVC-Events/Operational                                                    0        False      True Circular    Operational
Microsoft-Windows-WPD-MTPClassDriver/Operational                                                 0        False      True Circular    Operational
Microsoft-Windows-WPD-CompositeClassDriver/Operational                                           0        False      True Circular    Operational
Microsoft-Windows-WPD-ClassInstaller/Operational                                                 0        False      True Circular    Operational
Microsoft-Windows-Workplace Join/Admin                                                           0        False      True Circular Administrative
Microsoft-Windows-WorkFolders/WHC                                                                0        False      True Circular    Operational
Microsoft-Windows-WorkFolders/Operational                                                        0        False      True Circular    Operational
Microsoft-Windows-Wordpad/Admin                                                                           False     False Circular    Operational
Microsoft-Windows-WMPNSS-Service/Operational                                                     0        False      True Circular    Operational
Microsoft-Windows-WMI-Activity/Operational                                                     895        False      True Circular    Operational
Microsoft-Windows-wmbclass/Trace                                                                          False     False Circular    Operational
Microsoft-Windows-WLAN-AutoConfig/Operational                                                    0        False      True Circular    Operational
Microsoft-Windows-Wired-AutoConfig/Operational                                                   0        False      True Circular    Operational
Microsoft-Windows-Winsock-WS2HELP/Operational                                                    0        False      True Circular    Operational
Microsoft-Windows-Winsock-NameResolution/Operational                                                      False     False Circular    Operational
Microsoft-Windows-Winsock-AFD/Operational                                                                 False     False Circular    Operational
Microsoft-Windows-WinRM/Operational                                                            230        False      True Circular    Operational
Microsoft-Windows-WinNat/Oper                                                                             False     False Circular    Operational
Microsoft-Windows-Winlogon/Operational                                                         648        False      True Circular    Operational
Microsoft-Windows-WinINet-Config/ProxyConfigChanged                                              2        False      True Circular    Operational
--- SNIP ---
```

```powershell
PS C:\Users\Administrator> Get-WinEvent -ListProvider * | Format-Table -AutoSize

Name                                                                       LogLinks
----                                                                       --------
PowerShell                                                                 {Windows PowerShell}
Workstation                                                                {System}
WMIxWDM                                                                    {System}
WinNat                                                                     {System}
Windows Script Host                                                        {System}
Microsoft-Windows-IME-OEDCompiler                                          {Microsoft-Windows-IME-OEDCompiler/Analytic}
Microsoft-Windows-DeviceSetupManager                                       {Microsoft-Windows-DeviceSetupManager/Operat...
Microsoft-Windows-Search-ProfileNotify                                     {Application}
Microsoft-Windows-Eventlog                                                 {System, Security, Setup, Microsoft-Windows-...
Microsoft-Windows-Containers-BindFlt                                       {Microsoft-Windows-Containers-BindFlt/Operat...
Microsoft-Windows-NDF-HelperClassDiscovery                                 {Microsoft-Windows-NDF-HelperClassDiscovery/...
Microsoft-Windows-FirstUX-PerfInstrumentation                              {FirstUXPerf-Analytic}
--- SNIP ---
```

```powershell
PS C:\Users\Administrator> Get-WinEvent -LogName 'System' -MaxEvents 50 | Select-Object TimeCreated, ID, ProviderName, LevelDisplayName, Message | Format-Table -AutoSize

TimeCreated            Id ProviderName                             LevelDisplayName Message
-----------            -- ------------                             ---------------- -------
6/2/2023 9:41:42 AM    16 Microsoft-Windows-Kernel-General         Information      The access history in hive \??\C:\Users\Administrator\AppData\Local\Packages\MicrosoftWindows.Client.CBS_cw5...
6/2/2023 9:38:32 AM    16 Microsoft-Windows-Kernel-General         Information      The access history in hive \??\C:\Users\Administrator\AppData\Local\Packages\Microsoft.Windows.ShellExperien...
6/2/2023 9:38:32 AM 10016 Microsoft-Windows-DistributedCOM         Warning          The machine-default permission settings do not grant Local Activation permission for the COM Server applicat...
6/2/2023 9:37:31 AM    16 Microsoft-Windows-Kernel-General         Information      The access history in hive \??\C:\Users\Administrator\AppData\Local\Packages\Microsoft.WindowsAlarms_8wekyb3...
6/2/2023 9:37:31 AM    16 Microsoft-Windows-Kernel-General         Information      The access history in hive \??\C:\Users\Administrator\AppData\Local\Packages\microsoft.windowscommunications...
6/2/2023 9:37:31 AM    16 Microsoft-Windows-Kernel-General         Information      The access history in hive \??\C:\Users\Administrator\AppData\Local\Packages\Microsoft.Windows.ContentDelive...
6/2/2023 9:36:35 AM    16 Microsoft-Windows-Kernel-General         Information      The access history in hive \??\C:\Users\Administrator\AppData\Local\Packages\Microsoft.YourPhone_8wekyb3d8bb...
6/2/2023 9:36:32 AM    16 Microsoft-Windows-Kernel-General         Information      The access history in hive \??\C:\Users\Administrator\AppData\Local\Packages\Microsoft.AAD.BrokerPlugin_cw5n...
6/2/2023 9:36:30 AM    16 Microsoft-Windows-Kernel-General         Information      The access history in hive \??\C:\Users\Administrator\AppData\Local\Packages\Microsoft.Windows.Search_cw5n1h...
6/2/2023 9:36:29 AM    16 Microsoft-Windows-Kernel-General         Information      The access history in hive \??\C:\Users\Administrator\AppData\Local\Packages\Microsoft.Windows.StartMenuExpe...
6/2/2023 9:36:14 AM    16 Microsoft-Windows-Kernel-General         Information      The access history in hive \??\C:\Users\Administrator\AppData\Local\Microsoft\Windows\UsrClass.dat was clear...
6/2/2023 9:36:14 AM    16 Microsoft-Windows-Kernel-General         Information      The access history in hive \??\C:\Users\Administrator\ntuser.dat was cleared updating 2366 keys and creating...
6/2/2023 9:36:14 AM  7001 Microsoft-Windows-Winlogon               Information      User Logon Notification for Customer Experience Improvement Program	
6/2/2023 9:33:04 AM    16 Microsoft-Windows-Kernel-General         Information      The access history in hive \??\C:\Windows\AppCompat\Programs\Amcache.hve was cleared updating 920 keys and c...
6/2/2023 9:31:54 AM    16 Microsoft-Windows-Kernel-General         Information      The access history in hive \??\C:\Windows\ServiceProfiles\NetworkService\AppData\Local\Microsoft\Windows\Del...
6/2/2023 9:30:23 AM    16 Microsoft-Windows-Kernel-General         Information      The access history in hive \??\C:\Windows\System32\config\COMPONENTS was cleared updating 54860 keys and cre...
6/2/2023 9:30:16 AM    15 Microsoft-Windows-Kernel-General         Information      Hive \SystemRoot\System32\config\DRIVERS was reorganized with a starting size of 3956736 bytes and an ending...
6/2/2023 9:30:10 AM  1014 Microsoft-Windows-DNS-Client             Warning          Name resolution for the name settings-win.data.microsoft.com timed out after none of the configured DNS serv...
6/2/2023 9:29:54 AM  7026 Service Control Manager                  Information      The following boot-start or system-start driver(s) did not load: ...
6/2/2023 9:29:54 AM 10148 Microsoft-Windows-WinRM                  Information      The WinRM service is listening for WS-Management requests. ...
6/2/2023 9:29:51 AM 51046 Microsoft-Windows-DHCPv6-Client          Information      DHCPv6 client service is started
--- SNIP ---
```

```powershell
PS C:\Users\Administrator> Get-WinEvent -LogName 'Microsoft-Windows-WinRM/Operational' -MaxEvents 30 | Select-Object TimeCreated, ID, ProviderName, LevelDisplayName, Message | Format-Table -AutoSize

TimeCreated            Id ProviderName            LevelDisplayName Message
-----------            -- ------------            ---------------- -------
6/2/2023 9:30:15 AM   132 Microsoft-Windows-WinRM Information      WSMan operation Enumeration completed successfully
6/2/2023 9:30:15 AM   145 Microsoft-Windows-WinRM Information      WSMan operation Enumeration started with resourceUri...
6/2/2023 9:30:15 AM   132 Microsoft-Windows-WinRM Information      WSMan operation Enumeration completed successfully
6/2/2023 9:30:15 AM   145 Microsoft-Windows-WinRM Information      WSMan operation Enumeration started with resourceUri...
6/2/2023 9:29:54 AM   209 Microsoft-Windows-WinRM Information      The Winrm service started successfully
--- SNIP ---
```

To retrieve the oldest events, instead of manually sorting the results, we can utilize the -Oldest parameter with the Get-WinEvent cmdlet. This parameter allows us to retrieve the first events based on their chronological order. The following command demonstrates how to retrieve the oldest 30 events from the 'Microsoft-Windows-WinRM/Operational' log.

```powershell
PS C:\Users\Administrator> Get-WinEvent -LogName 'Microsoft-Windows-WinRM/Operational' -Oldest -MaxEvents 30 | Select-Object TimeCreated, ID, ProviderName, LevelDisplayName, Message | Format-Table -AutoSize

TimeCreated           Id ProviderName            LevelDisplayName Message
-----------            -- ------------            ---------------- -------
8/3/2022 4:41:38 PM  145 Microsoft-Windows-WinRM Information      WSMan operation Enumeration started with resourceUri ...
8/3/2022 4:41:42 PM  254 Microsoft-Windows-WinRM Information      Activity Transfer
8/3/2022 4:41:42 PM  161 Microsoft-Windows-WinRM Error            The client cannot connect to the destination specifie...
8/3/2022 4:41:42 PM  142 Microsoft-Windows-WinRM Error            WSMan operation Enumeration failed, error code 215085...
8/3/2022 9:51:03 AM  145 Microsoft-Windows-WinRM Information      WSMan operation Enumeration started with resourceUri ...
8/3/2022 9:51:07 AM  254 Microsoft-Windows-WinRM Information      Activity Transfer
```

Retrieve with files

```powershell
PS C:\Users\Administrator> Get-WinEvent -Path 'C:\Tools\chainsaw\EVTX-ATTACK-SAMPLES\Execution\exec_sysmon_1_lolbin_pcalua.evtx' -MaxEvents 5 | Select-Object TimeCreated, ID, ProviderName, LevelDisplayName, Message | Format-Table -AutoSize

TimeCreated           Id ProviderName             LevelDisplayName Message
-----------           -- ------------             ---------------- -------
5/12/2019 10:01:51 AM  1 Microsoft-Windows-Sysmon Information      Process Create:...
5/12/2019 10:01:50 AM  1 Microsoft-Windows-Sysmon Information      Process Create:...
5/12/2019 10:01:43 AM  1 Microsoft-Windows-Sysmon Information      Process Create:...
```

Con esto podemos hacer un filtro con id, este mismo es el que se usa en sysmon

```powershell
PS C:\Users\Administrator> Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; ID=1,3} | Select-Object TimeCreated, ID, ProviderName, LevelDisplayName, Message | Format-Table -AutoSize

TimeCreated           Id ProviderName             LevelDisplayName Message
-----------           -- ------------             ---------------- -------
6/2/2023 10:40:09 AM   1 Microsoft-Windows-Sysmon Information      Process Create:...
6/2/2023 10:39:01 AM   1 Microsoft-Windows-Sysmon Information      Process Create:...
6/2/2023 10:34:12 AM   1 Microsoft-Windows-Sysmon Information      Process Create:...
6/2/2023 10:33:26 AM   1 Microsoft-Windows-Sysmon Information      Process Create:...
6/2/2023 10:33:16 AM   1 Microsoft-Windows-Sysmon Information      Process Create:...
6/2/2023 9:36:10 AM    3 Microsoft-Windows-Sysmon Information      Network connection detected:...
5/29/2023 6:30:26 PM   1 Microsoft-Windows-Sysmon Information      Process Create:...
5/29/2023 6:30:24 PM   3 Microsoft-Windows-Sysmon Information      Network connection detected:...
```

```powershell
PS C:\Users\Administrator> Get-WinEvent -FilterHashtable @{Path='C:\Tools\chainsaw\EVTX-ATTACK-SAMPLES\Execution\sysmon_mshta_sharpshooter_stageless_meterpreter.evtx'; ID=1,3} | Select-Object TimeCreated, ID, ProviderName, LevelDisplayName, Message | Format-Table -AutoSize

TimeCreated           Id ProviderName             LevelDisplayName Message
-----------           -- ------------             ---------------- -------
6/15/2019 12:14:32 AM  1 Microsoft-Windows-Sysmon Information      Process Create:...
6/15/2019 12:13:44 AM  3 Microsoft-Windows-Sysmon Information      Network connection detected:...
6/15/2019 12:13:42 AM  1 Microsoft-Windows-Sysmon Information      Process Create:...
```

POR FECHAS

```powershell
 PS C:\Users\Administrator> $startDate = (Get-Date -Year 2023 -Month 5 -Day 28).Date
 PS C:\Users\Administrator> $endDate   = (Get-Date -Year 2023 -Month 6 -Day 3).Date
 PS C:\Users\Administrator> Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; ID=1,3; StartTime=$startDate; EndTime=$endDate} | Select-Object TimeCreated, ID, ProviderName, LevelDisplayName, Message | Format-Table -AutoSize

 TimeCreated           Id ProviderName             LevelDisplayName Message
-----------           -- ------------             ---------------- -------
6/2/2023 3:26:56 PM    1 Microsoft-Windows-Sysmon Information      Process Create:...
6/2/2023 3:25:20 PM    1 Microsoft-Windows-Sysmon Information      Process Create:...
6/2/2023 3:25:20 PM    1 Microsoft-Windows-Sysmon Information      Process Create:...
6/2/2023 3:24:13 PM    1 Microsoft-Windows-Sysmon Information      Process Create:...
6/2/2023 3:24:13 PM    1 Microsoft-Windows-Sysmon Information      Process Create:...
6/2/2023 3:23:41 PM    1 Microsoft-Windows-Sysmon Information      Process Create:...
6/2/2023 3:20:27 PM    1 Microsoft-Windows-Sysmon Information      Process Create:...
6/2/2023 3:20:26 PM    1 Microsoft-Windows-Sysmon Information      Process Create:...
--- SNIP ---
```
