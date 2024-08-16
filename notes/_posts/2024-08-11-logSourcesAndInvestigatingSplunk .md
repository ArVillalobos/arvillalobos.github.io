---
layout: post
title: Log Sources and Investigating with Splunk
related_posts:
  - notes/_posts/2024-06-27-manageSecurityRisks.md
sitemap: false
categories: notes
---

# Log Sources and Investigating with Splunk

* toc
{:toc}

## Basic Searching

Splunk use SPL language that contains houndred of commands, functions, arguments, clauses that help us to make a good search of information. To make our first explicit search we can use. We need to remember for searching in the specific time or range of it that we want to get the information.

```spl
search index="main" "UNKNOWN"
```

Main means that is only gonna search in main index information(Sysmon or Windows Event logs), and "UNKNOWN" means to search for that specific pattern. We can use * to make the search less specific.

Splunk uses a lot of fields data like source, sourcetype, host, eventcode. We can make search with comoparison operators (=, <, >, <=, >=).

```spl
search index="main" EventCode!=1
```

We can use field command to specify which files would included. In this example we are using a filter that give us all the information in index main with sourcetype WinEventLog:Sysmon and Eventcode equal to 1, but excluding the user that is executing the process.

```spl
search index="main" sourceType="WinEventLog:Sysmon" EventCode=1 | fields - User
 ```

We can filter in more tabular way with table

```spl
index="main" sourceType="WinEventLog:Sysmon" EventCode=1 | table _time host Image
```

We can rename some fields with rename

```spl
index="main" sourceType="WinEventLog:Sysmon" EventCode=1 | raname Image as Process
```

We can remove duplicated events:

```spl
index="main" sourcetype="WinEventLog:Sysmon" EventCode=1 | dedup Image
```

We can sort information with sort, this command sort the information in descending or ascending order.

```spl
index="main" sourcetype="WinEventLog:Sysmon" EventCode=1 | sort _time
index="main" sourcetype="WinEventLog:Sysmon" EventCode=1 | sort - _time
```
We can count all the events that match fields that we put in search. For this situation we can use stats or chart function.

```spl
index="main" sourcetype="WinEventLog:Sysmon" EventCode=1 | stats count by _time, Image
index="main" sourcetype="WinEventLog:Sysmon" EventCode=1 | chart count by _time, Image
```

The eval command creates or redifines fields

```spl
index="main" sourcetype="WinEventLog:Sysmon" EventCode=1 | eval Process_path=lower(Image)
```

We can filter for regular expresion

```spl
index="main" EventCode=4662 | rex max_match=0 "[^%](?<guid>{.*})" | table guid
```

We can use lookup files to make search with more matches, for example, you can create a file that lists common malicious files. 

```csv
filename, is_malware
notepad.exe, false
cmd.exe, false
powershell.exe, false
sharphound.exe, true
randomfile.exe, true
```
*  index="main" sourcetype="WinEventLog:Sysmon" EventCode=1: This is the search criteria. It's looking for Sysmon logs (as identified by the sourcetype) with an EventCode of 1 (which represents process creation events) in the "main" index.
* | rex field=Image "(?P<filename>[^\\\]+)$": This command is using the regular expression (regex) to extract a part of the Image field. The Image field in Sysmon EventCode=1 logs typically contains the full file path of the process. This regex is saying: Capture everything after the last backslash (which should be the filename itself) and save it as filename.
* | eval filename=lower(filename): This command is taking the filename that was just extracted and converting it to lowercase. The lower() function is used to ensure the search is case-insensitive.
* | lookup malware_lookup.csv filename OUTPUTNEW is_malware: This command is performing a lookup operation using the filename as a key. The lookup table (malware_lookup.csv) is expected to contain a list of filenames of known malicious executables. If a match is found in the lookup table, the new field is_malware is added to the event, which indicates whether or not the process is considered malicious based on the lookup table. <-- filename in this part of the query is the first column title in the CSV.
* | table filename, is_malware: This command is formatting the output to show only the fields filename and is_malware. If is_malware is not present in a row, it means that no match was found in the lookup table for that filename.


```spl
index="main" sourcetype="WinEventLog:Sysmon" EventCode=1 | rex field=Image "(?P<filename>[^\\\]+)$" | eval filename=lower(filename) | lookup malware.csv filename OUTPUTNEW is_malware | table filename, is_malware 
|  dedup filename
```

To search for a range of time we can use

```spl
index="main" earliest=-7d EventCode!=1
```

```spl
index="main" sourcetype="WinEventLog:Sysmon" (EventCode=1 OR EventCode=3) | transaction Image startswith=eval(EventCode=1) endswith=eval(EventCode=3) maxspan=1m | table Image |  dedup Image 
```

* index="main" sourcetype="WinEventLog:Sysmon" (EventCode=1 OR EventCode=3): This is the search criteria. It's pulling from the main index where the sourcetype is WinEventLog:Sysmon and the EventCode is either 1 or 3. In Sysmon logs, EventCode 1 refers to a process creation event, and EventCode 3 refers to a network connection event.
* | transaction Image startswith=eval(EventCode=1) endswith=eval(EventCode=3) maxspan=1m: The transaction command is used here to group events based on the Image field, which represents the executable or script involved in the event. This grouping is subject to the conditions: the transaction starts with an event where EventCode is 1 and ends with an event where EventCode is 3. The maxspan=1m clause limits the transaction to events occurring within a 1-minute window. The transaction command can link together related events to provide a better understanding of the sequences of activities happening within a system.
* | table Image: This command formats the output into a table, displaying only the Image field.
* | dedup Image: Finally, the dedup command removes duplicate entries from the result set. Here, it's eliminating any duplicate Image values. The command keeps only the first occurrence and removes subsequent duplicates based on the Image field.

This query is gonna help us to find event that have subsequent events, in this example we are looking for events that inicate a process and then maka a network connection.

```spl
index="main" sourcetype="WinEventLog:Sysmon" EventCode=1 NOT [ search index="main" sourcetype="WinEventLog:Sysmon" EventCode=1 | top limit=100 Image | fields Image ] | table _time, Image, CommandLine, User, ComputerName
```
Whith this query we can search some events with event code 1 but excluding the first 100 matches.

## Examples

Find username counts in kerberos authentication tries.

```spl
index="main" EventCode="4768" |  chart count by Account_Name
```

Find through an SPL search against all 4624 events the count of distinct computers accessed by the account name SYSTEM

```spl
index="main" EventCode="4624" Account_Name="SYSTEM" |  chart count by ComputerName
```

We can search for authenticated users in a time span of 10 minutes

```spl
index="*" EventCode=4624 
| stats range(_time) as rango count as total_attempts by Account_Name
| where rango <= 600
| sort - rango
| head 1
```

## Apps

We can use `Sysmon` application by downloading it from splunk website. With this we are able to search of specific information. We need to fix some queries in this app, just map the correct field that you want to serch modifying de default one.

```spl
`sysmon` CommandLine="net  view*" | stats count by ComputerName,CommandLine
```

## Intrusion Detection

* Sysmon Event ID 1 - Process Creation: Useful for hunts targeting abnormal parent-child process hierarchies, as illustrated in the first lesson with Process Hacker. It's an event we can use later.
* Sysmon Event ID 2 - A process changed a file creation time: Helpful in spotting "time stomp" attacks, where attackers alter file creation times. Bear in mind, not all such actions signal malicious intent.
* Sysmon Event ID 3 - Network connection: A source of abundant noise since machines are perpetually establishing network connections. We may uncover anomalies, but let's consider other quieter areas first.
* Sysmon Event ID 4 - Sysmon service state changed: Could be a useful hunt if attackers attempt to stop Sysmon, though the majority of these events are likely benign and informational, considering Sysmon's frequent legitimate starts and stops.
* Sysmon Event ID 5 - Process terminated: This might aid us in detecting when attackers kill key processes or use sacrificial ones. For instance, Cobalt Strike often spawns temporary processes like werfault, the termination of which would be logged here, as well as the creation in ID 1.
* Sysmon Event ID 6 - Driver loaded: A potential flag for BYOD (bring your own driver) attacks, though this is less common. Before diving deep into this, let's weed out more conspicuous threats first.
* Sysmon Event ID 7 - Image loaded: Allows us to track dll loads, which is handy in detecting DLL hijacks.
* Sysmon Event ID 8 - CreateRemoteThread: Potentially aids in identifying injected threads. While remote threads can be created legitimately, if an attacker misuses this API, we can potentially trace their rogue process and what they injected into.
* Sysmon Event ID 10 - ProcessAccess: Useful for spotting remote code injection and memory dumping, as it records when handles on processes are made.
* Sysmon Event ID 11 - FileCreate: With many files being created frequently due to updates, downloads, etc., it might be challenging to aim our hunt directly here. However, these events can be beneficial in correlating or identifying a file's origins later.
* Sysmon Event ID 12 - RegistryEvent (Object create and delete) & Sysmon Event ID 13 - RegistryEvent (Value Set): While numerous events take place here, many registry events can be malicious, and with a good idea of what to look for, hunting here can be fruitful.
* Sysmon Event ID 15 - FileCreateStreamHash: Relates to file streams and the "Mark of the Web" pertaining to external downloads, but we'll leave this aside for now.
* Sysmon Event ID 16 - Sysmon config state changed: Logs alterations in Sysmon configuration, useful for spotting tampering.
* Sysmon Event ID 17 - Pipe created & Sysmon Event ID 18 - Pipe connected: Record pipe creations and connections. They can help observe malware's interprocess communication attempts, usage of PsExec, and SMB lateral movement.
* Sysmon Event ID 22 - DNSEvent: Tracks DNS queries, which can be beneficial for monitoring beacon resolutions and DNS beacons.
* Sysmon Event ID 23 - FileDelete: Monitors file deletions, which can provide insights into whether a threat actor cleaned up their malware, deleted crucial files, or possibly attempted a ransomware attack.
* Sysmon Event ID 25 - ProcessTampering (Process image change): Alerts on behaviors such as process herpadering, acting as a mini AV alert filter.


```spl
index="main" sourcetype="WinEventLog:Sysmon" EventCode=1 (Image="*cmd.exe" OR Image="*powershell.exe") | stats count by ParentImage, Image

index="main" CallTrace="*UNKNOWN*" SourceImage!="*Microsoft.NET*" CallTrace!=*ni.dll* CallTrace!=*clr.dll* CallTrace!=*wow64* SourceImage!="C:\\Windows\\Explorer.EXE" | where SourceImage!=TargetImage | stats count by SourceImage, TargetImage, CallTrace

index="main" 10.0.0.229 sourcetype="WinEventLog:sysmon" | stats count by CommandLine
```

## Detecting Attacker Behavior With Splunk Based On TTPs

### Detection Of Reconnaissance Activities Leveraging Native Windows Binaries
  
```spl
index="main" sourcetype="WinEventLog:Sysmon" EventCode=1 Image=*\\ipconfig.exe OR Image=*\\net.exe OR Image=*\\whoami.exe OR Image=*\\netstat.exe OR Image=*\\nbtstat.exe OR Image=*\\hostname.exe OR Image=*\\tasklist.exe | stats count by Image,CommandLine | sort - count
```
### Detection Of Requesting Malicious Payloads/Tools Hosted On Reputable/Whitelisted Domains (Such As githubusercontent.com)

```spl
index="main" sourcetype="WinEventLog:Sysmon" EventCode=22  QueryName="*github*" | stats count by Image, QueryName
```

### Example: Detection Of PsExec Usage

```spl
index="main" sourcetype="WinEventLog:Sysmon" EventCode=13 Image="C:\\Windows\\system32\\services.exe" TargetObject="HKLM\\System\\CurrentControlSet\\Services\\*\\ImagePath" | rex field=Details "(?<reg_file_name>[^\\\]+)$" | eval reg_file_name = lower(reg_file_name), file_name = if(isnull(file_name),reg_file_name,lower(file_name)) | stats values(Image) AS Image, values(Details) AS RegistryDetails, values(_time) AS EventTimes, count by file_name, ComputerName
```

### Leveraging Sysmon Event ID 11

```spl
index="main" sourcetype="WinEventLog:Sysmon" EventCode=11 Image=System | stats count by TargetFilename
```
### Leveraging Sysmon Event ID 18

```spl
index="main" sourcetype="WinEventLog:Sysmon" EventCode=18 Image=System | stats count by PipeName
```

### Detection Of Utilizing Archive Files For Transferring Tools Or Data Exfiltration

```spl
index="main" EventCode=11 (TargetFilename="*.zip" OR TargetFilename="*.rar" OR TargetFilename="*.7z") | stats count by ComputerName, User, TargetFilename | sort - count
```

### Detection Of Utilizing PowerShell or MS Edge For Downloading Payloads/Tools

```spl
index="main" sourcetype="WinEventLog:Sysmon" EventCode=11 Image="*powershell.exe*" |  stats count by Image, TargetFilename |  sort + count

index="main" sourcetype="WinEventLog:Sysmon" EventCode=11 Image="*msedge.exe" TargetFilename=*"Zone.Identifier" |  stats count by TargetFilename |  sort + count

```

### Detection Of Execution From Atypical Or Suspicious Locations

```spl
index="main" EventCode=1 | regex Image="C:\\\\Users\\\\.*\\\\Downloads\\\\.*" |  stats count by Image
```

### Detection Of Executables or DLLs Being Created Outside The Windows Directory

```spl
index="main" EventCode=11 (TargetFilename="*.exe" OR TargetFilename="*.dll") TargetFilename!="*\\windows\\*" | stats count by User, TargetFilename | sort + count
```

### Detection Of Misspelling Legitimate Binaries

```spl
index="main" sourcetype="WinEventLog:Sysmon" EventCode=1 (CommandLine="*psexe*.exe" NOT (CommandLine="*PSEXESVC.exe" OR CommandLine="*PsExec64.exe")) OR (ParentCommandLine="*psexe*.exe" NOT (ParentCommandLine="*PSEXESVC.exe" OR ParentCommandLine="*PsExec64.exe")) OR (ParentImage="*psexe*.exe" NOT (ParentImage="*PSEXESVC.exe" OR ParentImage="*PsExec64.exe")) OR (Image="*psexe*.exe" NOT (Image="*PSEXESVC.exe" OR Image="*PsExec64.exe")) |  table Image, CommandLine, ParentImage, ParentCommandLine
```

### Detection Of Using Non-standard Ports For Communications/Transfers

```spl
index="main" EventCode=3 NOT (DestinationPort=80 OR DestinationPort=443 OR DestinationPort=22 OR DestinationPort=21) | stats count by SourceIp, DestinationIp, DestinationPort | sort - count
```

## Streamstats

We can use streamstats tu obtain average or standard deviation of processes, connection, etc. 

```spl
index="main" sourcetype="WinEventLog:Sysmon" EventCode=3 | bin _time span=1h | stats count as NetworkConnections by _time, Image | streamstats time_window=24h avg(NetworkConnections) as avg stdev(NetworkConnections) as stdev by Image | eval isOutlier=if(NetworkConnections > (avg + (0.5*stdev)), 1, 0) | search isOutlier=1

index="main" EventCode=1 (CommandLine="*cmd.exe*") | bucket _time span=1h | stats count as cmdCount by _time User CommandLine | eventstats avg(cmdCount) as avg stdev(cmdCount) as stdev | eval isOutlier=if(cmdCount > avg+1.5*stdev, 1, 0) | search isOutlier=1
```

Detection of high number of dll loads

```spl
index="main" EventCode=7 | bucket _time span=1h | stats dc(ImageLoaded) as unique_dlls_loaded by _time, Image | where unique_dlls_loaded > 3 | stats count by Image, unique_dlls_loaded

index="main" EventCode=7 NOT (Image="C:\\Windows\\System32*") NOT (Image="C:\\Program Files (x86)*") NOT (Image="C:\\Program Files*") NOT (Image="C:\\ProgramData*") NOT (Image="C:\\Users\\waldo\\AppData*")| bucket _time span=1h | stats dc(ImageLoaded) as unique_dlls_loaded by _time, Image | where unique_dlls_loaded > 3 | stats count by Image, unique_dlls_loaded | sort - unique_dlls_loaded
```

Execution of the same process (Image) in a same maching

```spl
index="main" sourcetype="WinEventLog:Sysmon" EventCode=1 | transaction ComputerName, Image | where mvcount(ProcessGuid) > 1 | stats count by Image, ParentImage
```

