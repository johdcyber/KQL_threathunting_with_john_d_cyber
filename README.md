# KQL_threathunting_with_john_d_cyber

Explore a collection of KQL queries crafted for dynamic threat hunting across a diverse range of topics, techniques, and use cases! 
These queries are designed as your launchpad - ready to be tailored to your unique environment and evolving threat landscape. 
Dive in, experiment, and don't forget to share your own insights. Together, let's elevate our cybersecurity game and make the internet a safer, more secure place for everyone. Happy hunting!


```jsx
**Network Communication: DNS Tunneling Detection:**
```

```
// Detect DNS tunneling based on query length
// Look for unusually long DNS queries that might indicate tunneling
DNSLogs
| where QueryLength > 250
| project TimeGenerated, ClientIP, Query

```

```jsx
**File Manipulation: Suspicious File Deletion:**
```

```
// Detect suspicious file deletion
// Look for files being deleted from sensitive directories
FileDeleted
| where FileName in ("C:\\\\Windows\\\\System32\\\\mshta.exe", "C:\\\\Windows\\\\System32\\\\cmd.exe")
| project TimeGenerated, Computer, FileName, InitiatingProcessCommandLine

```

```jsx
**Code Signing Abuse: Suspicious Certificates:**
```

```
// Detect potential code signing abuse
// Look for certificates with unexpected publishers or subject names
CertificateLog
| where Publisher != "Microsoft Windows" and Publisher != "Microsoft Windows UEFI Driver Publisher"
| project TimeGenerated, Publisher, Subject, Thumbprint

```

```jsx
**Anti-Virus Evasion: PowerShell Obfuscation:**
```

```
// Detect PowerShell obfuscation techniques
// Look for common obfuscation functions and keywords
ProcessCreation
| where ProcessCommandLine contains "powershell" and
  (ProcessCommandLine contains "Invoke-Expression" or ProcessCommandLine contains "iex" or ProcessCommandLine contains "Enc" or ProcessCommandLine contains "Base64")
| project TimeGenerated, Computer, User, ProcessCommandLine

```

```jsx
**AppLocker Bypass: Unauthorized Script Execution:**
```

```
// Detect unauthorized script execution
// Look for script interpreters being used to execute scripts
ProcessCreation
| where ProcessCommandLine contains ".ps1" or ProcessCommandLine contains ".vbs" or ProcessCommandLine contains ".bat"
| project TimeGenerated, Computer, User, ProcessCommandLine

```

```jsx
**Rootkit Installation: Kernel Module Load Detection:**
```

```
// Detect kernel module loads
// Look for suspicious kernel modules being loaded
KernelDriverEvents
| where EventType == "Load"
| project TimeGenerated, Computer, ImageLoaded

```

```jsx
**Privilege Escalation: Group Membership Changes:**
```

```
// Detect changes to privileged groups
// Look for changes in membership to administrators or other high-privilege groups
SecurityEvent
| where EventID == 4732 or EventID == 4733
| project TimeGenerated, Computer, TargetUserName, TargetDomainName, MemberName

```

```jsx
**Credential Theft: RDP Logon Anomalies:**
```

```
// Detect unusual RDP logon attempts
// Look for multiple failed RDP logons within a short time period
SecurityEvent
| where EventID == 4625 and TargetLogonType == 10 and FailureReason != 0
| extend LogonInterval = TimeGenerated - prev(TimeGenerated)
| where LogonInterval < 600s // 10 minutes
| project TimeGenerated, Computer, Account, FailureReason, LogonInterval

```

```jsx
**Fileless Malware: WMI Activity:**
```

```
// Detect suspicious WMI activity
// Look for WMI queries that might indicate fileless malware
SecurityEvent
| where EventID == 5858
| project TimeGenerated, Computer, User, SubjectName, Query

```

```jsx
**Living Off The Land: Unusual Script Execution:**
```

```
// Detect unusual scripting activity
// Look for PowerShell or WScript being used in unexpected ways
ProcessCreation
| where ProcessCommandLine contains "powershell" or ProcessCommandLine contains "wscript"
| where ProcessCommandLine !contains "-File" and ProcessCommandLine !contains "-Command" and ProcessCommandLine !contains "-EncodedCommand"
| project TimeGenerated, Computer, User, ProcessCommandLine

```

```jsx

```

```jsx
**Process Injection: Process Hollowing Detection:**
```

```
// Detect process hollowing based on process memory changes
// Look for process memory being written with executable content
ProcessMemory
| where ActionType == "WriteProcessMemory" and TargetObject contains "VirtualAllocEx" and (ActionInitiator contains "explorer.exe" or ActionInitiator contains "svchost.exe")
| project TimeGenerated, Computer, ActionInitiator, TargetObject, ProcessCommandLine

```

```jsx
**Network Communication: Beaconing Detection:**
```

```
// Detect beaconing behavior using outbound traffic patterns
// Look for repeated small-sized packets to external IPs
Heartbeat
| extend OutboundBytesPerMinute = OutboundBytes / (TimeGenerated - prev(TimeGenerated)).TotalMinutes
| where OutboundBytesPerMinute < 50 and RemoteIPType == "IPV4"
| project TimeGenerated, RemoteIP, OutboundBytesPerMinute

```

```jsx
**File Manipulation: Suspicious Archive Extraction:**
```

```
// Detect suspicious extraction of archives
// Look for common archive utilities being used to extract files
FileCreated
| where FileName contains ".zip" or FileName contains ".rar" or FileName contains ".7z"
| project TimeGenerated, Computer, InitiatingProcessCommandLine, FileName

```

```jsx
**Rootkit Installation: Unusual Driver Loads:**
```

```
// Detect unusual driver loads
// Look for unsigned or uncommon drivers being loaded
KernelDriverEvents
| where EventType == "Load" and IsSigned != 1
| project TimeGenerated, Computer, ImageLoaded, SignatureStatus

```

```jsx
**Privilege Escalation: Suspicious Use of RunAs:**
```

```
// Detect suspicious use of RunAs
// Look for processes started using RunAs
SecurityEvent
| where EventID == 4688 and ProcessCommandLine contains "runas.exe"
| project TimeGenerated, Computer, NewProcessName, SubjectUser, TargetUser, ProcessCommandLine

```

```jsx
**Credential Theft: Credential Dumping:**
```

```
// Detect potential credential dumping activity
// Look for LSASS memory access and specific Event IDs
SecurityEvent
| where EventID in (4648, 4661, 4662, 4663, 4672) or
  (EventID == 4656 and ObjectName == "Security" and ObjectType == "File")
| project TimeGenerated, Computer, User, EventID, ObjectName, ObjectType, LogonType

```

```jsx
**AppLocker Bypass: Execution via COM Objects:**
```

```
// Detect potential AppLocker bypass using COM objects
// Look for COM object initialization in a non-standard way
ProcessCreation
| where ProcessCommandLine contains "CreateInstance"
| project TimeGenerated, Computer, User, ProcessCommandLine

```

```jsx
**Code Signing Abuse: Malicious Certificate Usage:**
```

```
// Detect potential malicious certificate usage
// Look for certificates associated with known malicious activities
CertificateLog
| where Subject contains "malicious.com" or Thumbprint in ("maliciousThumbprint1", "maliciousThumbprint2")
| project TimeGenerated, Publisher, Subject, Thumbprint

```

```jsx
**Anti-Virus Evasion: Suspicious Packed Executables:**
```

```
// Detect suspicious packed executables
// Look for known packer signatures or unpacking behavior
FileCreated
| where FileName endswith ".exe" and SignatureStatus == "Unsigned" and
  (FileName in ("upx.exe", "packing_tool.exe") or FileName == "unpackme.exe")
| project TimeGenerated, Computer, FileName

```

```jsx
**Fileless Malware: WMI Persistence:**
```

```
// Detect potential WMI-based fileless malware
// Look for WMI subscription or event consumer creation
SecurityEvent
| where EventID == 19 or EventID == 20
| project TimeGenerated, Computer, User, NewProcessName, EventData

```

```jsx
**Living Off The Land: Unusual Registry Modifications:**
```

```
// Detect potential LOLBins using registry modifications
// Look for suspicious registry key changes by common LOLBin executables
RegistryEvents
| where RegistryKey in ("HKEY_LOCAL_MACHINE\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run",
                        "HKEY_LOCAL_MACHINE\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\RunOnce",
                        "HKEY_CURRENT_USER\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run",
                        "HKEY_CURRENT_USER\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\RunOnce")
| where RegistryAction == "SetValue" and InitiatingProcessCommandLine contains_any("cmd.exe", "powershell.exe")
| project TimeGenerated, Computer, RegistryKey, InitiatingProcessCommandLine, TargetValue

```

```jsx
**Network Communication: Data Exfiltration Detection:**
```

```
// Detect potential data exfiltration based on network traffic patterns
// Look for unusual volume of outbound traffic to non-standard ports
NetworkCommunication
| where RemotePort in (443, 53, 80, 8080) and BytesOut > 10MB
| project TimeGenerated, RemoteIP, RemotePort, BytesOut

```

```jsx
**File Manipulation: Unusual File Rename Patterns:**
```

```
// Detect potential file name obfuscation or evasion
// Look for files with random or unusual naming patterns
FileCreated
| where FileName matches regex @"^[A-F0-9]{8}-[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{12}\\.exe$"
| project TimeGenerated, Computer, FileName

```

```jsx
**Privilege Escalation: Abnormal User Permission Changes:**
```

```
// Detect suspicious changes in user permissions
// Look for unexpected changes to user permissions on files and folders
SecurityEvent
| where EventID in (4656, 4663) and ObjectName contains "\\\\Users\\\\"
| project TimeGenerated, Computer, User, ObjectName, ObjectType, ObjectProperties

```

```jsx
**Process Injection: Reflective DLL Injection:**
```

```
// Detect potential reflective DLL injection
// Look for process memory write operations with PAGE_EXECUTE_READWRITE protection
ProcessMemory
| where ActionType == "WriteProcessMemory" and Protect == "PAGE_EXECUTE_READWRITE"
| project TimeGenerated, Computer, ActionInitiator, TargetObject, ProcessCommandLine

```

```jsx
**File Manipulation: File Extensions Anomalies:**
```

```
// Detect files with suspicious extensions
// Look for files with multiple file extensions or unusual extensions
FileCreated
| where FileName contains ".." or FileName contains ".exe." or FileName contains ".doc.js"
| project TimeGenerated, Computer, FileName

```

```jsx
**Network Communication: Unusual Domain Beaconing:**
```

```
// Detect potential beaconing by analyzing domain patterns
// Look for domains with consecutive digits or unusual naming patterns
DNSLogs
| extend DomainLength = strlen(Query)
| where DomainLength > 10 and Domain contains pattern ".*\\d{5,}.*"
| project TimeGenerated, Computer, Domain

```

```jsx
**Privilege Escalation: Suspicious Scheduled Task Creation:**
```

```
// Detect potential privilege escalation by suspicious scheduled task creation
// Look for scheduled tasks with unusual names or paths
SecurityEvent
| where EventID == 4698 and TaskName contains_any("evildoer", "backdoor", "rootkit") or
  (EventID == 4702 and TaskName contains "C:\\\\Windows\\\\System32\\\\Tasks\\\\")
| project TimeGenerated, Computer, TaskName, NewProcessName, SubjectUser

```

```jsx
**Living Off The Land: Unusual PowerShell Modules Usage:**
```

```
// Detect potential misuse of PowerShell modules
// Look for PowerShell commands loading non-standard modules
SecurityEvent
| where EventID == 4104 and Channel == "Microsoft-Windows-Security-Auditing"
| where tostring(Params[0]) contains "powershell.exe" and tostring(Params[1]) contains "-m"
| project TimeGenerated, Computer, User, ProcessCommandLine, Image

```

```jsx
**Process Injection: RunPE Detection:**
```

```
// Detect potential RunPE-based process injection
// Look for parent processes loading other executables
ProcessCreation
| where ProcessCommandLine contains "RunPE" or ProcessCommandLine contains "LoadEXE"
| project TimeGenerated, Computer, User, ParentImage, ProcessCommandLine

```

```jsx
**Anti-Virus Evasion: Code Packing Detection:**
```

```
// Detect potential code packing techniques
// Look for executable files with sections containing suspicious entropy levels
FileCreated
| where FileName endswith ".exe"
| join kind=inner (PeInfo | where SectionEntropy > 6) on FileName
| project TimeGenerated, Computer, FileName

```

```jsx
**Network Communication: Uncommon User-Agent Strings:**
```

```
// Detect potential malicious or non-standard user-agent strings
// Look for unusual user-agent strings in web traffic
WebBrowser
| where UserAgent != "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3"
| project TimeGenerated, Computer, UserAgent

```

```jsx
**Rootkit Installation: Hidden Module Loads:**
```

```
// Detect potential rootkit behavior by hidden module loads
// Look for modules being loaded with hidden or protected attributes
KernelDriverEvents
| where EventType == "Load" and ImageLoaded contains "\\\\Hidden\\\\"
| project TimeGenerated, Computer, ImageLoaded, SignatureStatus

```

```jsx
**AppLocker Bypass: Unsigned DLL Loading:**
```

```
// Detect potential AppLocker bypass using unsigned DLLs
// Look for processes loading unsigned DLLs from common directories
ProcessCreation
| where ProcessCommandLine contains ".dll" and SignatureStatus == "Unsigned"
| where ProcessCommandLine !contains "System32" and ProcessCommandLine !contains "SysWOW64"
| project TimeGenerated, Computer, User, ProcessCommandLine

```

```jsx
**Fileless Malware: Suspicious PowerShell Script Blocks:**
```

```
// Detect potential PowerShell script blocks used for fileless malware
// Look for obfuscated or encoded script content
PowerShellEvent
| where EventID == 4104 and ScriptBlockText contains "([a-z]+\\(('[a-z]+',?)+\\))"
| project TimeGenerated, Computer, User, ScriptBlockText

```

```jsx
**Network Communication: Abnormal Outbound Connections:**
```

```
// Detect potential command and control (C2) activity
// Look for unusual outbound connections to known malicious IPs or domains
NetworkCommunication
| where RemoteIP in ("192.168.1.2", "10.0.0.2") or RemoteURL contains_any("malicious.com", "evil.net")
| project TimeGenerated, RemoteIP, RemoteURL

```

```jsx
**Anti-Virus Evasion: Known Evasion Tool Execution:**
```

```
// Detect potential execution of known anti-virus evasion tools
// Look for command-line arguments indicative of evasion tools
ProcessCreation
| where ProcessCommandLine contains_any("-c", "-ec", "-m", "--mimikatz", "-w", "-winrm", "wce.exe")
| project TimeGenerated, Computer, User, ProcessCommandLine

```

```jsx
**File Manipulation: Suspicious Renaming and Deletion:**
```

```
// Detect potential suspicious file renaming or deletion
// Look for rapid rename or delete operations on sensitive files
FileOperation
| where ActionType in ("FileRenamed", "FileDeleted")
| extend OperationInterval = TimeGenerated - prev(TimeGenerated)
| where OperationInterval < 60s // 1 minute
| project TimeGenerated, Computer, FileName, InitiatingProcessCommandLine, ActionType

```

```jsx
**Rootkit Installation: Kernel Hook Detection:**
```

```
// Detect potential kernel hooks by monitoring system calls
// Look for unusual system call behavior or hooking indicators
KernelEvent
| where EventID == 13 or EventID == 15
| project TimeGenerated, Computer, EventID, HookedFunction

```

```jsx
**Privilege Escalation: Unusual Registry Key Changes:**
```

```
// Detect potential privilege escalation by suspicious registry key changes
// Look for modifications to known privilege-related registry keys
RegistryEvents
| where RegistryKey in ("HKEY_LOCAL_MACHINE\\\\SYSTEM\\\\CurrentControlSet\\\\Services\\\\*\\\\ImagePath",
                        "HKEY_LOCAL_MACHINE\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run",
                        "HKEY_LOCAL_MACHINE\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\RunOnce")
| where RegistryAction == "SetValue" and InitiatingProcessCommandLine !contains "svchost.exe"
| project TimeGenerated, Computer, RegistryKey, InitiatingProcessCommandLine, TargetValue

```

```jsx
**AppLocker Bypass: Unusual Child Process Creation:**
```

```
// Detect potential AppLocker bypass using unusual child process creation
// Look for processes being started by common Windows binaries
ProcessCreation
| where ParentImage contains_any("powershell.exe", "explorer.exe") and ProcessCommandLine !contains "Microsoft"
| project TimeGenerated, Computer, ParentImage, ProcessImage, ProcessCommandLine

```

```jsx
**Living Off The Land: WMI Filter Abuse:**
```

```
// Detect potential misuse of WMI filters
// Look for WMI queries using unusual or unauthorized filters
SecurityEvent
| where EventID == 5864 and
  (TargetObject contains "CN=Policy*" or TargetObject contains "OU=Windows-*")
| project TimeGenerated, Computer, User, TargetObject, FilterName

```

```jsx
**Process Injection: Memory Write Anomalies:**
```

```
// Detect potential process injection by unusual memory write behavior
// Look for processes writing to other process memory without known reasons
ProcessMemory
| where ActionType == "WriteProcessMemory" and PageState == "Write-CopyOnWrite"
| project TimeGenerated, Computer, ActionInitiator, TargetObject, ProcessCommandLine

```

```jsx
**Network Communication: Uncommon Port Usage:**
```

```
// Detect potential unusual port usage
// Look for uncommon ports being used for outbound connections
NetworkCommunication
| where RemotePort notin (80, 443, 53, 8080)
| project TimeGenerated, Computer, RemoteIP, RemotePort

```

```jsx
**Fileless Malware: PowerShell Command Line Obfuscation:**
```

```
// Detect potential PowerShell obfuscation techniques
// Look for PowerShell commands with complex obfuscation patterns
SecurityEvent
| where EventID == 4104 and Channel == "Microsoft-Windows-Security-Auditing"
| where tostring(Params[0]) contains "powershell.exe" and
  (tostring(Params[1]) contains "-e" or tostring(Params[1]) contains "-ec")
| project TimeGenerated, Computer, User, ProcessCommandLine, Image

```

```jsx
**Anti-Virus Evasion: JavaScript Obfuscation:**
```

```
// Detect potential JavaScript obfuscation techniques
// Look for JavaScript code with heavy obfuscation patterns
ProcessCreation
| where ProcessCommandLine contains "wscript.exe" or ProcessCommandLine contains "cscript.exe"
| where ProcessCommandLine contains "eval(String.fromCharCode" or ProcessCommandLine contains "fromCharCode"
| project TimeGenerated, Computer, User, ProcessCommandLine

```

```jsx
**Rootkit Installation: Malicious Driver Load:**
```

```
// Detect potential malicious driver loads
// Look for drivers with unsigned certificates or known malicious hashes
KernelDriverEvents
| where EventType == "Load" and (IsSigned != 1 or ImageLoaded in ("maliciousHash1", "maliciousHash2"))
| project TimeGenerated, Computer, ImageLoaded, SignatureStatus

```

```jsx
**Privilege Escalation: Suspicious Service Creation:**
```

```
// Detect potential privilege escalation through service creation
// Look for services with unusual names, paths, or permissions
SecurityEvent
| where EventID in (4697, 4698, 4701)
| project TimeGenerated, Computer, TaskName, NewProcessName, SubjectUser

```

```jsx
**Network Communication: Tor and VPN Traffic:**
```

```
// Detect potential use of Tor or VPN services
// Look for connections to known Tor exit nodes or VPN IPs
NetworkCommunication
| where RemoteIP in ("185.220.101.7", "185.220.101.10") or RemoteURL contains "vpn-proxy"
| project TimeGenerated, Computer, RemoteIP, RemoteURL

```

```jsx
**AppLocker Bypass: Suspicious Script Block Execution:**
```

```
// Detect potential script block execution to bypass AppLocker
// Look for PowerShell script blocks with known bypass techniques
PowerShellEvent
| where EventID == 4104 and ScriptBlockText contains_any("Set-ExecutionPolicy", "Bypass")
| project TimeGenerated, Computer, User, ScriptBlockText

```

```jsx
**Living Off The Land: Unusual DLL Loading:**
```

```
// Detect potential LOLBin usage for DLL loading
// Look for processes loading DLLs from unusual or non-standard directories
ProcessCreation
| where ProcessCommandLine contains ".dll" and
  (ProcessCommandLine contains_any("system32", "syswow64") == false)
| project TimeGenerated, Computer, User, ProcessCommandLine

```

```jsx
**Process Injection: Hooking Detection:**
```

```
// Detect potential API hooking
// Look for processes loading modules known for hooking or detouring
ProcessCreation
| where ProcessCommandLine contains ".dll" and ProcessCommandLine contains_any("Detours", "EasyHook", "Mhook")
| project TimeGenerated, Computer, User, ProcessCommandLine

```

```jsx
**Network Communication: Encrypted PowerShell Traffic:**
```

```
// Detect potential malicious PowerShell over HTTPS
// Look for encrypted PowerShell traffic over non-standard ports
NetworkCommunication
| where RemotePort > 1024 and RemoteURL contains_any("https://", "4433", "8443")
| project TimeGenerated, Computer, RemoteIP, RemotePort

```

```jsx
**File Manipulation: Unexpected File Access:**
```

```
// Detect potential unauthorized file access
// Look for file access to sensitive directories by unusual processes
FileAccess
| where FileAccessRights contains "Read" and FileAccessRights contains "Write"
| where InitiatingProcessCommandLine !contains_any("explorer.exe", "cmd.exe", "powershell.exe")
| project TimeGenerated, Computer, InitiatingProcessCommandLine, ObjectName

```

```jsx
**Fileless Malware: WMI Script Block Execution:**
```

```
// Detect potential WMI script block execution
// Look for WMI queries with script blocks
SecurityEvent
| where EventID == 5859 and Query contains "Invoke-Expression" and Query contains "ScriptBlock"
| project TimeGenerated, Computer, User, Query

```

```jsx

```

```jsx
**Privilege Escalation: Unusual Group Policy Changes:**
```

```
// Detect potential privilege escalation through Group Policy changes
// Look for modifications to sensitive Group Policy settings
SecurityEvent
| where EventID == 4739 and ObjectName contains "GroupPolicy"
| project TimeGenerated, Computer, User, ObjectName, ObjectType

```

```jsx
**Anti-Virus Evasion: PowerShell Script Block Obfuscation:**
```

```
// Detect potential PowerShell obfuscation techniques
// Look for complex obfuscation patterns in PowerShell script blocks
PowerShellEvent
| where EventID == 4104 and Channel == "Microsoft-Windows-Security-Auditing"
| where tostring(Params[0]) contains "powershell.exe" and tostring(Params[1]) contains "-encodedcommand"
| project TimeGenerated, Computer, User, ProcessCommandLine, Image

```

```jsx
**Network Communication: Suspicious Beaconing Patterns:**
```

```
// Detect potential beaconing patterns in network traffic
// Look for regular and consistent communication with specific IPs or domains
Heartbeat
| extend OutboundFrequency = (1 / (TimeGenerated - prev(TimeGenerated)).TotalSeconds)
| where RemoteIPType == "IPV4" and OutboundFrequency > 30
| project TimeGenerated, Computer, RemoteIP, OutboundFrequency

```

```jsx
**AppLocker Bypass: PowerShell Obfuscation:**
```

```
// Detect potential AppLocker bypass using obfuscated PowerShell
// Look for PowerShell commands with heavy obfuscation
ProcessCreation
| where ProcessCommandLine contains "powershell.exe" and ProcessCommandLine contains "-encodedcommand"
| project TimeGenerated, Computer, User, ProcessCommandLine

```

```jsx
**Rootkit Installation: Hook Detection:**
```

```
// Detect potential rootkit hooks
// Look for processes loading modules known for hooking or rootkit behavior
ProcessCreation
| where ProcessCommandLine contains ".dll" and ProcessCommandLine contains_any("Rootkit", "Hook")
| project TimeGenerated, Computer, User, ProcessCommandLine

```

```jsx
**Network Communication: Beaconing by Data Volume:**
```

```
// Detect potential beaconing by analyzing data volume
// Look for repeated, small-sized packets sent to specific IPs
Heartbeat
| extend OutboundBytesPerMinute = OutboundBytes / (TimeGenerated - prev(TimeGenerated)).TotalMinutes
| where OutboundBytesPerMinute < 50 and RemoteIPType == "IPV4"
| project TimeGenerated, RemoteIP, OutboundBytesPerMinute

```

```jsx
**File Manipulation: Unauthorized File Modification:**
```

```
// Detect potential unauthorized file modification
// Look for files being modified by unusual processes
FileAccess
| where FileAccessRights contains "Write" and InitiatingProcessCommandLine !contains_any("explorer.exe", "cmd.exe", "powershell.exe")
| project TimeGenerated, Computer, InitiatingProcessCommandLine, ObjectName

```

```jsx
**Living Off The Land: Unusual Command Line Arguments:**
```

```
// Detect potential LOLBin usage by analyzing command-line arguments
// Look for common binaries executed with unusual arguments
ProcessCreation
| where ProcessCommandLine contains_any("certutil", "regsvr32", "mshta", "rundll32")
| where ProcessCommandLine contains "--"
| project TimeGenerated, Computer, User, ProcessCommandLine

```

```jsx
**Process Injection: Process Hollowing Detection:**
```

```
// Detect potential process hollowing techniques
// Look for processes with low virtual memory usage and high thread count
Process
| where VirtualSize < 50000 and ThreadCount > 50
| project TimeGenerated, Computer, Image, CommandLine

```

```jsx
**Fileless Malware: Unusual PowerShell Commandlets:**
```

```
// Detect potential fileless malware through unusual PowerShell commandlets
// Look for PowerShell commands using uncommon or malicious cmdlets
SecurityEvent
| where EventID == 4104 and Channel == "Microsoft-Windows-Security-Auditing"
| where tostring(Params[0]) contains "powershell.exe" and
  tostring(Params[1]) contains_any("WebClient", "New-Object", "Add-Type", "Invoke-ReflectivePEInjection")
| project TimeGenerated, Computer, User, ProcessCommandLine, Image

```

```jsx

```

```jsx
**Network Communication: Unusual User-Agent Strings in HTTP Traffic:**
```

```
// Detect potential malicious user-agent strings in HTTP requests
// Look for uncommon or suspicious user-agent strings
Heartbeat
| where RemotePort == 80 or RemotePort == 443
| where RemoteUrl contains "http" and UserAgent notlike "%Mozilla/5.0%"
| project TimeGenerated, Computer, RemoteIP, RemoteUrl, UserAgent

```

```jsx
**Rootkit Installation: Hidden Processes Detection:**
```

```
// Detect potential rootkit behavior by hidden processes
// Look for processes with hidden windows or non-standard window titles
ProcessCreation
| where ProcessCommandLine !contains_any("explorer.exe", "cmd.exe", "powershell.exe") and
  (WindowStation == "WinSta0" or WindowTitle != "" or ParentWindowStation != "")
| project TimeGenerated, Computer, User, ProcessCommandLine, WindowStation, WindowTitle, ParentWindowStation

```

```jsx
**Living Off The Land: Unusual Parent Processes:**
```

```
// Detect potential LOLBin usage by analyzing parent process relationships
// Look for common binaries started by unusual parent processes
ProcessCreation
| where ProcessCommandLine contains_any("mshta", "rundll32", "regsvr32") and
  ParentImage !contains_any("explorer.exe", "cmd.exe", "powershell.exe")
| project TimeGenerated, Computer, User, ParentImage, ProcessCommandLine

```

```jsx
**Anti-Virus Evasion: Process Hollowing Detection:**
```

```
// Detect potential process hollowing by analyzing process memory behavior
// Look for processes with write access to executable memory regions
ProcessMemory
| where ActionType == "WriteProcessMemory" and Protect == "PAGE_EXECUTE_READWRITE"
| project TimeGenerated, Computer, ActionInitiator, TargetObject, ProcessCommandLine

```

```jsx
**File Manipulation: Suspicious Execution Paths:**
```

```
// Detect potential suspicious execution paths
// Look for files being executed from unusual or non-standard paths
ProcessCreation
| where ProcessCommandLine contains ".exe" and
  (ProcessCommandLine contains_any("appdata", "temp", "recycle", "roaming") or
  (ProcessCommandLine contains "c:" and ProcessCommandLine !contains "c:\\\\windows\\\\"))
| project TimeGenerated, Computer, User, ProcessCommandLine

```

```jsx
**Network Communication: Suspicious DNS Query Patterns:**
```

```
// Detect potential DNS tunneling or data exfiltration
// Look for DNS queries with unusual patterns or domain length
DNSLogs
| where QueryLength > 30 or Query contains "base64" or Query contains "hex"
| project TimeGenerated, Computer, RemoteIP, Query

```

```jsx
**AppLocker Bypass: PowerShell Environment Abuse:**
```

```
// Detect potential AppLocker bypass through PowerShell environment manipulation
// Look for PowerShell sessions modifying environment variables
PowerShellEvent
| where EventID == 400 and ScriptBlockText contains "Set-ItemProperty -Path 'HKCU:"
| project TimeGenerated, Computer, User, ScriptBlockText

```

```jsx
**Process Injection: Dynamic API Resolution:**
```

```
// Detect potential process injection using dynamic API resolution
// Look for processes resolving API functions dynamically (e.g., LoadLibraryA)
ProcessCreation
| where ProcessCommandLine contains_any("LoadLibrary", "GetProcAddress", "VirtualAllocEx")
| project TimeGenerated, Computer, User, ProcessCommandLine

```

```jsx
**Fileless Malware: Uncommon PowerShell Cmdlet Usage:**
```

```
// Detect potential fileless malware using less common PowerShell cmdlets
// Look for PowerShell commands with unusual cmdlets not often used
PowerShellEvent
| where EventID == 4104 and Channel == "Microsoft-Windows-Security-Auditing"
| where tostring(Params[0]) contains "powershell.exe" and
  tostring(Params[1]) contains_none("Get-Process", "Get-Service", "Get-ItemProperty")
| project TimeGenerated, Computer, User, ProcessCommandLine, Image

```

```jsx
**Network Communication: Unusual Protocol Usage:**
```

```
// Detect potential suspicious protocol usage in network traffic
// Look for non-standard protocols or port combinations
NetworkCommunication
| where RemotePort in (6667, 1337, 31337) or RemoteProtocol != "http" and RemoteProtocol != "https"
| project TimeGenerated, Computer, RemoteIP, RemotePort, RemoteProtocol

```

```jsx

```

```jsx
**Privilege Escalation: Unusual Task Scheduler Behavior:**
```

```
// Detect potential privilege escalation through Task Scheduler
// Look for suspicious task actions, triggers, or conditions
SecurityEvent
| where EventID in (4698, 4699, 4700) and
  (NewProcessName contains "schtasks.exe" or NewProcessName contains "taskeng.exe")
| project TimeGenerated, Computer, User, NewProcessName, TaskName, TaskAction, TaskTrigger, TaskCondition

```

```jsx
**Living Off The Land: WMI Persistence Checks:**
```

```
// Detect potential WMI-based persistence mechanisms
// Look for WMI queries checking for persistence artifacts
SecurityEvent
| where EventID == 5860 and Query contains_any("SELECT * FROM Win32_StartupCommand")
| project TimeGenerated, Computer, User, Query

```

```jsx
**Network Communication: Suspicious TLS Certificates:**
```

```
// Detect potential malicious TLS certificates
// Look for certificates with low validity period, mismatched subjects, or missing extensions
TlsCertificate
| where ValidTo < now() and (ValidTo - ValidFrom) < 30d or Subject != CommonName or EnhancedKeyUsage == ""
| project TimeGenerated, Computer, Subject, ValidFrom, ValidTo, Thumbprint

```

```jsx
**Anti-Virus Evasion: PowerShell Script Block Download:**
```

```
// Detect potential downloading of obfuscated PowerShell script blocks
// Look for web requests fetching PowerShell scripts with obfuscation indicators
Heartbeat
| where RemoteUrl contains ".ps1" and RemoteUrl contains_any("base64", "encoded", "obfuscate")
| project TimeGenerated, Computer, RemoteIP, RemoteUrl

```

```jsx
**Rootkit Installation: Memory Module Unloading:**
```

```
// Detect potential rootkit behavior by unloading memory modules
// Look for memory module unloads performed by uncommon processes
KernelDriverEvents
| where EventType == "Unload" and ImageLoaded contains "memoryModule"
| project TimeGenerated, Computer, ImageLoaded, SignatureStatus

```

```jsx
**Network Communication: Unusual Beaconing Patterns:**
```

```
// Detect potential beaconing through analyzing beaconing intervals
// Look for consistent communication patterns at odd intervals
Heartbeat
| extend BeaconInterval = (TimeGenerated - prev(TimeGenerated)).TotalSeconds
| where BeaconInterval < 10 or BeaconInterval > 3600
| project TimeGenerated, Computer, BeaconInterval

```

```jsx
**AppLocker Bypass: Windows Script Host Usage:**
```

```
// Detect potential AppLocker bypass using Windows Script Host
// Look for script host execution of files with uncommon extensions
ProcessCreation
| where ProcessCommandLine contains "wscript.exe" or ProcessCommandLine contains "cscript.exe"
| where ProcessCommandLine !endswith ".vbs" and ProcessCommandLine !endswith ".js"
| project TimeGenerated, Computer, User, ProcessCommandLine

```

```jsx
**Process Injection: Remote Thread Creation:**
```

```
// Detect potential process injection through remote thread creation
// Look for processes creating threads in remote processes
ProcessCreation
| where ProcessCommandLine contains "CreateRemoteThread"
| project TimeGenerated, Computer, User, ProcessCommandLine

```

```jsx
**Fileless Malware: Script Block Persistence:**
```

```
// Detect potential script block-based persistence mechanisms
// Look for script block registration events or scheduled script block execution
SecurityEvent
| where EventID in (4104, 4105) and
  (ScriptBlockText contains "Register-ScheduledJob" or ScriptBlockText contains "ScheduledJob")
| project TimeGenerated, Computer, User, ScriptBlockText

```

```jsx
**Network Communication: Unusual Protocol Anomalies:**
```

```
// Detect potential suspicious protocol behaviors in network traffic
// Look for protocols with odd packet sizes, malformed headers, or non-standard behaviors
NetworkCommunication
| where RemoteProtocol == "ftp" and (BytesIn < 10 or BytesOut > 10000)
| project TimeGenerated, Computer, RemoteIP, RemotePort, RemoteProtocol, BytesIn, BytesOut

```

```jsx

```

```jsx
**Privilege Escalation: Unusual Registry Key Modifications:**
```

```
// Detect potential privilege escalation by suspicious registry key modifications
// Look for changes to sensitive registry keys related to user accounts and permissions
RegistryEvents
| where RegistryAction == "SetValue" and
  RegistryKey in ("HKEY_LOCAL_MACHINE\\\\SYSTEM\\\\CurrentControlSet\\\\Control\\\\Lsa", "HKEY_LOCAL_MACHINE\\\\SOFTWARE\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\Winlogon")
| project TimeGenerated, Computer, User, RegistryKey, TargetValue

```

```jsx
**Living Off The Land: Unusual Network Protocol Usage:**
```

```
// Detect potential LOLBin usage by analyzing uncommon network protocols
// Look for network communication using protocols like SMB, RDP, or IRC
NetworkCommunication
| where RemoteProtocol in ("smb", "rdp", "irc")
| project TimeGenerated, Computer, RemoteIP, RemotePort, RemoteProtocol

```

```jsx
**Network Communication: Command and Control Domain Flare-ups:**
```

```
// Detect potential command and control (C2) domain activity
// Look for spikes in connections to a particular domain within a short timeframe
Heartbeat
| extend Domain = tolower(parse_url(RemoteUrl).Host)
| summarize Count=count() by Domain, bin(TimeGenerated, 1h)
| where Count > 10
| project TimeGenerated, Domain, Count

```

```jsx
**Anti-Virus Evasion: Encoded PowerShell Commandlets:**
```

```
// Detect potential obfuscation by encoded PowerShell commandlets
// Look for PowerShell commands containing Base64-encoded strings
PowerShellEvent
| where EventID == 4104 and ScriptBlockText contains "Base64"
| project TimeGenerated, Computer, User, ScriptBlockText

```

```jsx
**Rootkit Installation: Suspicious Registry Key Access:**
```

```
// Detect potential rootkit installation through suspicious registry key access
// Look for access to sensitive registry keys by unusual processes
RegistryEvents
| where RegistryAction == "OpenKey" and
  RegistryKey in ("HKEY_LOCAL_MACHINE\\\\SYSTEM\\\\CurrentControlSet\\\\Services", "HKEY_LOCAL_MACHINE\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run")
| project TimeGenerated, Computer, User, InitiatingProcessCommandLine, RegistryKey

```

```jsx
**Network Communication: Abnormal Traffic Patterns:**
```

```
// Detect potential suspicious traffic patterns
// Look for traffic spikes or drops at unusual times
Heartbeat
| extend InboundBytesPerMinute = InboundBytes / (TimeGenerated - prev(TimeGenerated)).TotalMinutes
| where InboundBytesPerMinute > 100000 or InboundBytesPerMinute < 100
| project TimeGenerated, Computer, InboundBytesPerMinute

```

```jsx
**AppLocker Bypass: PowerShell Command History:**
```

```
// Detect potential AppLocker bypass using PowerShell history
// Look for PowerShell history containing bypass techniques
PowerShellEvent
| where EventID == 400 and (ScriptBlockText contains "bypass" or ScriptBlockText contains "NoProfile")
| project TimeGenerated, Computer, User, ScriptBlockText

```

```jsx
**Process Injection: Thread Suspension and Injection:**
```

```
// Detect potential process injection using thread suspension and injection
// Look for processes suspending threads in remote processes
ProcessCreation
| where ProcessCommandLine contains "SuspendThread" or ProcessCommandLine contains "QueueUserAPC"
| project TimeGenerated, Computer, User, ProcessCommandLine

```

```jsx
**Fileless Malware: Registry Run Keys Modification:**
```

```
// Detect potential fileless malware modifying Registry Run keys
// Look for changes to Run keys that execute scripts or binaries
RegistryEvents
| where RegistryKey contains "Run" and RegistryAction == "SetValue" and
  (TargetValue contains ".bat" or TargetValue contains ".ps1" or TargetValue contains ".exe")
| project TimeGenerated, Computer, User, RegistryKey, TargetValue

```

```jsx
**Network Communication: Suspicious Hostnames in DNS Queries:**
```

```
// Detect potential DNS tunneling or exfiltration using suspicious hostnames
// Look for DNS queries containing uncommon characters or long random strings
DNSLogs
| where Query contains any of ("@", "$", "{", "}", "#", "-") or strlen(Query) > 30
| project TimeGenerated, Computer, RemoteIP, Query

```

```

EmailEvents
| where ActionType == "FileAttached" or ActionType == "SteganographyDetected"
| where Timestamp > ago(1d)
| project Timestamp, SenderAddress, RecipientAddress, Subject, FileName, FileType, URL

```

```jsx
**File Transfer Protocols**:
```

```

NetworkTraffic
| where Protocol in ("FTP", "SFTP", "SCP")
| where Timestamp > ago(1d)
| project Timestamp, SourceIP, DestinationIP, Protocol, FileDetails

```

```jsx
**Cloud Storage and File Sharing**:
```

```

CloudAppEvents
| where AppName in ("Dropbox", "Google Drive", "OneDrive") and ActionType == "FileUploaded"
| where Timestamp > ago(1d)
| project Timestamp, UserName, AppName, FileName, FileSize, IPAddress

```

```jsx
**Remote Desktop Protocols (RDP)**:
```

```

SigninLogs
| where Application == "Remote Desktop" and ActionType == "Login"
| where Timestamp > ago(1d)
| project Timestamp, UserPrincipalName, IPAddress, Location

```

```jsx
**Instant Messaging and Chat Services**:
```

```

InstantMessageEvents
| where ActionType == "MessageSent" and MessageDetails contains "file transfer" or MessageDetails contains "encrypted"
| where Timestamp > ago(1d)
| project Timestamp, User, ChatService, MessageDetails

```

```jsx
**Web-Based Data Exfiltration**:
```

```

WebTraffic
| where URL contains "upload" or URLParameters contains "data="
| where Timestamp > ago(1d)
| project Timestamp, User, URL, URLParameters

```

```jsx
**DNS Tunneling**:
```

```

DnsEvents
| where QueryType == "TXT" or QueryType == "NULL"
| where Timestamp > ago(1d)
| project Timestamp, QueryName, IPAddress

```

```jsx
**Data Compression and Encryption**:
```

```

ProcessCreationEvents
| where ProcessName in ("winzip.exe", "7z.exe", "gpg.exe")
| where Timestamp > ago(1d)
| project Timestamp, ComputerName, FileName, ProcessCommandLine

```

```jsx
**Steganography**:
```

```

// This would require a specialized steganography detection tool that logs events
SteganographyDetectionEvents
| where Timestamp > ago(1d)
| project Timestamp, FileName, FilePath, DetectionMethod

```

```jsx
**Physical Media**:
```

```

DeviceEvents
| where DeviceType in ("USB", "External Hard Drive") and ActionType == "Connected"
| where Timestamp > ago(1d)
| project Timestamp, DeviceType, DeviceID, User

```
