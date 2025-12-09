# Threat-Hunt-Port-of-entry
 Flag 1: INITIAL ACCESS - Remote Access Source
Objective: Identify the source IP address of the Remote Desktop Protocol connection.

Flag Value: 88.97.178.12 2025-11-19T00:57:18.3409813Z

Detection Strategy: Query logon events for interactive sessions from external sources during the incident timeframe. Use DeviceLogonEvents table and filter by ActionType or LogonType values indicating remote access.

KQLQuery:

DeviceLogonEvents
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where LogonType == "RemoteInteractive"
| project Timestamp, AccountName, RemoteIP, AdditionalFields
| sort by AccountName
Evidence: image

Why This Matters: Remote Desktop Protocol connections leave network traces that identify the source of unauthorized access. Determining the origin helps with threat actor attribution and blocking ongoing attacks.

🚩 Flag 2: INITIAL ACCESS - Compromised User Account
Objective: Identify the user account that was compromised for initial access.

Flag Value: kenji.sato 2025-11-19T00:57:18.3409813Z

Detection Strategy: In the investigation, the RemoteIP was shown to have accessed the compromised account through the Remote Desktop Protocol.

KQLQuery:

DeviceLogonEvents
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where LogonType == "RemoteInteractive"
| project Timestamp, AccountName, RemoteIP, AdditionalFields
| sort by AccountName
Evidence: image

Why This Matters: Identifying which credentials were compromised determines the scope of unauthorized access and guides remediation efforts including password resets and privilege reviews.

🚩 Flag 3: DISCOVERY - Network Reconnaissance
Objective: Identify the command and argument used to enumerate network neighbours.

Flag Value: ARP.EXE -a 2025-11-19T19:04:01.773778Z

Detection Strategy: Look for commands that reveal local network devices and their hardware addresses. Check DeviceProcessEvents for network enumeration utilities executed after initial access.

KQLQuery:

DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where ProcessCommandLine has_any ("whoami", "hostname", "systeminfo", "ipconfig", "ipconfig /all", "net user", "net localgroup", "query user", "quser", "qwinsta", "wmic", "Get-ComputerInfo", "Get-CimInstance",
 "Get-WmiObject", "Get-NetIPConfiguration", "Get-NetAdapter", "Get-NetIPAddress", "Get-Process", "tasklist", "netstat -ano", "reg query", "Get-Service", "Get-LocalUser", "Get-ChildItem Env:")
 or FileName in~ ("netsh.exe", "ipconfig.exe", "systeminfo.exe", "whoami.exe", "dsquery.exe", "dsget.exe", "nltest.exe", "nbtstat.exe", "arp.exe", "tracert.exe", "quser.exe", "qwinsta.exe")
| project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName, AccountName
| order by Timestamp asc
Evidence: image

Why This Matters: Attackers enumerate network topology to identify lateral movement opportunities and high-value targets. This reconnaissance activity is a key indicator of advanced persistent threats.

🚩 Flag 4: DEFENSE EVASION - Malware Staging Directory
Objective: Find the primary staging directory where malware was stored.

Flag Value: C:\ProgramData\WindowsCache 2025-11-19T19:05:33.7665036Z

Detection Strategy: Search for newly created directories in system folders that were subsequently hidden from normal view. Look for mkdir or New-Item commands followed by attrib commands that modify folder attributes.

KQLQuery:

DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where ProcessCommandLine has_any ("mkdir", "New-Item", "attrib")
| project Timestamp, DeviceName, InitiatingProcessAccountName, FolderCreated=ProcessCommandLine, InitiatingProcessFolderPath
| order by Timestamp asc
Evidence: image

Why This Matters: Attackers establish staging locations to organize tools and stolen data. Identifying these directories reveals the scope of compromise and helps locate additional malicious artifacts.

🚩 Flag 5: DEFENSE EVASION - File Extension Exclusions
Objective: Find how many file extensions were excluded from Windows Defender scanning.

Flag Value: 3 2025-11-19T18:49:27.7301011Z

Detection Strategy: Search DeviceRegistryEvents for registry modifications to Windows Defender's exclusion settings. Look for the RegistryValueName field containing file extensions. Count the unique file extensions added to the "Exclusions\Extensions" registry key during the attack timeline.

KQLQuery:

DeviceRegistryEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where ActionType == "RegistryValueSet"
| where RegistryKey startswith "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Extensions"
| project Timestamp, DeviceName, RegistryKey, RegistryValueData, RegistryValueName
Evidence: image

Why This Matters: Attackers add file extension exclusions to Windows Defender to prevent scanning of malicious files. Counting these exclusions reveals the scope of the attacker's defense evasion strategy.

🚩 Flag 6: DEFENSE EVASION - Temporary Folder Exclusion
Objective: What temporary folder path was excluded from Windows Defender scanning?

Flag Value: C:\Users\KENJI~1.SAT\AppData\Local\Temp 2025-11-19T18:49:27.6830204Z

Detection Strategy: Search DeviceRegistryEvents for folder path exclusions added to Windows Defender configuration. Focus on the RegistryValueName field. Look for temporary folder paths added to the exclusions list during the attack timeline.

KQLQuery:

DeviceRegistryEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where ActionType == "RegistryValueSet"
| where RegistryKey startswith "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths"
| project Timestamp, DeviceName, RegistryKey, RegistryValueData, RegistryValueName, InitiatingProcessFolderPath, InitiatingProcessFileName
Evidence: image

Why This Matters: Attackers add folder path exclusions to Windows Defender to prevent scanning of directories used for downloading and executing malicious tools. These exclusions allow malware to run undetected.

🚩 Flag 7: DEFENSE EVASION - Download Utility Abuse
Objective: Identify the Windows-native binary the attacker abused to download files.

Flag Value: certutil.exe 2025-11-19T19:06:58.5778439Z

Detection Strategy: Look for built-in Windows tools with network download capabilities being used during the attack. Search DeviceProcessEvents for processes with command lines containing URLs and output file paths.

KQLQuery:

DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where ProcessCommandLine has_any ("http://", "https://")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ProcessCommandLine, InitiatingProcessFolderPath, AdditionalFields, InitiatingProcessCommandLine
| order by Timestamp asc
Evidence: image

Why This Matters: Legitimate system utilities are often weaponized to download malware while evading detection. Identifying these techniques helps improve defensive controls.

🚩 Flag 8: PERSISTENCE - Scheduled Task Name
Objective: Identify the name of the scheduled task created for persistence.

Flag Value: Windows Update Check 2025-11-19T19:07:46.9796512Z

Detection Strategy: Search for scheduled task creation commands executed during the attack timeline. Look for schtasks.exe with the /create parameter in DeviceProcessEvents.

KQLQuery:

DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where ProcessCommandLine has_any ("create", "task")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ProcessCommandLine, InitiatingProcessFolderPath, AdditionalFields, InitiatingProcessCommandLine
| order by Timestamp asc
Evidence: image

Why This Matters: Scheduled tasks provide reliable persistence across system reboots. The task name often attempts to blend with legitimate Windows maintenance routines.

🚩 Flag 9: PERSISTENCE - Scheduled Task Target
Objective: Identify the executable path configured in the scheduled task.

Flag Value: C:\ProgramData\WindowsCache\svchost.exe 2025-11-19T19:07:46.9796512Z

Detection Strategy: Extract the task action from the scheduled task creation command line. Look for the /tr parameter value in the schtasks command.

KQLQuery:

DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where ProcessCommandLine has_any ("create", "task")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ProcessCommandLine, InitiatingProcessFolderPath, AdditionalFields, InitiatingProcessCommandLine
| order by Timestamp asc
Evidence: image

Why This Matters: The scheduled task action defines what executes at runtime. This reveals the exact persistence mechanism and the malware location.

🚩 Flag 10: COMMAND & CONTROL - C2 Server Address
Objective: Identify the IP address of the command and control server.

Flag Value: 78.141.196.6 2025-11-19T18:37:26.3725923Z

Detection Strategy: Analyze network connections initiated by the suspicious executable shortly after it was downloaded. Use DeviceNetworkEvents to find outbound connections from the malicious process to external IP addresses.

KQLQuery:

DeviceNetworkEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where RemoteIPType == "Public"
| where InitiatingProcessFileName !in~ ("chrome.exe", "msedge.exe", "firefox.exe", "teams.exe", "outlook.exe")
| project Timestamp, LocalIP, RemoteIP, RemotePort, Protocol, ActionType, InitiatingProcessAccountName, InitiatingProcessCommandLine, InitiatingProcessRemoteSessionDeviceName
| order by Timestamp asc
Evidence: image

Why This Matters: Command and control infrastructure allows attackers to remotely control compromised systems. Identifying C2 servers enables network blocking and infrastructure tracking.

🚩 Flag 11: COMMAND & CONTROL - C2 Communication Port
Objective: Identify the destination port used for command and control communications.

Flag Value: 443 2025-11-19T19:11:04.1766386Z

Detection Strategy: Examine the destination port for outbound connections from the malicious executable. Check DeviceNetworkEvents for the RemotePort field associated with C2 traffic.

KQLQuery:

DeviceNetworkEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where RemoteIP == "78.141.196.6"
| project Timestamp, LocalIP, RemoteIP, RemotePort, Protocol, ActionType, InitiatingProcessAccountName, InitiatingProcessCommandLine, InitiatingProcessRemoteSessionDeviceName
| order by Timestamp asc
Evidence: image

Why This Matters: C2 communication ports can indicate the framework or protocol used. This information supports network detection rules and threat intelligence correlation.

🚩 Flag 12: CREDENTIAL ACCESS - Credential Theft Tool
Objective: Identify the filename of the credential dumping tool.

Flag Value: mm.exe 2025-11-19T19:07:22.8551193Z

Detection Strategy: Look for executables downloaded to the staging directory with very short filenames. Search for files created shortly before LSASS memory access events.

KQLQuery:

DeviceFileEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where FileName endswith ".exe"
| project Timestamp, DeviceName, FileName, ActionType, InitiatingProcessFileName, FolderPath
| order by Timestamp desc
Evidence: image

Why This Matters: Credential dumping tools extract authentication secrets from system memory. These tools are typically renamed to avoid signature-based detection.

🚩 Flag 13: CREDENTIAL ACCESS - Memory Extraction Module
Objective: Identify the module used to extract logon passwords from memory.

Flag Value: sekurlsa::logonpasswords 2025-11-19T19:08:26.2804285Z

Detection Strategy: Examine the command line arguments passed to the credential dumping tool. Look for module::command syntax in the process command line or output redirection.

KQLQuery:

DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where ProcessCommandLine has_any ("cls", "exit")
| project Timestamp, DeviceName, InitiatingProcessAccountName, FileName, ProcessCommandLine, InitiatingProcessFolderPath, AdditionalFields, InitiatingProcessCommandLine
| order by Timestamp asc
Evidence: image

Why This Matters: Credential dumping tools use specific modules to extract passwords from security subsystems. Documenting the exact technique used aids in detection engineering.

🚩 Flag 14: COLLECTION - Data Staging Archive
Objective: Identify the compressed archive filename used for data exfiltration.

Flag Value: export-data.zip 2025-11-19T19:08:58.0244963Z

Detection Strategy: Search for ZIP file creations in the staging directory during the collection phase. Look for Compress-Archive commands or examine files created before exfiltration activity.

KQLQuery:

DeviceFileEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where FileName endswith ".zip"
| project Timestamp, DeviceName, FileName, ActionType, InitiatingProcessFileName, FolderPath
| order by Timestamp desc
Evidence: image

Why This Matters: Attackers compress stolen data for efficient exfiltration. The archive filename often includes dates or descriptive names for the attacker's organization.

🚩 Flag 15: EXFILTRATION - Exfiltration Channel
Objective: Identify the cloud service used to exfiltrate stolen data.

Flag Value: Discord 2025-11-19T19:09:21.3881743Z

Detection Strategy: Analyze outbound HTTPS connections and file upload operations during the exfiltration phase. Check DeviceNetworkEvents for connections to common file sharing or communication platforms.

KQLQuery:

DeviceNetworkEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where InitiatingProcessCommandLine has_any ("https")
| project Timestamp, LocalIP, RemoteIP, RemotePort, Protocol, ActionType, InitiatingProcessAccountName, InitiatingProcessCommandLine, InitiatingProcessRemoteSessionDeviceName, AdditionalFields
| order by Timestamp asc
Evidence: image

Why This Matters: Cloud services with upload capabilities are frequently abused for data theft. Identifying the service helps with incident scope determination and potential data recovery.

🚩 Flag 16: ANTI-FORENSICS - Log Tampering
Objective: Identify the first Windows event log cleared by the attacker.

Flag Value: Security 2025-11-19T19:11:39.0934399Z

Detection Strategy: Search for event log clearing commands near the end of the attack timeline. Look for wevtutil.exe executions and identify which log was cleared first.

KQLQuery:

DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where FileName =~ "wevtutil.exe"
| project Timestamp, DeviceName, InitiatingProcessAccountName, FileName, ProcessCommandLine, InitiatingProcessFolderPath, AdditionalFields, InitiatingProcessCommandLine
| order by Timestamp asc
Evidence: image

Why This Matters: Clearing event logs destroys forensic evidence and impedes investigation efforts. The order of log clearing can indicate attacker priorities and sophistication.

🚩 Flag 17: IMPACT - Persistence Account
Objective: Identify the backdoor account username created by the attacker.

Flag Value: support 2025-11-19T19:09:53.0528848Z

Detection Strategy: Search for account creation commands executed during the impact phase. Look for commands with the /add parameter followed by administrator group additions.

KQLQuery:

DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where ProcessCommandLine has_any ("net user", "/add", "useradd", "username")
| project Timestamp, DeviceName, InitiatingProcessAccountName, FileName, ProcessCommandLine, InitiatingProcessFolderPath, AdditionalFields, InitiatingProcessCommandLine
| order by Timestamp asc
Evidence: image

Why This Matters: Hidden administrator accounts provide alternative access for future operations. These accounts are often configured to avoid appearing in normal user interfaces.

🚩 Flag 18: EXECUTION - Malicious Script
Objective: Identify the PowerShell script file used to automate the attack chain.

Flag Value: wupdate.ps1 2025-11-19T18:49:48.7079818Z

Detection Strategy: Search DeviceFileEvents for script files created in temporary directories during the initial compromise phase. Look for PowerShell or batch script files downloaded from external sources shortly after initial access.

KQLQuery:

| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where FileName endswith ".ps1" or FileName endswith ".bat"
| project Timestamp, DeviceName, FileName, ActionType, InitiatingProcessFileName, FolderPath
| order by Timestamp desc
Evidence: image

Why This Matters: Attackers often use scripting languages to automate their attack chain. Identifying the initial attack script reveals the entry point and automation method used in the compromise.

🚩 Flag 19: LATERAL MOVEMENT - Secondary Target
Objective: What IP address was targeted for lateral movement?

Flag Value: 10.1.0.188 2025-11-19T19:10:42.057693Z

Detection Strategy: Examine the target system specified in remote access commands during lateral movement. Look for IP addresses used with "cmdkey" or "mstsc" commands near the end of the attack timeline.

KQLQuery:

DeviceNetworkEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where InitiatingProcessCommandLine has_any ("cmdkey", "mstsc")
| project Timestamp, LocalIP, RemoteIP, RemotePort, Protocol, ActionType, InitiatingProcessAccountName, InitiatingProcessCommandLine, InitiatingProcessRemoteSessionDeviceName, AdditionalFields
| order by Timestamp asc
Evidence: image

Why This Matters: Lateral movement targets are selected based on their access to sensitive data or network privileges. Identifying these targets reveals attacker objectives.

🚩 Flag 20: LATERAL MOVEMENT - Remote Access Tool
Objective: Identify the remote access tool used for lateral movement.

Flag Value: mstsc.exe 2025-11-19T19:10:41.372526Z

Detection Strategy: Search for remote desktop connection utilities executed near the end of the attack timeline. Look for processes launched with remote system names or IP addresses as arguments.

KQLQuery:

DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where ProcessCommandLine matches regex @"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"
| project Timestamp, DeviceName, InitiatingProcessAccountName, FileName, ProcessCommandLine, InitiatingProcessFolderPath, AdditionalFields, InitiatingProcessCommandLine
| order by Timestamp asc
Evidence: image

Why This Matters: Built-in remote access tools are preferred for lateral movement as they blend with legitimate administrative activity. This technique is harder to detect than custom tools.
