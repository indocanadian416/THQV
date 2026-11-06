/*
 * Threat hunting query library.
 *
 * Every KQL query in this file is parsed and type-checked against the
 * documented table schemas by tests/queries.test.js (Microsoft's own Kusto
 * parser), so a typo, a missing column or a broken operator fails CI.
 * CrowdStrike queries use Falcon LogScale (CQL) syntax and are linted for
 * legacy SPL constructs.
 *
 * Queries are written with String.raw so backslashes are literal: what you
 * see here is exactly what gets copied into the SIEM.
 */
(function (root, factory) {
  const api = factory();
  if (typeof module === 'object' && module.exports) module.exports = api;
  else root.THQV = Object.assign(root.THQV || {}, api);
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  const PLATFORMS = {
    sentinel: { label: 'Microsoft Sentinel (KQL)', language: 'kql' },
    defender: { label: 'Microsoft Defender XDR Advanced Hunting (KQL)', language: 'kql' },
    crowdstrike: { label: 'CrowdStrike Falcon LogScale (CQL)', language: 'logscale' }
  };

  const huntingQueries = {
    sentinel: {
      'Credential Access': [
        {
          name: 'MFA Fatigue - Repeated MFA Denials',
          mitre: ['T1621'],
          requires: 'Microsoft Entra ID sign-in logs (SigninLogs)',
          desc: 'Users receiving and denying a burst of MFA prompts - a sign an attacker already has the password and is spamming push notifications.',
          query: String.raw`// Hunt: MFA fatigue / push spam
// MITRE: T1621 - Multi-Factor Authentication Request Generation
// Result 500121 = "Authentication failed during strong authentication request"
SigninLogs
| where TimeGenerated > ago(1d)
| where ResultType == "500121"
| summarize DenialCount = count(),
            SourceIPs = make_set(IPAddress, 10),
            Locations = make_set(Location, 10),
            Apps = make_set(AppDisplayName, 10)
    by UserPrincipalName, bin(TimeGenerated, 10m)
| where DenialCount >= 5
| join kind=leftouter (
    SigninLogs
    | where TimeGenerated > ago(1d)
    | where ResultType == "0"
    | summarize LastSuccess = max(TimeGenerated) by UserPrincipalName
  ) on UserPrincipalName
| extend SucceededAfterDenials = LastSuccess > TimeGenerated
| project TimeGenerated, UserPrincipalName, DenialCount, SucceededAfterDenials, LastSuccess, SourceIPs, Locations, Apps
| order by DenialCount desc
// TUNE: DenialCount threshold and the 10m window to your baseline
// VALIDATE: SucceededAfterDenials == true is the high-priority case (user gave in)`
        },
        {
          name: 'Credential Dumping - LSASS Memory Access Tools',
          mitre: ['T1003.001'],
          requires: 'Microsoft Defender XDR connector (DeviceProcessEvents)',
          desc: 'Command lines that dump LSASS memory: procdump against lsass, comsvcs.dll MiniDump, or Mimikatz keywords.',
          query: String.raw`// Hunt: LSASS memory dumping
// MITRE: T1003.001 - OS Credential Dumping: LSASS Memory
DeviceProcessEvents
| where TimeGenerated > ago(7d)
| where (FileName in~ ("procdump.exe", "procdump64.exe") and ProcessCommandLine has "lsass")
    or (FileName =~ "rundll32.exe" and ProcessCommandLine has "comsvcs" and ProcessCommandLine has "minidump")
    or ProcessCommandLine has_any ("sekurlsa", "logonpasswords", "lsadump")
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by TimeGenerated desc
// VALIDATE: Approved crash-dump/PAM tooling may match - correlate with change tickets
// ESCALATE: comsvcs.dll MiniDump is rarely legitimate`
        },
        {
          name: 'Password Spray - Many Accounts From One IP',
          mitre: ['T1110.003'],
          requires: 'Microsoft Entra ID sign-in logs (SigninLogs)',
          desc: 'A single source IP failing passwords against many different accounts in a short window.',
          query: String.raw`// Hunt: Password spraying
// MITRE: T1110.003 - Brute Force: Password Spraying
// 50126 = invalid username or password, 50053 = account locked / malicious IP
SigninLogs
| where TimeGenerated > ago(1d)
| where ResultType in ("50126", "50053")
| summarize FailedAccounts = dcount(UserPrincipalName),
            FailureCount = count(),
            AttemptedUsers = make_set(UserPrincipalName, 25),
            UserAgents = make_set(UserAgent, 5)
    by IPAddress, bin(TimeGenerated, 30m)
| where FailedAccounts >= 10
| order by FailedAccounts desc
// TUNE: FailedAccounts threshold relative to org size
// ENRICH: Join with ThreatIntelIndicators / ThreatIntelligenceIndicator for known-bad IPs`
        },
        {
          name: 'Kerberoasting - RC4 Service Ticket Requests',
          mitre: ['T1558.003'],
          requires: 'Windows Security events from domain controllers (SecurityEvent 4769)',
          desc: 'One account requesting RC4-encrypted (0x17) service tickets for many SPNs - the classic Kerberoasting pattern.',
          query: String.raw`// Hunt: Kerberoasting
// MITRE: T1558.003 - Steal or Forge Kerberos Tickets: Kerberoasting
// SecurityEvent has no TicketEncryptionType column, so it is parsed from EventData.
SecurityEvent
| where TimeGenerated > ago(1d)
| where EventID == 4769
| extend TicketEncryptionType = extract(@"Name=""TicketEncryptionType"">(0x[0-9A-Fa-f]+)<", 1, EventData),
         TicketStatus = extract(@"Name=""Status"">(0x[0-9A-Fa-f]+)<", 1, EventData)
| where TicketEncryptionType == "0x17" and TicketStatus == "0x0"
| where ServiceName !endswith "$" and ServiceName != "krbtgt"
| summarize SPNCount = dcount(ServiceName), SPNs = make_set(ServiceName, 25),
            FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated)
    by TargetUserName, IpAddress
| where SPNCount >= 5
| order by SPNCount desc
// TUNE: SPNCount threshold; legacy apps that still need RC4 will appear here
// HARDEN: Move service accounts to AES-only / gMSA`
        },
        {
          name: 'DCSync - Replication Rights Used by Non-DC Account',
          mitre: ['T1003.006'],
          requires: 'SecurityEvent 4662 with "Audit Directory Service Access" enabled on DCs',
          desc: 'Directory replication (DS-Replication-Get-Changes*) requested by a user account rather than a domain controller.',
          query: String.raw`// Hunt: DCSync
// MITRE: T1003.006 - OS Credential Dumping: DCSync
let ReplicationGuids = dynamic([
    "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2",   // DS-Replication-Get-Changes
    "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2",   // DS-Replication-Get-Changes-All
    "89e95b76-444d-4c62-991a-0facbeda640c"    // DS-Replication-Get-Changes-In-Filtered-Set
]);
SecurityEvent
| where TimeGenerated > ago(7d)
| where EventID == 4662
| where Properties has_any (ReplicationGuids)
| where SubjectUserName !endswith "$"          // DC computer accounts replicate legitimately
| project TimeGenerated, Computer, SubjectUserName, SubjectDomainName, ObjectName, Properties
| order by TimeGenerated desc
// VALIDATE: Entra Connect / AAD Connect sync accounts replicate legitimately - exclude them by name
// ESCALATE: Any other user account here is high severity`
        }
      ],
      'Lateral Movement': [
        {
          name: 'RDP Logon From Unexpected Country',
          mitre: ['T1021.001'],
          requires: 'Windows Security events (SecurityEvent 4624)',
          desc: 'Successful RDP (logon type 10) from public IPs located outside your expected countries.',
          query: String.raw`// Hunt: Anomalous RDP geolocation
// MITRE: T1021.001 - Remote Services: Remote Desktop Protocol
let ExpectedCountries = dynamic(["United States", "Canada"]);   // TUNE
SecurityEvent
| where TimeGenerated > ago(1d)
| where EventID == 4624 and LogonType == 10
| where isnotempty(IpAddress) and IpAddress !in ("-", "127.0.0.1", "::1")
| where ipv4_is_private(IpAddress) == false
| extend Country = tostring(geo_info_from_ip_address(IpAddress).country)
| where isnotempty(Country) and Country !in (ExpectedCountries)
| summarize LogonCount = count(), FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated)
    by Account, IpAddress, Country, Computer
| order by LastSeen desc
// NOTE: IPv6 sources are skipped by ipv4_is_private - add an ipv6 branch if you expose RDP over IPv6
// VALIDATE: Travel and VPN exit nodes - keep an allow-list of corporate egress IPs`
        },
        {
          name: 'Admin Share Access Across Many Hosts',
          mitre: ['T1021.002'],
          requires: 'SecurityEvent 5140 ("Audit File Share" enabled)',
          desc: 'One account touching C$ / ADMIN$ on several machines - typical of PsExec-style lateral movement.',
          query: String.raw`// Hunt: Administrative share access
// MITRE: T1021.002 - Remote Services: SMB/Windows Admin Shares
SecurityEvent
| where TimeGenerated > ago(1d)
| where EventID == 5140
| where ShareName endswith @"\C$" or ShareName endswith @"\ADMIN$"
| where SubjectUserName !endswith "$"
| summarize TargetHosts = dcount(Computer), Hosts = make_set(Computer, 25),
            Shares = make_set(ShareName), FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated)
    by SubjectUserName, IpAddress
| where TargetHosts >= 3
| order by TargetHosts desc
// VALIDATE: Software deployment and backup service accounts - exclude them explicitly
// ENRICH: Look for 7045 service installs on the same hosts shortly after`
        }
      ],
      'Persistence': [
        {
          name: 'Registry Run Key Modification',
          mitre: ['T1547.001'],
          requires: 'Microsoft Defender XDR connector (DeviceRegistryEvents)',
          desc: 'New values written to Run / RunOnce keys by something other than an installer.',
          query: String.raw`// Hunt: Registry Run key persistence
// MITRE: T1547.001 - Boot or Logon Autostart Execution: Registry Run Keys
DeviceRegistryEvents
| where TimeGenerated > ago(7d)
| where ActionType == "RegistryValueSet"
| where RegistryKey contains @"\Software\Microsoft\Windows\CurrentVersion\Run"
| where InitiatingProcessFileName !in~ ("msiexec.exe", "setup.exe", "OneDriveSetup.exe")   // TUNE
| project TimeGenerated, DeviceName, RegistryKey, RegistryValueName, RegistryValueData,
          InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName
| order by TimeGenerated desc
// TUNE: Baseline your software deployment tooling
// PRIORITISE: Values pointing into AppData, Temp, ProgramData or using powershell/mshta`
        },
        {
          name: 'Scheduled Task Created Outside Business Hours',
          mitre: ['T1053.005'],
          requires: 'Microsoft Defender XDR connector (DeviceProcessEvents)',
          desc: 'schtasks.exe /create run after hours - persistence often lands when nobody is watching.',
          query: String.raw`// Hunt: After-hours scheduled task creation
// MITRE: T1053.005 - Scheduled Task/Job: Scheduled Task
DeviceProcessEvents
| where TimeGenerated > ago(7d)
| where FileName =~ "schtasks.exe" and ProcessCommandLine contains "/create"
| where hourofday(TimeGenerated) !between (8 .. 18)        // UTC - TUNE to your business hours
| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
| order by TimeGenerated desc
// VALIDATE: Patch and backup tooling legitimately creates tasks after hours`
        }
      ],
      'Exfiltration': [
        {
          name: 'Large Upload to Cloud Storage (Proxy/Firewall)',
          mitre: ['T1567.002'],
          requires: 'Proxy or firewall logs in CommonSecurityLog (CEF) with SentBytes',
          desc: 'More than 100 MB sent to consumer file-sharing services by a single user/host in a day.',
          query: String.raw`// Hunt: Exfiltration to cloud storage
// MITRE: T1567.002 - Exfiltration Over Web Service: Exfiltration to Cloud Storage
// DeviceNetworkEvents has no byte counts - proxy/firewall logs are required for volume.
let CloudStorage = dynamic(["dropbox.com", "drive.google.com", "onedrive.live.com", "box.com", "mega.nz", "wetransfer.com"]);
CommonSecurityLog
| where TimeGenerated > ago(1d)
| where DestinationHostName has_any (CloudStorage) or RequestURL has_any (CloudStorage)
| summarize TotalBytesSent = sum(SentBytes), Requests = count()
    by SourceIP, SourceUserName, DestinationHostName
| where TotalBytesSent > 104857600                       // 100 MB - TUNE
| extend TotalMB = round(TotalBytesSent / 1048576.0, 1)
| project SourceIP, SourceUserName, DestinationHostName, TotalMB, Requests
| order by TotalMB desc
// VALIDATE: Sanctioned OneDrive/Box tenants - exclude your corporate tenant URLs`
        },
        {
          name: 'DNS Tunneling - Long, Unique Subdomains',
          mitre: ['T1071.004', 'T1048'],
          requires: 'Windows DNS server logs (DnsEvents)',
          desc: 'Clients generating many long, unique subdomains under one parent domain - typical of DNS tunnelling/exfiltration.',
          query: String.raw`// Hunt: DNS tunnelling
// MITRE: T1071.004 - Application Layer Protocol: DNS / T1048 - Exfiltration Over Alternative Protocol
DnsEvents
| where TimeGenerated > ago(1d)
| where SubType == "LookupQuery"
| where strlen(Name) > 50
| extend Labels = split(Name, ".")
| extend ParentDomain = strcat(tostring(Labels[-2]), ".", tostring(Labels[-1]))
| summarize Queries = count(), UniqueNames = dcount(Name), AvgLength = avg(strlen(Name))
    by ClientIP, ParentDomain
| where UniqueNames > 50
| order by UniqueNames desc
// TUNE: Two-label parent extraction is naive for co.uk-style suffixes
// VALIDATE: CDNs, AV cloud lookups and telemetry services use long names - allow-list them`
        }
      ],
      'Initial Access': [
        {
          name: 'Email Attachment Executed Soon After Delivery',
          mitre: ['T1566.001', 'T1204.002'],
          requires: 'Defender XDR connector (EmailAttachmentInfo + DeviceProcessEvents)',
          desc: 'A file delivered as an email attachment is executed (same SHA256) within an hour of delivery.',
          query: String.raw`// Hunt: Attachment delivery -> execution
// MITRE: T1566.001 - Spearphishing Attachment / T1204.002 - User Execution: Malicious File
let Attachments = EmailAttachmentInfo
    | where TimeGenerated > ago(1d)
    | where isnotempty(SHA256)
    | project EmailTime = TimeGenerated, NetworkMessageId, SenderFromAddress, RecipientEmailAddress,
              AttachmentName = FileName, SHA256;
DeviceProcessEvents
| where TimeGenerated > ago(1d)
| where isnotempty(SHA256)
| join kind=inner Attachments on SHA256
| where TimeGenerated between (EmailTime .. (EmailTime + 1h))
| project TimeGenerated, DeviceName, AccountName, AttachmentName, FileName, FolderPath, ProcessCommandLine,
          SenderFromAddress, RecipientEmailAddress, NetworkMessageId
| order by TimeGenerated desc
// NOTE: Archives (zip/iso) execute their contents, which have different hashes -
//       pivot on DeviceFileEvents for files extracted from the attachment
// ENRICH: Check SHA256 in VirusTotal / MalwareBazaar from the OSINT tab`
        }
      ]
    },

    defender: {
      'Credential Access': [
        {
          name: 'Kerberoasting Recon - SPN Enumeration via LDAP',
          mitre: ['T1558.003', 'T1087.002'],
          requires: 'Microsoft Defender for Identity (IdentityQueryEvents)',
          desc: 'LDAP queries enumerating servicePrincipalName - the reconnaissance step before Kerberoasting.',
          query: String.raw`// Hunt: SPN enumeration (Kerberoasting precursor)
// MITRE: T1558.003 - Kerberoasting / T1087.002 - Domain Account Discovery
IdentityQueryEvents
| where Timestamp > ago(1d)
| where ActionType == "LDAP query"
| where Query contains "servicePrincipalName"
| summarize Queries = count(), Samples = make_set(Query, 5), Targets = make_set(DestinationDeviceName, 5)
    by AccountUpn, DeviceName, IPAddress
| order by Queries desc
// VALIDATE: Management/monitoring tools enumerate SPNs - allow-list their hosts
// CORRELATE: Same account requesting many RC4 tickets (see the Sentinel 4769 hunt)`
        },
        {
          name: 'DCSync - Replication From Non-DC Device',
          mitre: ['T1003.006'],
          requires: 'Microsoft Defender for Identity (IdentityDirectoryEvents)',
          desc: 'Directory replication activity whose source device is not one of your domain controllers.',
          query: String.raw`// Hunt: DCSync via Defender for Identity
// MITRE: T1003.006 - OS Credential Dumping: DCSync
// Check the exact ActionType in the portal schema reference (Advanced hunting > Schema)
let DomainControllers = dynamic(["dc01.contoso.com", "dc02.contoso.com"]);   // TUNE: your DC FQDNs
IdentityDirectoryEvents
| where Timestamp > ago(7d)
| where ActionType has "replication"
| where DeviceName !in~ (DomainControllers)
| project Timestamp, ActionType, AccountUpn, AccountName, DeviceName, IPAddress,
          DestinationDeviceName, AdditionalFields
| order by Timestamp desc
// ALSO: Defender for Identity raises "Suspected DCSync attack" (external ID 2006) - check AlertInfo`
        }
      ],
      'Execution': [
        {
          name: 'Living-off-the-Land Binaries (LOLBins) Downloading or Proxying',
          mitre: ['T1218', 'T1105'],
          requires: 'Microsoft Defender for Endpoint (DeviceProcessEvents)',
          desc: 'certutil, bitsadmin, regsvr32, mshta and rundll32 used to download, decode or proxy-execute content.',
          query: String.raw`// Hunt: LOLBin abuse
// MITRE: T1218 - System Binary Proxy Execution / T1105 - Ingress Tool Transfer
DeviceProcessEvents
| where Timestamp > ago(1d)
| where FileName in~ ("certutil.exe", "bitsadmin.exe", "regsvr32.exe", "mshta.exe", "rundll32.exe")
| where ProcessCommandLine has_any ("http", "urlcache", "decode", "scrobj", "transfer", "javascript")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
// VALIDATE: Some admin scripts use certutil -decode - exclude by script path/hash`
        },
        {
          name: 'Obfuscated or Encoded PowerShell',
          mitre: ['T1059.001', 'T1027'],
          requires: 'Microsoft Defender for Endpoint (DeviceProcessEvents)',
          desc: 'PowerShell combining at least two of: encoded command, download cradle, IEX/FromBase64, hidden/bypass flags.',
          query: String.raw`// Hunt: Obfuscated PowerShell
// MITRE: T1059.001 - PowerShell / T1027 - Obfuscated Files or Information
DeviceProcessEvents
| where Timestamp > ago(1d)
| where FileName in~ ("powershell.exe", "pwsh.exe", "powershell_ise.exe")
| extend Encoded  = ProcessCommandLine matches regex @"(?i)\s-e[a-z]*\s+[A-Za-z0-9+/=]{20,}"
| extend Download = ProcessCommandLine has_any ("DownloadString", "DownloadFile", "Invoke-WebRequest", "Net.WebClient", "Start-BitsTransfer")
| extend Exec     = ProcessCommandLine has_any ("IEX", "Invoke-Expression", "FromBase64String")
| extend Stealth  = ProcessCommandLine has_any ("hidden", "bypass", "nop", "noprofile")
| extend Score = toint(Encoded) + toint(Download) + toint(Exec) + toint(Stealth)
| where Score >= 2 or strlen(ProcessCommandLine) > 1000
| project Timestamp, DeviceName, AccountName, Score, ProcessCommandLine, InitiatingProcessFileName
| order by Score desc, Timestamp desc
// TUNE: Exclude known management agents (SCCM/Intune scripts) by InitiatingProcessFileName`
        }
      ],
      'Defense Evasion': [
        {
          name: 'Microsoft Defender Tampering',
          mitre: ['T1562.001'],
          requires: 'Microsoft Defender for Endpoint (DeviceProcessEvents)',
          desc: 'Commands that disable Defender protections or add broad exclusions.',
          query: String.raw`// Hunt: Defender tampering
// MITRE: T1562.001 - Impair Defenses: Disable or Modify Tools
DeviceProcessEvents
| where Timestamp > ago(7d)
| where ProcessCommandLine has_any (
    "DisableRealtimeMonitoring", "DisableBehaviorMonitoring", "DisableIOAVProtection",
    "DisableAntiSpyware", "Add-MpPreference", "sc config windefend", "sc stop windefend")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
// VALIDATE: IT troubleshooting and some installers add exclusions - review Add-MpPreference paths
// ESCALATE: Disabling real-time monitoring is high priority`
        },
        {
          name: 'Windows Event Log Clearing',
          mitre: ['T1070.001'],
          requires: 'Microsoft Defender for Endpoint (DeviceProcessEvents)',
          desc: 'wevtutil cl / Clear-EventLog / Remove-EventLog - attackers clearing tracks.',
          query: String.raw`// Hunt: Event log clearing
// MITRE: T1070.001 - Indicator Removal: Clear Windows Event Logs
DeviceProcessEvents
| where Timestamp > ago(7d)
| where (FileName =~ "wevtutil.exe" and ProcessCommandLine has_any ("cl", "clear-log"))
    or ProcessCommandLine has_any ("Clear-EventLog", "Remove-EventLog")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
// ALSO: SecurityEvent 1102 (Security log cleared) in Sentinel
// ENRICH: Look at what else happened on the host in the hour before`
        }
      ],
      'Impact': [
        {
          name: 'Ransomware Precursor - Shadow Copy / Recovery Deletion',
          mitre: ['T1490'],
          requires: 'Microsoft Defender for Endpoint (DeviceProcessEvents)',
          desc: 'vssadmin/wmic/bcdedit/wbadmin commands that remove recovery options right before encryption.',
          query: String.raw`// Hunt: Inhibit system recovery
// MITRE: T1490 - Inhibit System Recovery
DeviceProcessEvents
| where Timestamp > ago(7d)
| where (FileName =~ "vssadmin.exe" and ProcessCommandLine has "delete" and ProcessCommandLine has "shadows")
    or (FileName =~ "wmic.exe" and ProcessCommandLine has "shadowcopy" and ProcessCommandLine has "delete")
    or (FileName =~ "bcdedit.exe" and ProcessCommandLine has_any ("recoveryenabled", "ignoreallfailures"))
    or (FileName =~ "wbadmin.exe" and ProcessCommandLine has "delete")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
// ESCALATE: Treat as an active ransomware incident until proven otherwise`
        }
      ]
    },

    crowdstrike: {
      'Execution': [
        {
          name: 'Office Application Spawning a Script Interpreter',
          mitre: ['T1059', 'T1204.002'],
          requires: 'Falcon Insight / Next-Gen SIEM (ProcessRollup2)',
          desc: 'Word, Excel, PowerPoint or Outlook launching cmd, PowerShell, wscript, mshta and similar.',
          query: String.raw`// Hunt: Office -> interpreter process chain
// MITRE: T1059 - Command and Scripting Interpreter / T1204.002 - Malicious File
// Language: Falcon LogScale (Advanced Event Search / Next-Gen SIEM)
#event_simpleName=ProcessRollup2
| in(field="ParentBaseFileName", values=["winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe"], ignoreCase=true)
| in(field="FileName", values=["powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe"], ignoreCase=true)
| table([@timestamp, ComputerName, UserName, ParentBaseFileName, FileName, CommandLine], limit=1000)
// TUNE: Some business macros legitimately call cmd.exe - exclude by CommandLine pattern
// VALIDATE: Check the document's origin (email, download, share)`
        },
        {
          name: 'C2 Beaconing - High-Frequency Connections to Few IPs',
          mitre: ['T1071.001', 'T1573'],
          requires: 'Falcon Insight / Next-Gen SIEM (NetworkConnectIP4)',
          desc: 'A host connecting to the same external IP/port many times over several hours - candidate Cobalt Strike-style beacon.',
          query: String.raw`// Hunt: Beaconing candidates
// MITRE: T1071.001 - Web Protocols / T1573 - Encrypted Channel
// Language: Falcon LogScale
#event_simpleName=NetworkConnectIP4
| in(field="RemotePort", values=["80", "443", "8080", "8443"])
| !cidr(RemoteAddressIP4, subnet=["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16"])
| groupBy([aid, ComputerName, RemoteAddressIP4, RemotePort], function=[count(as=Connections), min(@timestamp, as=FirstSeen), max(@timestamp, as=LastSeen)], limit=max)
| SpanHours := (LastSeen - FirstSeen) / 3600000
| Connections > 50
| SpanHours > 4
| AvgIntervalSec := ((LastSeen - FirstSeen) / 1000) / Connections
| sort(Connections, order=desc, limit=200)
// NEXT: For top hits, look at the spread of intervals (low jitter = beacon)
// ENRICH: Look up RemoteAddressIP4 in the OSINT tab (GreyNoise, Shodan, ThreatFox)`
        }
      ],
      'Persistence': [
        {
          name: 'WMI Event Subscription Persistence',
          mitre: ['T1546.003'],
          requires: 'Falcon Insight / Next-Gen SIEM (ProcessRollup2)',
          desc: 'Processes creating WMI filters/consumers/bindings, or scripts run by the WMI script consumer host (scrcons.exe).',
          query: String.raw`// Hunt: WMI event subscription persistence
// MITRE: T1546.003 - Event Triggered Execution: WMI Event Subscription
// Language: Falcon LogScale
#event_simpleName=ProcessRollup2
| CommandLine=/(__EventFilter|EventConsumer|__FilterToConsumerBinding|root\\subscription|Register-WmiEvent|Set-WmiInstance)/i
    or ParentBaseFileName=/^scrcons\.exe$/i
| table([@timestamp, ComputerName, UserName, ParentBaseFileName, FileName, CommandLine], limit=1000)
// VALIDATE: Monitoring/management agents register WMI consumers - baseline them
// ALSO: Falcon detections tagged T1546.003 in the Endpoint Detections page`
        }
      ],
      'Credential Access': [
        {
          name: 'Browser Credential Store Accessed by Non-Browser',
          mitre: ['T1555.003'],
          requires: 'Falcon Insight with file-open telemetry (FileOpenInfo) + ProcessRollup2',
          desc: 'Login Data / Cookies / logins.json / key4.db opened by a process that is not a browser - typical infostealer behaviour.',
          query: String.raw`// Hunt: Browser credential theft
// MITRE: T1555.003 - Credentials from Password Stores: Credentials from Web Browsers
// Language: Falcon LogScale
#event_simpleName=FileOpenInfo
| TargetFileName=/\\(Login Data|Cookies|Web Data|logins\.json|key4\.db|cookies\.sqlite)$/i
| join(query={#event_simpleName=ProcessRollup2}, field=[aid, ContextProcessId], key=[aid, TargetProcessId], include=[ImageFileName])
| ImageFileName!=/\\(chrome|msedge|firefox|brave|opera|vivaldi)\.exe$/i
| table([@timestamp, ComputerName, UserName, ImageFileName, TargetFileName], limit=1000)
// NOTE: FileOpenInfo is not collected by default on every sensor policy
// VALIDATE: Backup and password-manager software may read these files`
        }
      ]
    }
  };

  /** Summary numbers for the stats tiles - computed, never hard-coded. */
  function queryStats(db) {
    const data = db || huntingQueries;
    const categories = new Set();
    const techniques = new Set();
    let total = 0;
    Object.values(data).forEach((cats) => {
      Object.entries(cats).forEach(([cat, list]) => {
        categories.add(cat);
        list.forEach((q) => { total++; q.mitre.forEach((t) => techniques.add(t)); });
      });
    });
    return { platforms: Object.keys(data).length, categories: categories.size, queries: total, techniques: techniques.size };
  }

  return { PLATFORMS, huntingQueries, queryStats };
});
