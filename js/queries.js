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

  /* ------------------------------------------------------------------
   * Extended library (v2.1). Merged into huntingQueries below so the
   * category lists stay in one place for the UI. Same rules apply: every
   * KQL query is parsed and type-checked in tests/queries.test.js.
   * `triage: true` marks correlation/triage hunts that span many techniques.
   * ------------------------------------------------------------------ */
  const extendedQueries = {
    sentinel: {
      'Initial Access': [
        {
          name: 'Legacy Authentication Sign-ins (MFA Bypass Path)',
          mitre: ['T1078.004', 'T1110.003'],
          requires: 'Microsoft Entra ID sign-in logs (SigninLogs)',
          desc: 'Sign-ins over IMAP/POP/SMTP/ActiveSync and other legacy protocols that cannot do MFA - the favourite path for password spraying.',
          query: String.raw`// Hunt: Legacy authentication usage
// MITRE: T1078.004 - Valid Accounts: Cloud Accounts / T1110.003 - Password Spraying
let LegacyClients = dynamic(["Exchange ActiveSync", "IMAP4", "POP3", "Authenticated SMTP", "Exchange Web Services",
    "MAPI Over HTTP", "Offline Address Book", "Other clients", "AutoDiscover", "Exchange Online PowerShell"]);
SigninLogs
| where TimeGenerated > ago(7d)
| where ClientAppUsed in (LegacyClients)
| summarize Attempts = count(), Successes = countif(ResultType == "0"),
            Users = dcount(UserPrincipalName), SampleUsers = make_set(UserPrincipalName, 10)
    by IPAddress, ClientAppUsed
| order by Successes desc, Attempts desc
// HARDEN: Block legacy auth with Conditional Access; this hunt finds what still uses it
// PRIORITISE: Successes > 0 from unfamiliar IPs`
        },
        {
          name: 'Successful Sign-ins From Multiple Countries in One Hour',
          mitre: ['T1078.004'],
          requires: 'Microsoft Entra ID sign-in logs (SigninLogs)',
          desc: 'The same account signing in successfully from two or more countries within an hour - stolen session or credential use.',
          query: String.raw`// Hunt: Impossible-travel style sign-ins
// MITRE: T1078.004 - Valid Accounts: Cloud Accounts
SigninLogs
| where TimeGenerated > ago(1d)
| where ResultType == "0"
| extend Country = tostring(LocationDetails.countryOrRegion)
| where isnotempty(Country)
| summarize Countries = dcount(Country), CountryList = make_set(Country, 10), IPs = make_set(IPAddress, 10),
            Apps = make_set(AppDisplayName, 10)
    by UserPrincipalName, bin(TimeGenerated, 1h)
| where Countries >= 2
| order by Countries desc
// VALIDATE: VPN split tunnelling and mobile carriers can geolocate oddly - check the IPs`
        }
      ],
      'Credential Access': [
        {
          name: 'On-Prem Brute Force Followed by Success',
          mitre: ['T1110.001'],
          requires: 'Windows Security events (SecurityEvent 4625 / 4624)',
          desc: 'Twenty or more failed logons for an account from one source, followed by a successful logon within an hour.',
          query: String.raw`// Hunt: Brute force that worked
// MITRE: T1110.001 - Brute Force: Password Guessing
let Failures = SecurityEvent
    | where TimeGenerated > ago(1d)
    | where EventID == 4625
    | summarize FailedCount = count(), FirstFail = min(TimeGenerated), LastFail = max(TimeGenerated)
        by TargetAccount, IpAddress, Computer
    | where FailedCount >= 20;
SecurityEvent
| where TimeGenerated > ago(1d)
| where EventID == 4624 and LogonType in (3, 10)
| project SuccessTime = TimeGenerated, TargetAccount, IpAddress, Computer, LogonType
| join kind=inner Failures on TargetAccount, IpAddress, Computer
| where SuccessTime between (LastFail .. (LastFail + 1h))
| project SuccessTime, TargetAccount, IpAddress, Computer, LogonType, FailedCount, FirstFail, LastFail
| order by FailedCount desc
// ESCALATE: A success right after a burst of failures from the same IP`
        }
      ],
      'Privilege Escalation': [
        {
          name: 'Member Added to a Privileged AD Group',
          mitre: ['T1098'],
          requires: 'Windows Security events from DCs/servers (SecurityEvent 4728/4732/4756)',
          desc: 'Accounts added to Domain Admins, Enterprise Admins, local Administrators and other high-privilege groups.',
          query: String.raw`// Hunt: Privileged group membership changes
// MITRE: T1098 - Account Manipulation
let PrivilegedGroups = dynamic(["Administrators", "Domain Admins", "Enterprise Admins", "Schema Admins",
    "Account Operators", "Backup Operators", "Server Operators", "DnsAdmins", "Group Policy Creator Owners"]);
SecurityEvent
| where TimeGenerated > ago(7d)
| where EventID in (4728, 4732, 4756)      // added to global / local / universal security group
| where TargetUserName in~ (PrivilegedGroups)
| project TimeGenerated, Computer, Group = TargetUserName, AddedMember = MemberName, MemberSid,
          AddedBy = SubjectUserName, EventID
| order by TimeGenerated desc
// VALIDATE: Match each change to an approved access request`
        }
      ],
      'Persistence': [
        {
          name: 'Suspicious Service Installed (4697)',
          mitre: ['T1543.003'],
          requires: 'SecurityEvent 4697 ("Audit Security System Extension" enabled)',
          desc: 'New services whose binary path runs a script host, shell or a file in a user-writable folder.',
          query: String.raw`// Hunt: Malicious service installation
// MITRE: T1543.003 - Create or Modify System Process: Windows Service
SecurityEvent
| where TimeGenerated > ago(7d)
| where EventID == 4697
| extend Path = tolower(ServiceFileName)
| where Path has_any ("powershell", "cmd.exe", "rundll32", "mshta", "regsvr32", "comspec", "appdata", "temp", "public", "programdata")
| project TimeGenerated, Computer, ServiceName, ServiceFileName, ServiceAccount, SubjectUserName
| order by TimeGenerated desc
// ALSO: System log event 7045 carries the same data if you collect the Event table`
        },
        {
          name: 'Account Created and Deleted Within 24 Hours',
          mitre: ['T1136.002', 'T1070'],
          requires: 'Windows Security events from DCs (SecurityEvent 4720 / 4726)',
          desc: 'Short-lived domain accounts - attackers create an account, use it, and delete it to cover tracks.',
          query: String.raw`// Hunt: Short-lived accounts
// MITRE: T1136.002 - Create Account: Domain Account / T1070 - Indicator Removal
let Created = SecurityEvent
    | where TimeGenerated > ago(7d)
    | where EventID == 4720
    | project CreatedTime = TimeGenerated, TargetSid, NewAccount = TargetUserName, CreatedBy = SubjectUserName, Computer;
SecurityEvent
| where TimeGenerated > ago(7d)
| where EventID == 4726
| project DeletedTime = TimeGenerated, TargetSid, DeletedBy = SubjectUserName
| join kind=inner Created on TargetSid
| where DeletedTime between (CreatedTime .. (CreatedTime + 24h))
| extend Lifetime = DeletedTime - CreatedTime
| project CreatedTime, DeletedTime, Lifetime, NewAccount, CreatedBy, DeletedBy, Computer
| order by CreatedTime desc`
        }
      ],
      'Defense Evasion': [
        {
          name: 'Security Event Log Cleared (1102)',
          mitre: ['T1070.001'],
          requires: 'Windows Security events (SecurityEvent 1102)',
          desc: 'The Security log being cleared - almost never legitimate on servers outside a documented procedure.',
          query: String.raw`// Hunt: Security log cleared
// MITRE: T1070.001 - Indicator Removal: Clear Windows Event Logs
SecurityEvent
| where TimeGenerated > ago(30d)
| where EventID == 1102
| project TimeGenerated, Computer, Account, SubjectUserName, SubjectDomainName, Activity, EventData
| order by TimeGenerated desc
// ENRICH: Pull everything from the host in the 2 hours before the clear`
        }
      ],
      'Identity & Cloud': [
        {
          name: 'Privileged Entra ID Role Assigned',
          mitre: ['T1098.003'],
          requires: 'Microsoft Entra ID audit logs (AuditLogs)',
          desc: 'Global Administrator, Privileged Role Administrator and other powerful roles granted (directly or via PIM).',
          query: String.raw`// Hunt: Privileged role assignment
// MITRE: T1098.003 - Account Manipulation: Additional Cloud Roles
let PrivilegedRoles = dynamic(["Global Administrator", "Privileged Role Administrator", "Security Administrator",
    "Exchange Administrator", "Application Administrator", "Cloud Application Administrator", "User Administrator"]);
AuditLogs
| where TimeGenerated > ago(7d)
| where OperationName in ("Add member to role", "Add eligible member to role", "Add member to role completed (PIM activation)")
| mv-expand Target = TargetResources
| mv-expand Prop = Target.modifiedProperties
| where tostring(Prop.displayName) == "Role.DisplayName"
| extend RoleName = trim(@'"', tostring(Prop.newValue))
| where RoleName in (PrivilegedRoles)
| extend TargetUser = tostring(Target.userPrincipalName),
         Actor = coalesce(tostring(InitiatedBy.user.userPrincipalName), tostring(InitiatedBy.app.displayName))
| project TimeGenerated, OperationName, RoleName, TargetUser, Actor, Result
| order by TimeGenerated desc`
        },
        {
          name: 'MFA / Security Info Registered or Changed',
          mitre: ['T1556.006', 'T1098.005'],
          requires: 'Microsoft Entra ID audit logs (AuditLogs)',
          desc: 'New or changed MFA methods - attackers with a stolen password register their own authenticator.',
          query: String.raw`// Hunt: MFA method changes
// MITRE: T1556.006 - Modify Authentication Process: MFA / T1098.005 - Device Registration
AuditLogs
| where TimeGenerated > ago(7d)
| where OperationName in ("User registered security info", "User changed default security info",
    "Admin registered security info", "User deleted security info")
| extend Actor = tostring(InitiatedBy.user.userPrincipalName),
         ActorIP = tostring(InitiatedBy.user.ipAddress),
         TargetUser = tostring(TargetResources[0].userPrincipalName)
| project TimeGenerated, OperationName, TargetUser, Actor, ActorIP, Result, ResultReason
| order by TimeGenerated desc
// CORRELATE: Same user with a risky sign-in in the hour before`
        },
        {
          name: 'OAuth Application Consent Granted',
          mitre: ['T1528'],
          requires: 'Microsoft Entra ID audit logs (AuditLogs)',
          desc: 'Users or admins consenting to OAuth apps - illicit consent grants give attackers persistent mailbox/file access.',
          query: String.raw`// Hunt: Illicit consent grant
// MITRE: T1528 - Steal Application Access Token
AuditLogs
| where TimeGenerated > ago(7d)
| where OperationName == "Consent to application"
| extend Actor = tostring(InitiatedBy.user.userPrincipalName), AppName = tostring(TargetResources[0].displayName)
| mv-expand Prop = TargetResources[0].modifiedProperties
| where tostring(Prop.displayName) in ("ConsentAction.Permissions", "ConsentContext.IsAdminConsent")
| summarize Details = make_set(tostring(Prop.newValue), 5) by TimeGenerated, Actor, AppName, CorrelationId
| order by TimeGenerated desc
// PRIORITISE: Mail.Read, Files.ReadWrite.All, offline_access granted to unfamiliar apps`
        },
        {
          name: 'Mailbox Forwarding or Hiding Inbox Rule Created',
          mitre: ['T1114.003', 'T1564.008'],
          requires: 'Microsoft 365 audit logs (OfficeActivity)',
          desc: 'Inbox rules that forward/redirect mail or delete it - a hallmark of business email compromise.',
          query: String.raw`// Hunt: BEC inbox rules
// MITRE: T1114.003 - Email Forwarding Rule / T1564.008 - Hide Artifacts: Email Hiding Rules
OfficeActivity
| where TimeGenerated > ago(7d)
| where OfficeWorkload == "Exchange"
| where Operation in~ ("New-InboxRule", "Set-InboxRule", "UpdateInboxRules", "Set-Mailbox")
| where Parameters has_any ("ForwardTo", "RedirectTo", "ForwardAsAttachmentTo", "ForwardingSmtpAddress", "DeleteMessage", "MoveToFolder")
| project TimeGenerated, UserId, Operation, ClientIP, Parameters, ResultStatus
| order by TimeGenerated desc
// VALIDATE: Forwarding to an external domain is the high-risk case`
        },
        {
          name: 'Mass Azure Resource Deletion',
          mitre: ['T1485'],
          requires: 'Azure activity logs (AzureActivity)',
          desc: 'One caller deleting 20+ Azure resources within an hour - destructive attack or compromised automation.',
          query: String.raw`// Hunt: Destructive activity in Azure
// MITRE: T1485 - Data Destruction
AzureActivity
| where TimeGenerated > ago(1d)
| where OperationNameValue endswith "/DELETE" and ActivityStatusValue in ("Success", "Succeeded")
| summarize Deletions = count(), Providers = make_set(ResourceProviderValue, 10), ResourceGroups = make_set(ResourceGroup, 10)
    by Caller, CallerIpAddress, bin(TimeGenerated, 1h)
| where Deletions >= 20
| order by Deletions desc
// VALIDATE: IaC pipelines tearing down test environments - exclude their service principals`
        }
      ]
    },

    defender: {
      'Credential Access': [
        {
          name: 'LSASS Process Handle Opened by Unusual Process',
          mitre: ['T1003.001'],
          requires: 'Microsoft Defender for Endpoint (DeviceEvents)',
          desc: 'Processes opening a handle to lsass.exe (OpenProcessApiCall) that are not known security or system components.',
          query: String.raw`// Hunt: LSASS access
// MITRE: T1003.001 - OS Credential Dumping: LSASS Memory
DeviceEvents
| where Timestamp > ago(1d)
| where ActionType == "OpenProcessApiCall"
| where FileName =~ "lsass.exe"
| where InitiatingProcessFileName !in~ ("MsMpEng.exe", "MsSense.exe", "SenseIR.exe", "csrss.exe", "wininit.exe",
    "svchost.exe", "lsm.exe", "taskmgr.exe", "services.exe")
| summarize Count = count(), FirstSeen = min(Timestamp), LastSeen = max(Timestamp)
    by DeviceName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessAccountName
| order by Count desc
// TUNE: Add your EDR/backup/monitoring agents to the exclusion list`
        },
        {
          name: 'Brute Force Against Endpoints (Failed Logons)',
          mitre: ['T1110'],
          requires: 'Microsoft Defender for Endpoint (DeviceLogonEvents)',
          desc: 'A remote IP producing 25+ failed logons in 30 minutes across one or many devices.',
          query: String.raw`// Hunt: Endpoint brute force
// MITRE: T1110 - Brute Force
DeviceLogonEvents
| where Timestamp > ago(1d)
| where ActionType == "LogonFailed"
| summarize Failures = count(), Accounts = dcount(AccountName), SampleAccounts = make_set(AccountName, 10),
            Targets = make_set(DeviceName, 10), Reasons = make_set(FailureReason, 5)
    by RemoteIP, RemoteIPType, bin(Timestamp, 30m)
| where Failures >= 25
| order by Failures desc
// PRIORITISE: RemoteIPType == "Public" means a device is exposed to the internet`
        }
      ],
      'Execution': [
        {
          name: 'Office Application Spawning Script Interpreters',
          mitre: ['T1204.002', 'T1566.001'],
          requires: 'Microsoft Defender for Endpoint (DeviceProcessEvents)',
          desc: 'Word/Excel/PowerPoint/Outlook/OneNote launching shells, script hosts or LOLBins - classic malicious document behaviour.',
          query: String.raw`// Hunt: Malicious document execution
// MITRE: T1204.002 - User Execution: Malicious File / T1566.001 - Spearphishing Attachment
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "onenote.exe", "mspub.exe", "msaccess.exe")
| where FileName in~ ("cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe",
    "rundll32.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe", "msbuild.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine, InitiatingProcessCommandLine
| order by Timestamp desc
// HARDEN: ASR rule "Block all Office applications from creating child processes"`
        },
        {
          name: 'Remote Execution via WMI (WmiPrvSE Children)',
          mitre: ['T1047'],
          requires: 'Microsoft Defender for Endpoint (DeviceProcessEvents)',
          desc: 'Shells and LOLBins started by the WMI provider host - how wmiexec, Impacket and many RATs run commands remotely.',
          query: String.raw`// Hunt: WMI remote execution
// MITRE: T1047 - Windows Management Instrumentation
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName =~ "wmiprvse.exe"
| where FileName in~ ("cmd.exe", "powershell.exe", "pwsh.exe", "rundll32.exe", "mshta.exe", "regsvr32.exe", "certutil.exe")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessAccountName
| order by Timestamp desc
// PRIORITISE: cmd.exe /Q /c ... 1> \\127.0.0.1\ADMIN$\__<timestamp> is the Impacket wmiexec pattern`
        }
      ],
      'Persistence': [
        {
          name: 'Web Shell - Web Server Spawning Shell or Recon Tools',
          mitre: ['T1505.003'],
          requires: 'Microsoft Defender for Endpoint (DeviceProcessEvents)',
          desc: 'IIS/Apache/Tomcat/Exchange worker processes launching cmd, PowerShell or reconnaissance commands.',
          query: String.raw`// Hunt: Web shell activity
// MITRE: T1505.003 - Server Software Component: Web Shell
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("w3wp.exe", "httpd.exe", "nginx.exe", "tomcat9.exe", "php-cgi.exe", "UMWorkerProcess.exe")
| where FileName in~ ("cmd.exe", "powershell.exe", "pwsh.exe", "whoami.exe", "net.exe", "net1.exe", "certutil.exe",
    "nltest.exe", "systeminfo.exe", "tasklist.exe")
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, AccountName
| order by Timestamp desc
// ESCALATE: whoami / net from w3wp.exe on an internet-facing server`
        },
        {
          name: 'Service ImagePath Pointing to Script or User Folder',
          mitre: ['T1543.003'],
          requires: 'Microsoft Defender for Endpoint (DeviceRegistryEvents)',
          desc: 'Service ImagePath values set to script hosts, shells or binaries in AppData/Temp/ProgramData.',
          query: String.raw`// Hunt: Service persistence via registry
// MITRE: T1543.003 - Create or Modify System Process: Windows Service
DeviceRegistryEvents
| where Timestamp > ago(7d)
| where ActionType == "RegistryValueSet"
| where RegistryKey startswith @"HKEY_LOCAL_MACHINE\SYSTEM\" and RegistryKey contains @"\Services\"
| where RegistryValueName =~ "ImagePath"
| where RegistryValueData has_any ("powershell", "cmd.exe", "rundll32", "mshta", "regsvr32", "AppData", "Temp", "ProgramData", "Public")
| project Timestamp, DeviceName, RegistryKey, RegistryValueData, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc`
        },
        {
          name: 'File Dropped in a Startup Folder',
          mitre: ['T1547.001'],
          requires: 'Microsoft Defender for Endpoint (DeviceFileEvents)',
          desc: 'Files created in user or all-users Startup folders - they run at every logon.',
          query: String.raw`// Hunt: Startup folder persistence
// MITRE: T1547.001 - Boot or Logon Autostart Execution: Startup Folder
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType in ("FileCreated", "FileRenamed", "FileModified")
| where FolderPath contains @"\Start Menu\Programs\Startup"
| project Timestamp, DeviceName, FileName, FolderPath, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName
| order by Timestamp desc
// PRIORITISE: .lnk/.vbs/.js/.bat files written by browsers, Office or script hosts`
        }
      ],
      'Lateral Movement': [
        {
          name: 'RDP Logon From a Public IP Address',
          mitre: ['T1021.001', 'T1133'],
          requires: 'Microsoft Defender for Endpoint (DeviceLogonEvents)',
          desc: 'Successful RemoteInteractive logons whose source is a public IP - an exposed RDP service in use.',
          query: String.raw`// Hunt: Internet-exposed RDP
// MITRE: T1021.001 - Remote Desktop Protocol / T1133 - External Remote Services
DeviceLogonEvents
| where Timestamp > ago(7d)
| where ActionType == "LogonSuccess"
| where LogonType == "RemoteInteractive"
| where RemoteIPType == "Public"
| summarize Logons = count(), Accounts = make_set(AccountName, 10), FirstSeen = min(Timestamp), LastSeen = max(Timestamp)
    by DeviceName, RemoteIP
| order by LastSeen desc
// FIX: Put RDP behind a VPN / gateway; look up RemoteIP in the OSINT tab`
        },
        {
          name: 'PsExec-Style Remote Service Execution',
          mitre: ['T1569.002', 'T1021.002'],
          requires: 'Microsoft Defender for Endpoint (DeviceProcessEvents)',
          desc: 'PSEXESVC, PAExec, RemCom and CSExec service binaries running - remote command execution over SMB.',
          query: String.raw`// Hunt: PsExec and clones
// MITRE: T1569.002 - System Services: Service Execution / T1021.002 - SMB/Windows Admin Shares
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("psexesvc.exe", "paexec.exe", "remcomsvc.exe", "csexecsvc.exe")
    or InitiatingProcessFileName in~ ("psexesvc.exe", "paexec.exe", "remcomsvc.exe", "csexecsvc.exe")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
// VALIDATE: IT admins use PsExec - compare accounts and source hosts with your admin tier model`
        }
      ],
      'Discovery': [
        {
          name: 'Reconnaissance Command Burst',
          mitre: ['T1087', 'T1082', 'T1016'],
          requires: 'Microsoft Defender for Endpoint (DeviceProcessEvents)',
          desc: 'Five or more different discovery tools (whoami, net, nltest, ipconfig, systeminfo...) run by one account within 10 minutes.',
          query: String.raw`// Hunt: Hands-on-keyboard discovery
// MITRE: T1087 - Account Discovery / T1082 - System Information Discovery / T1016 - Network Configuration Discovery
let ReconTools = dynamic(["whoami.exe", "net.exe", "net1.exe", "nltest.exe", "ipconfig.exe", "systeminfo.exe", "tasklist.exe",
    "quser.exe", "qwinsta.exe", "arp.exe", "route.exe", "netstat.exe", "dsquery.exe", "adfind.exe", "klist.exe", "hostname.exe"]);
DeviceProcessEvents
| where Timestamp > ago(1d)
| where FileName in~ (ReconTools)
| summarize Tools = dcount(FileName), ToolList = make_set(FileName, 20), Commands = make_set(ProcessCommandLine, 20)
    by DeviceName, AccountName, InitiatingProcessFileName, bin(Timestamp, 10m)
| where Tools >= 5
| order by Tools desc
// PRIORITISE: Parent is powershell/cmd launched by Office, w3wp or an unusual binary`
        }
      ],
      'Collection & Exfiltration': [
        {
          name: 'Password-Protected Archive Created',
          mitre: ['T1560.001'],
          requires: 'Microsoft Defender for Endpoint (DeviceProcessEvents)',
          desc: '7-Zip/RAR archives created with a password - attackers stage stolen data this way before exfiltration.',
          query: String.raw`// Hunt: Data staging in encrypted archives
// MITRE: T1560.001 - Archive Collected Data: Archive via Utility
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("7z.exe", "7za.exe", "7zr.exe", "rar.exe", "winrar.exe")
| where ProcessCommandLine matches regex @"(?i)\s-(h)?p\S+"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
// PRIORITISE: Archives written to C:\PerfLogs, C:\ProgramData or web roots`
        },
        {
          name: 'Mass File Download From SharePoint / OneDrive',
          mitre: ['T1530', 'T1567'],
          requires: 'Microsoft Defender for Cloud Apps (CloudAppEvents)',
          desc: 'One account downloading 200+ distinct files from Microsoft 365 within an hour.',
          query: String.raw`// Hunt: Bulk download from cloud storage
// MITRE: T1530 - Data from Cloud Storage / T1567 - Exfiltration Over Web Service
CloudAppEvents
| where Timestamp > ago(1d)
| where ActionType in ("FileDownloaded", "FileSyncDownloadedFull")
| summarize Files = dcount(ObjectName), Downloads = count(), IPs = make_set(IPAddress, 5), Countries = make_set(CountryCode, 5)
    by AccountDisplayName, AccountObjectId, Application, bin(Timestamp, 1h)
| where Files >= 200
| order by Files desc
// CONTEXT: Departing employees and new sync clients are the usual benign causes`
        }
      ],
      'Initial Access': [
        {
          name: 'User Clicked Through to a Phishing or Malware URL',
          mitre: ['T1566.002', 'T1204.001'],
          requires: 'Microsoft Defender for Office 365 (UrlClickEvents)',
          desc: 'Safe Links clicks that were allowed or clicked through despite a phishing/malware verdict.',
          query: String.raw`// Hunt: Risky clicks
// MITRE: T1566.002 - Spearphishing Link / T1204.001 - User Execution: Malicious Link
UrlClickEvents
| where Timestamp > ago(7d)
| where ActionType == "ClickAllowed" or IsClickedThrough == true
| where ThreatTypes has_any ("Phish", "Malware")
| project Timestamp, AccountUpn, Url, ActionType, IsClickedThrough, ThreatTypes, Workload, IPAddress, NetworkMessageId
| order by Timestamp desc
// NEXT: Reset the user's sessions/password and check their sign-ins after the click`
        },
        {
          name: 'QR-Code Phishing (Quishing) Delivered to Inboxes',
          mitre: ['T1566.002'],
          requires: 'Microsoft Defender for Office 365 (EmailUrlInfo + EmailEvents)',
          desc: 'Delivered emails whose URL was extracted from a QR code - grouped by destination domain.',
          query: String.raw`// Hunt: QR-code phishing
// MITRE: T1566.002 - Phishing: Spearphishing Link
EmailUrlInfo
| where Timestamp > ago(7d)
| where UrlLocation == "QRCode"
| join kind=inner (
    EmailEvents
    | where Timestamp > ago(7d)
    | where EmailDirection == "Inbound" and DeliveryAction == "Delivered"
    | project NetworkMessageId, SenderFromAddress, RecipientEmailAddress, Subject
  ) on NetworkMessageId
| summarize Recipients = dcount(RecipientEmailAddress), Subjects = make_set(Subject, 5), Senders = make_set(SenderFromAddress, 5)
    by UrlDomain
| order by Recipients desc
// WHY: QR codes move the click to a personal phone, outside corporate protections`
        }
      ],
      'Triage & Correlation': [
        {
          name: 'Devices With Alerts Across Three or More Categories',
          mitre: [],
          triage: true,
          requires: 'Microsoft Defender XDR alerts (AlertInfo + AlertEvidence)',
          desc: 'Devices whose alerts span several categories (e.g. Execution + Persistence + CredentialAccess) - likely a real intrusion chain.',
          query: String.raw`// Hunt: Multi-stage alert chains per device
// Use: daily triage - a device hitting several kill-chain stages deserves a human first
AlertInfo
| where Timestamp > ago(7d)
| join kind=inner (
    AlertEvidence
    | where Timestamp > ago(7d)
    | where EntityType == "Machine"
    | project AlertId, DeviceName
  ) on AlertId
| summarize Alerts = dcount(AlertId), Categories = make_set(Category), Severities = make_set(Severity),
            Titles = make_set(Title, 10), Sources = make_set(ServiceSource)
    by DeviceName
| extend CategoryCount = array_length(Categories)
| where CategoryCount >= 3
| order by CategoryCount desc, Alerts desc`
        },
        {
          name: 'Antivirus Detections Summary by Device',
          mitre: [],
          triage: true,
          requires: 'Microsoft Defender for Endpoint (DeviceEvents)',
          desc: 'Which devices had Defender AV detections this week, which threats, and whether they were remediated.',
          query: String.raw`// Hunt: AV detection overview
// Use: find devices with repeated or unremediated detections
DeviceEvents
| where Timestamp > ago(7d)
| where ActionType == "AntivirusDetection"
| extend Details = parse_json(AdditionalFields)
| extend ThreatName = tostring(Details.ThreatName), WasRemediated = tostring(Details.WasRemediated)
| summarize Detections = count(), Threats = make_set(ThreatName, 10), Files = make_set(FileName, 10),
            Remediated = make_set(WasRemediated)
    by DeviceName
| order by Detections desc
// PRIORITISE: Remediated contains "false", or hacktool / credential-theft threat names`
        }
      ]
    },

    crowdstrike: {
      'Execution': [
        {
          name: 'Encoded PowerShell Command Line',
          mitre: ['T1059.001', 'T1027'],
          requires: 'Falcon Insight / Next-Gen SIEM (ProcessRollup2)',
          desc: 'PowerShell started with -e / -enc / -EncodedCommand and a long Base64 payload.',
          query: String.raw`// Hunt: Encoded PowerShell
// MITRE: T1059.001 - PowerShell / T1027 - Obfuscated Files or Information
// Language: Falcon LogScale
#event_simpleName=ProcessRollup2
| in(field="FileName", values=["powershell.exe", "pwsh.exe"], ignoreCase=true)
| CommandLine=/\s-e(c|nc|ncodedcommand)?\s+[A-Za-z0-9+\/=]{20,}/i
| table([@timestamp, ComputerName, UserName, ParentBaseFileName, CommandLine], limit=1000)
// DECODE: Base64 -> UTF-16LE to read the payload`
        },
        {
          name: 'LOLBin Downloading or Proxy-Executing Content',
          mitre: ['T1105', 'T1218'],
          requires: 'Falcon Insight / Next-Gen SIEM (ProcessRollup2)',
          desc: 'certutil, bitsadmin, mshta, regsvr32, rundll32 or msiexec used with URLs or download switches.',
          query: String.raw`// Hunt: LOLBin download / proxy execution
// MITRE: T1105 - Ingress Tool Transfer / T1218 - System Binary Proxy Execution
// Language: Falcon LogScale
#event_simpleName=ProcessRollup2
| in(field="FileName", values=["certutil.exe", "bitsadmin.exe", "mshta.exe", "regsvr32.exe", "rundll32.exe", "msiexec.exe"], ignoreCase=true)
| CommandLine=/(https?:\/\/|urlcache|\/transfer|scrobj)/i
| table([@timestamp, ComputerName, UserName, ParentBaseFileName, FileName, CommandLine], limit=1000)`
        }
      ],
      'Persistence': [
        {
          name: 'Scheduled Task Created With schtasks.exe',
          mitre: ['T1053.005'],
          requires: 'Falcon Insight / Next-Gen SIEM (ProcessRollup2)',
          desc: 'schtasks /create command lines - review the action and the account that created them.',
          query: String.raw`// Hunt: Scheduled task creation (command line)
// MITRE: T1053.005 - Scheduled Task/Job: Scheduled Task
// Language: Falcon LogScale
#event_simpleName=ProcessRollup2
| FileName=/^schtasks\.exe$/i
| CommandLine=/\/create/i
| table([@timestamp, ComputerName, UserName, ParentBaseFileName, CommandLine], limit=1000)`
        },
        {
          name: 'Scheduled Task Registered Running a Script or User-Folder Binary',
          mitre: ['T1053.005'],
          requires: 'Falcon Insight / Next-Gen SIEM (ScheduledTaskRegistered)',
          desc: 'Tasks registered by any method (API, COM, schtasks) whose action runs a script host, shell or a file in a user-writable path.',
          query: String.raw`// Hunt: Suspicious scheduled task actions
// MITRE: T1053.005 - Scheduled Task/Job: Scheduled Task
// Language: Falcon LogScale
#event_simpleName=ScheduledTaskRegistered
| TaskExecCommand=/(powershell|cmd\.exe|mshta|rundll32|regsvr32|wscript|cscript|\\AppData\\|\\Temp\\|\\Users\\Public\\)/i
| table([@timestamp, ComputerName, TaskName, TaskExecCommand, TaskExecArguments], limit=1000)
// WHY: Catches tasks created through the API, which never show a schtasks.exe command line`
        },
        {
          name: 'Service Created or Reconfigured With sc.exe',
          mitre: ['T1543.003'],
          requires: 'Falcon Insight / Next-Gen SIEM (ProcessRollup2)',
          desc: 'sc create / sc config with a binPath - common for persistence and for remote execution.',
          query: String.raw`// Hunt: Service creation via sc.exe
// MITRE: T1543.003 - Create or Modify System Process: Windows Service
// Language: Falcon LogScale
#event_simpleName=ProcessRollup2
| FileName=/^sc\.exe$/i
| CommandLine=/\s(create|config)\s.*binpath\s*=/i
| table([@timestamp, ComputerName, UserName, ParentBaseFileName, CommandLine], limit=1000)`
        },
        {
          name: 'Web Shell - Web Server Spawning Shell or Recon Tools',
          mitre: ['T1505.003'],
          requires: 'Falcon Insight / Next-Gen SIEM (ProcessRollup2)',
          desc: 'IIS/Apache/Tomcat/Exchange worker processes launching cmd, PowerShell or discovery commands.',
          query: String.raw`// Hunt: Web shell activity
// MITRE: T1505.003 - Server Software Component: Web Shell
// Language: Falcon LogScale
#event_simpleName=ProcessRollup2
| in(field="ParentBaseFileName", values=["w3wp.exe", "httpd.exe", "nginx.exe", "tomcat9.exe", "php-cgi.exe", "UMWorkerProcess.exe"], ignoreCase=true)
| in(field="FileName", values=["cmd.exe", "powershell.exe", "pwsh.exe", "whoami.exe", "net.exe", "net1.exe", "certutil.exe", "nltest.exe", "systeminfo.exe"], ignoreCase=true)
| table([@timestamp, ComputerName, UserName, ParentBaseFileName, FileName, CommandLine], limit=1000)`
        }
      ],
      'Credential Access': [
        {
          name: 'LSASS Dump via comsvcs.dll, ProcDump or Mimikatz Keywords',
          mitre: ['T1003.001'],
          requires: 'Falcon Insight / Next-Gen SIEM (ProcessRollup2)',
          desc: 'Command lines that dump LSASS memory or invoke Mimikatz modules.',
          query: String.raw`// Hunt: LSASS dumping
// MITRE: T1003.001 - OS Credential Dumping: LSASS Memory
// Language: Falcon LogScale
#event_simpleName=ProcessRollup2
| CommandLine=/(comsvcs(\.dll)?[,\s]+(#24|minidump)|procdump(64)?(\.exe)?.*lsass|sekurlsa|lsadump)/i
| table([@timestamp, ComputerName, UserName, ParentBaseFileName, FileName, CommandLine], limit=1000)
// NOTE: Falcon usually blocks and alerts on this - the hunt finds attempts on hosts in detect-only policies`
        },
        {
          name: 'Password Spray - Failed Logons for Many Accounts From One IP',
          mitre: ['T1110.003'],
          requires: 'Falcon Insight / Next-Gen SIEM (UserLogonFailed2)',
          desc: 'One remote address failing logons for ten or more different accounts.',
          query: String.raw`// Hunt: Password spraying against endpoints
// MITRE: T1110.003 - Brute Force: Password Spraying
// Language: Falcon LogScale
#event_simpleName=UserLogonFailed2
| RemoteAddressIP4=*
| groupBy([RemoteAddressIP4], function=[count(as=Failures), count(UserName, distinct=true, as=Accounts), count(aid, distinct=true, as=Hosts), collect([UserName], limit=20)], limit=max)
| Accounts >= 10
| sort(Accounts, order=desc, limit=200)
// ENRICH: SubStatus explains the failure reason (bad password vs unknown user vs locked)`
        }
      ],
      'Lateral Movement': [
        {
          name: 'RDP Logon From a Public IP Address',
          mitre: ['T1021.001', 'T1133'],
          requires: 'Falcon Insight / Next-Gen SIEM (UserLogon)',
          desc: 'Logon type 10 (RemoteInteractive) sessions from internet addresses, with geolocation.',
          query: String.raw`// Hunt: Internet-exposed RDP
// MITRE: T1021.001 - Remote Desktop Protocol / T1133 - External Remote Services
// Language: Falcon LogScale
#event_simpleName=UserLogon LogonType=10 RemoteAddressIP4=*
| !cidr(RemoteAddressIP4, subnet=["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16"])
| ipLocation(RemoteAddressIP4)
| groupBy([ComputerName, UserName, RemoteAddressIP4, RemoteAddressIP4.country], function=[count(as=Logons), min(@timestamp, as=FirstSeen), max(@timestamp, as=LastSeen)], limit=max)
| sort(LastSeen, order=desc, limit=200)`
        },
        {
          name: 'Host Making RDP Connections to Many Internal Systems',
          mitre: ['T1021.001'],
          requires: 'Falcon Insight / Next-Gen SIEM (NetworkConnectIP4)',
          desc: 'A single workstation connecting to port 3389 on five or more internal hosts - RDP-based lateral movement.',
          query: String.raw`// Hunt: RDP fan-out
// MITRE: T1021.001 - Remote Services: Remote Desktop Protocol
// Language: Falcon LogScale
#event_simpleName=NetworkConnectIP4 RemotePort=3389
| cidr(RemoteAddressIP4, subnet=["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"])
| groupBy([aid, ComputerName], function=[count(RemoteAddressIP4, distinct=true, as=Targets), collect([RemoteAddressIP4], limit=20)], limit=max)
| Targets >= 5
| sort(Targets, order=desc, limit=200)
// VALIDATE: Jump hosts and admin workstations - keep them in a lookup and exclude`
        }
      ],
      'Discovery': [
        {
          name: 'Reconnaissance Command Burst',
          mitre: ['T1087', 'T1082', 'T1016'],
          requires: 'Falcon Insight / Next-Gen SIEM (ProcessRollup2)',
          desc: 'One user running six or more distinct discovery tools - run this over a short window (e.g. 1 hour).',
          query: String.raw`// Hunt: Hands-on-keyboard discovery
// MITRE: T1087 - Account Discovery / T1082 - System Information Discovery / T1016 - Network Configuration Discovery
// Language: Falcon LogScale - set the time picker to 1h for best results
#event_simpleName=ProcessRollup2
| in(field="FileName", values=["whoami.exe", "net.exe", "net1.exe", "nltest.exe", "ipconfig.exe", "systeminfo.exe", "tasklist.exe", "quser.exe", "arp.exe", "netstat.exe", "dsquery.exe", "adfind.exe", "klist.exe"], ignoreCase=true)
| groupBy([aid, ComputerName, UserName], function=[count(FileName, distinct=true, as=Tools), collect([FileName, CommandLine], limit=30)], limit=max)
| Tools >= 6
| sort(Tools, order=desc, limit=200)`
        }
      ],
      'Command and Control': [
        {
          name: 'Rare Domain Queried Repeatedly by Few Hosts',
          mitre: ['T1071.004', 'T1568'],
          requires: 'Falcon Insight / Next-Gen SIEM (DnsRequest)',
          desc: 'Domains looked up 50+ times but by at most two hosts - beaconing candidates hidden among normal DNS.',
          query: String.raw`// Hunt: Rare but busy domains
// MITRE: T1071.004 - Application Layer Protocol: DNS / T1568 - Dynamic Resolution
// Language: Falcon LogScale
#event_simpleName=DnsRequest
| groupBy([DomainName], function=[count(aid, distinct=true, as=Hosts), count(as=Requests)], limit=max)
| Hosts <= 2
| Requests >= 50
| sort(Requests, order=desc, limit=200)
// ENRICH: Paste the top domains into the OSINT tab (VirusTotal, urlscan, ThreatFox)`
        }
      ],
      'Defense Evasion': [
        {
          name: 'Windows Event Log Clearing',
          mitre: ['T1070.001'],
          requires: 'Falcon Insight / Next-Gen SIEM (ProcessRollup2)',
          desc: 'wevtutil cl / clear-log, Clear-EventLog or Remove-EventLog executed.',
          query: String.raw`// Hunt: Event log clearing
// MITRE: T1070.001 - Indicator Removal: Clear Windows Event Logs
// Language: Falcon LogScale
#event_simpleName=ProcessRollup2
| CommandLine=/(wevtutil(\.exe)?\s+(cl|clear-log)\s|Clear-EventLog|Remove-EventLog)/i
| table([@timestamp, ComputerName, UserName, ParentBaseFileName, CommandLine], limit=1000)`
        }
      ],
      'Impact': [
        {
          name: 'Shadow Copy and Recovery Deletion',
          mitre: ['T1490'],
          requires: 'Falcon Insight / Next-Gen SIEM (ProcessRollup2)',
          desc: 'vssadmin/wmic/bcdedit/wbadmin commands that remove recovery options - a near-universal ransomware precursor.',
          query: String.raw`// Hunt: Inhibit system recovery
// MITRE: T1490 - Inhibit System Recovery
// Language: Falcon LogScale
#event_simpleName=ProcessRollup2
| CommandLine=/(vssadmin(\.exe)?\s+delete\s+shadows|wmic(\.exe)?\s+shadowcopy\s+delete|bcdedit(\.exe)?.*recoveryenabled\s+no|wbadmin(\.exe)?\s+delete)/i
| table([@timestamp, ComputerName, UserName, ParentBaseFileName, CommandLine], limit=1000)
// ESCALATE: Treat as active ransomware until proven otherwise`
        }
      ],
      'Initial Access': [
        {
          name: 'Executable Written to Downloads/Temp by a Browser or Office',
          mitre: ['T1204.002', 'T1105'],
          requires: 'Falcon Insight / Next-Gen SIEM (NewExecutableWritten, PeFileWritten, ProcessRollup2)',
          desc: 'New executables written into Downloads, Temp or Public by browsers, Outlook or Office apps.',
          query: String.raw`// Hunt: Executable downloads
// MITRE: T1204.002 - User Execution: Malicious File / T1105 - Ingress Tool Transfer
// Language: Falcon LogScale
#event_simpleName=/^(NewExecutableWritten|PeFileWritten)$/
| TargetFileName=/\\(Downloads|AppData\\Local\\Temp|Users\\Public)\\/i
| join(query={#event_simpleName=ProcessRollup2}, field=[aid, ContextProcessId], key=[aid, TargetProcessId], include=[ImageFileName])
| ImageFileName=/\\(chrome|msedge|firefox|brave|outlook|winword|excel)\.exe$/i
| table([@timestamp, ComputerName, ImageFileName, TargetFileName], limit=1000)
// ENRICH: Check the file hash in VirusTotal from the OSINT tab`
        }
      ]
    }
  };

  Object.entries(extendedQueries).forEach(([platform, cats]) => {
    Object.entries(cats).forEach(([category, list]) => {
      huntingQueries[platform][category] = (huntingQueries[platform][category] || []).concat(list);
    });
  });

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
