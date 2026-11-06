/*
 * Telemetry reference for EDR operators: what each Microsoft Defender XDR
 * advanced hunting table and each CrowdStrike Falcon event type records,
 * which columns matter for hunting, a sample record and a starter query.
 *
 * Defender columns are cross-checked against tests/kql-schema.js (taken from
 * Microsoft Learn) by tests/tables.test.js, and every starter KQL query is
 * parsed and type-checked. CrowdStrike field names come from CrowdStrike's
 * public LogScale community content; fields marked verify:true could not be
 * confirmed publicly and should be checked in your Falcon Event Data Dictionary.
 *
 * Sample records are illustrative (contoso / documentation IP ranges).
 */
(function (root, factory) {
  const api = factory();
  if (typeof module === 'object' && module.exports) module.exports = api;
  else root.THQV = Object.assign(root.THQV || {}, api);
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  const MS_DOCS = 'https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-';

  const defenderTables = [
    {
      name: 'DeviceProcessEvents',
      source: 'Defender for Endpoint',
      docs: MS_DOCS + 'deviceprocessevents-table',
      summary: 'Every process started on onboarded devices, with its command line, hashes, and the full parent/grandparent chain. The single most useful table for endpoint hunting.',
      huntFor: [
        'Suspicious parent-child chains (Office -> PowerShell, w3wp -> cmd, wmiprvse -> cmd)',
        'Encoded or obfuscated command lines, LOLBin abuse, credential-dumping tools',
        'Discovery bursts (whoami, net, nltest) and ransomware precursors (vssadmin delete shadows)'
      ],
      columns: [
        { name: 'Timestamp', type: 'datetime', desc: 'When the process started (UTC)' },
        { name: 'DeviceName', type: 'string', desc: 'Device FQDN' },
        { name: 'AccountName', type: 'string', desc: 'User the new process runs as' },
        { name: 'FileName', type: 'string', desc: 'Image name of the new process (e.g. powershell.exe)' },
        { name: 'FolderPath', type: 'string', desc: 'Full path - binaries in Temp/AppData/Public are suspicious' },
        { name: 'ProcessCommandLine', type: 'string', desc: 'Full command line - where most detections live' },
        { name: 'SHA256', type: 'string', desc: 'Hash of the new process image - pivot to VirusTotal' },
        { name: 'ProcessIntegrityLevel', type: 'string', desc: 'Low / Medium / High / System - privilege of the new process' },
        { name: 'InitiatingProcessFileName', type: 'string', desc: 'Parent process name' },
        { name: 'InitiatingProcessCommandLine', type: 'string', desc: 'Parent command line' },
        { name: 'InitiatingProcessParentFileName', type: 'string', desc: 'Grandparent process name' },
        { name: 'InitiatingProcessAccountName', type: 'string', desc: 'Account that ran the parent process' }
      ],
      actionTypes: ['ProcessCreated'],
      sample: {
        Timestamp: '2026-11-05T14:02:11Z', DeviceName: 'ws-0142.contoso.local', AccountName: 'jdoe',
        FileName: 'powershell.exe', FolderPath: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
        ProcessCommandLine: 'powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoA...',
        ProcessIntegrityLevel: 'Medium', InitiatingProcessFileName: 'winword.exe',
        InitiatingProcessParentFileName: 'explorer.exe'
      },
      starter: String.raw`// Rare processes: images seen on only one or two devices in the last 7 days
DeviceProcessEvents
| where Timestamp > ago(7d)
| summarize Devices = dcount(DeviceId), Executions = count(), SamplePath = any(FolderPath), SampleCommand = any(ProcessCommandLine)
    by FileName, SHA256
| where Devices <= 2
| order by Executions desc`
    },
    {
      name: 'DeviceNetworkEvents',
      source: 'Defender for Endpoint',
      docs: MS_DOCS + 'devicenetworkevents-table',
      summary: 'Network connections made and accepted by processes on devices, including the remote IP, port and (when known) URL. Has no byte counts.',
      huntFor: [
        'Beaconing and connections to rare or known-bad destinations',
        'Unexpected processes talking to the internet (rundll32, regsvr32, Office apps)',
        'Lateral movement ports (445, 3389, 5985) between workstations'
      ],
      columns: [
        { name: 'Timestamp', type: 'datetime', desc: 'When the connection was recorded' },
        { name: 'DeviceName', type: 'string', desc: 'Device FQDN' },
        { name: 'ActionType', type: 'string', desc: 'ConnectionSuccess, ConnectionFailed, InboundConnectionAccepted...' },
        { name: 'RemoteIP', type: 'string', desc: 'Destination (or source, for inbound) IP' },
        { name: 'RemotePort', type: 'int', desc: 'Remote port' },
        { name: 'RemoteUrl', type: 'string', desc: 'URL / FQDN if the sensor resolved it' },
        { name: 'RemoteIPType', type: 'string', desc: 'Public, Private, Loopback... - filter to Public for internet traffic' },
        { name: 'LocalIP', type: 'string', desc: 'Device IP used for the connection' },
        { name: 'LocalPort', type: 'int', desc: 'Local port - useful for listening services' },
        { name: 'Protocol', type: 'string', desc: 'Tcp / Udp' },
        { name: 'InitiatingProcessFileName', type: 'string', desc: 'Process that made the connection' },
        { name: 'InitiatingProcessCommandLine', type: 'string', desc: 'Its command line' }
      ],
      actionTypes: ['ConnectionSuccess', 'ConnectionFailed', 'ConnectionRequest', 'InboundConnectionAccepted', 'ListeningConnectionCreated'],
      sample: {
        Timestamp: '2026-11-05T14:02:19Z', DeviceName: 'ws-0142.contoso.local', ActionType: 'ConnectionSuccess',
        RemoteIP: '203.0.113.45', RemotePort: 443, RemoteUrl: 'update-check.example', RemoteIPType: 'Public',
        LocalIP: '10.20.4.17', Protocol: 'Tcp', InitiatingProcessFileName: 'rundll32.exe'
      },
      starter: String.raw`// Unusual processes making internet connections
DeviceNetworkEvents
| where Timestamp > ago(1d)
| where RemoteIPType == "Public"
| where InitiatingProcessFileName in~ ("rundll32.exe", "regsvr32.exe", "mshta.exe", "certutil.exe", "msbuild.exe", "installutil.exe")
| summarize Connections = count(), Destinations = make_set(strcat(RemoteIP, ":", RemotePort), 10), Urls = make_set(RemoteUrl, 10)
    by DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Connections desc`
    },
    {
      name: 'DeviceFileEvents',
      source: 'Defender for Endpoint',
      docs: MS_DOCS + 'devicefileevents-table',
      summary: 'File creation, modification, rename and deletion on devices, with hashes and (for downloads) the origin URL.',
      huntFor: [
        'Payloads dropped in Startup folders, Temp, Public or web roots',
        'Mass renames/modifications that indicate ransomware encryption',
        'Files downloaded from suspicious URLs (FileOriginUrl) or written over SMB (RequestSourceIP)'
      ],
      columns: [
        { name: 'Timestamp', type: 'datetime', desc: 'When the file event happened' },
        { name: 'DeviceName', type: 'string', desc: 'Device FQDN' },
        { name: 'ActionType', type: 'string', desc: 'FileCreated, FileModified, FileRenamed, FileDeleted' },
        { name: 'FileName', type: 'string', desc: 'File name' },
        { name: 'FolderPath', type: 'string', desc: 'Full path of the file' },
        { name: 'SHA256', type: 'string', desc: 'File hash (when computed)' },
        { name: 'FileOriginUrl', type: 'string', desc: 'Where a downloaded file came from (Mark-of-the-Web)' },
        { name: 'PreviousFileName', type: 'string', desc: 'Name before a rename - ransomware extension changes show here' },
        { name: 'RequestAccountName', type: 'string', desc: 'Remote account that wrote the file over the network' },
        { name: 'RequestSourceIP', type: 'string', desc: 'Remote IP that wrote the file (SMB lateral movement)' },
        { name: 'InitiatingProcessFileName', type: 'string', desc: 'Process that touched the file' }
      ],
      actionTypes: ['FileCreated', 'FileModified', 'FileRenamed', 'FileDeleted'],
      sample: {
        Timestamp: '2026-11-05T14:03:02Z', DeviceName: 'ws-0142.contoso.local', ActionType: 'FileCreated',
        FileName: 'invoice.lnk', FolderPath: 'C:\\Users\\jdoe\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\invoice.lnk',
        FileOriginUrl: '', InitiatingProcessFileName: 'wscript.exe'
      },
      starter: String.raw`// Executables and scripts dropped into user-writable locations
DeviceFileEvents
| where Timestamp > ago(1d)
| where ActionType == "FileCreated"
| where FolderPath has_any ("AppData", "Temp", "Public", "ProgramData", "Downloads")
| where FileName endswith ".exe" or FileName endswith ".dll" or FileName endswith ".ps1" or FileName endswith ".vbs" or FileName endswith ".hta"
| project Timestamp, DeviceName, FileName, FolderPath, SHA256, FileOriginUrl, InitiatingProcessFileName
| order by Timestamp desc`
    },
    {
      name: 'DeviceRegistryEvents',
      source: 'Defender for Endpoint',
      docs: MS_DOCS + 'deviceregistryevents-table',
      summary: 'Creation, modification and deletion of registry keys and values on Windows devices.',
      huntFor: [
        'Autostart persistence: Run/RunOnce keys, services (ImagePath), Winlogon, IFEO debuggers',
        'Security tampering: Defender/AMSI/firewall settings switched off',
        'Credential theft enablers such as WDigest UseLogonCredential = 1'
      ],
      columns: [
        { name: 'Timestamp', type: 'datetime', desc: 'When the change happened' },
        { name: 'DeviceName', type: 'string', desc: 'Device FQDN' },
        { name: 'ActionType', type: 'string', desc: 'RegistryValueSet, RegistryKeyCreated, RegistryKeyDeleted...' },
        { name: 'RegistryKey', type: 'string', desc: 'Full key path (HKEY_LOCAL_MACHINE\\...)' },
        { name: 'RegistryValueName', type: 'string', desc: 'Value name' },
        { name: 'RegistryValueData', type: 'string', desc: 'New data written' },
        { name: 'PreviousRegistryValueData', type: 'string', desc: 'Data before the change - shows what was disabled' },
        { name: 'InitiatingProcessFileName', type: 'string', desc: 'Process that made the change' },
        { name: 'InitiatingProcessCommandLine', type: 'string', desc: 'Its command line (reg.exe add ... / PowerShell)' }
      ],
      actionTypes: ['RegistryValueSet', 'RegistryKeyCreated', 'RegistryKeyDeleted', 'RegistryValueDeleted'],
      sample: {
        Timestamp: '2026-11-05T14:03:40Z', DeviceName: 'ws-0142.contoso.local', ActionType: 'RegistryValueSet',
        RegistryKey: 'HKEY_CURRENT_USER\\S-1-5-21-...\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
        RegistryValueName: 'OneDriveUpdate', RegistryValueData: 'C:\\Users\\Public\\odupd.exe',
        InitiatingProcessFileName: 'reg.exe'
      },
      starter: String.raw`// WDigest re-enabled (cleartext credentials kept in LSASS)
DeviceRegistryEvents
| where Timestamp > ago(30d)
| where RegistryKey contains @"\Control\SecurityProviders\WDigest"
| where RegistryValueName =~ "UseLogonCredential" and RegistryValueData == "1"
| project Timestamp, DeviceName, RegistryKey, RegistryValueData, InitiatingProcessFileName, InitiatingProcessCommandLine`
    },
    {
      name: 'DeviceLogonEvents',
      source: 'Defender for Endpoint',
      docs: MS_DOCS + 'devicelogonevents-table',
      summary: 'Logons and authentication attempts on devices: who logged on, how (interactive, RDP, network, batch, service), from where, and whether they are a local admin.',
      huntFor: [
        'Brute force and password spraying against endpoints (LogonFailed bursts)',
        'RDP from public IPs and unusual remote logons',
        'Local admin logons by accounts that should not have admin rights'
      ],
      columns: [
        { name: 'Timestamp', type: 'datetime', desc: 'When the logon happened' },
        { name: 'DeviceName', type: 'string', desc: 'Device logged on to' },
        { name: 'ActionType', type: 'string', desc: 'LogonSuccess, LogonFailed, LogonAttempted' },
        { name: 'LogonType', type: 'string', desc: 'Interactive, RemoteInteractive (RDP), Network, Batch, Service...' },
        { name: 'AccountDomain', type: 'string', desc: 'Domain of the account' },
        { name: 'AccountName', type: 'string', desc: 'Account that logged on' },
        { name: 'IsLocalAdmin', type: 'bool', desc: 'Whether the account is a local administrator' },
        { name: 'RemoteIP', type: 'string', desc: 'Where the logon came from' },
        { name: 'RemoteIPType', type: 'string', desc: 'Public / Private... - Public RDP is a red flag' },
        { name: 'RemoteDeviceName', type: 'string', desc: 'Source device name when known' },
        { name: 'FailureReason', type: 'string', desc: 'Why a failed logon failed (bad password, unknown user...)' },
        { name: 'Protocol', type: 'string', desc: 'Authentication protocol (Kerberos, NTLM, Negotiate)' }
      ],
      actionTypes: ['LogonSuccess', 'LogonFailed', 'LogonAttempted'],
      sample: {
        Timestamp: '2026-11-05T02:14:55Z', DeviceName: 'srv-app01.contoso.local', ActionType: 'LogonSuccess',
        LogonType: 'RemoteInteractive', AccountDomain: 'contoso', AccountName: 'svc_backup', IsLocalAdmin: true,
        RemoteIP: '198.51.100.23', RemoteIPType: 'Public', Protocol: 'Negotiate'
      },
      starter: String.raw`// Local-admin logons per account in the last week - spot unexpected admins
DeviceLogonEvents
| where Timestamp > ago(7d)
| where ActionType == "LogonSuccess" and IsLocalAdmin == true
| where LogonType in ("Interactive", "RemoteInteractive")
| summarize Devices = dcount(DeviceName), DeviceList = make_set(DeviceName, 20) by AccountDomain, AccountName
| order by Devices desc`
    },
    {
      name: 'DeviceImageLoadEvents',
      source: 'Defender for Endpoint',
      docs: MS_DOCS + 'deviceimageloadevents-table',
      summary: 'DLLs loaded by processes. High volume; best used with tight filters.',
      huntFor: [
        'DLL side-loading: signed apps loading DLLs from user-writable folders',
        'Credential theft modules loaded into unusual processes',
        'Script engines (e.g. System.Management.Automation.dll) loaded by non-PowerShell binaries'
      ],
      columns: [
        { name: 'Timestamp', type: 'datetime', desc: 'When the DLL was loaded' },
        { name: 'DeviceName', type: 'string', desc: 'Device FQDN' },
        { name: 'FileName', type: 'string', desc: 'DLL name' },
        { name: 'FolderPath', type: 'string', desc: 'Where the DLL was loaded from' },
        { name: 'SHA1', type: 'string', desc: 'DLL hash (SHA1 is the reliably populated hash here)' },
        { name: 'InitiatingProcessFileName', type: 'string', desc: 'Process that loaded the DLL' },
        { name: 'InitiatingProcessFolderPath', type: 'string', desc: 'Where that process lives' },
        { name: 'InitiatingProcessCommandLine', type: 'string', desc: 'Its command line' }
      ],
      actionTypes: ['ImageLoaded'],
      sample: {
        Timestamp: '2026-11-05T14:05:12Z', DeviceName: 'ws-0142.contoso.local', FileName: 'version.dll',
        FolderPath: 'C:\\Users\\jdoe\\AppData\\Local\\Temp\\app\\version.dll',
        InitiatingProcessFileName: 'OneDriveStandaloneUpdater.exe'
      },
      starter: String.raw`// PowerShell engine loaded by something that is not PowerShell ("PowerShell without powershell.exe")
DeviceImageLoadEvents
| where Timestamp > ago(1d)
| where FileName =~ "System.Management.Automation.dll"
| where InitiatingProcessFileName !in~ ("powershell.exe", "pwsh.exe", "powershell_ise.exe", "sdiagnhost.exe")
| summarize Loads = count() by DeviceName, InitiatingProcessFileName, InitiatingProcessFolderPath
| order by Loads desc`
    },
    {
      name: 'DeviceEvents',
      source: 'Defender for Endpoint',
      docs: MS_DOCS + 'deviceevents-table',
      summary: 'A catch-all table for security-relevant events that do not fit elsewhere: AV detections, ASR/exploit protection blocks, LSASS access, remote thread injection, PowerShell commands, USB mounts, scheduled tasks and more. Always filter on ActionType.',
      huntFor: [
        'Antivirus and ASR detections and blocks',
        'Process injection (CreateRemoteThreadApiCall) and LSASS handle access (OpenProcessApiCall)',
        'Removable media, named pipes and other niche signals - details live in AdditionalFields'
      ],
      columns: [
        { name: 'Timestamp', type: 'datetime', desc: 'When the event happened' },
        { name: 'DeviceName', type: 'string', desc: 'Device FQDN' },
        { name: 'ActionType', type: 'string', desc: 'What happened - the key to this table' },
        { name: 'FileName', type: 'string', desc: 'Target file/process of the event (e.g. lsass.exe)' },
        { name: 'FolderPath', type: 'string', desc: 'Path of the target file' },
        { name: 'ProcessCommandLine', type: 'string', desc: 'Command line of the target process when relevant' },
        { name: 'AccountName', type: 'string', desc: 'Account involved' },
        { name: 'RemoteUrl', type: 'string', desc: 'URL for network-protection / SmartScreen events' },
        { name: 'AdditionalFields', type: 'dynamic', desc: 'JSON with event-specific details (ThreatName, Command...) - use parse_json()' },
        { name: 'InitiatingProcessFileName', type: 'string', desc: 'Process responsible for the event' }
      ],
      actionTypes: ['AntivirusDetection', 'OpenProcessApiCall', 'CreateRemoteThreadApiCall', 'PowerShellCommand', 'ScheduledTaskCreated', 'ServiceInstalled', 'UsbDriveMounted', 'DnsQueryResponse', 'AsrOfficeChildProcessBlocked'],
      sample: {
        Timestamp: '2026-11-05T14:06:31Z', DeviceName: 'ws-0142.contoso.local', ActionType: 'AntivirusDetection',
        FileName: 'mimikatz.exe', FolderPath: 'C:\\Users\\Public\\mimikatz.exe',
        AdditionalFields: { ThreatName: 'HackTool:Win64/Mimikatz', WasRemediated: true },
        InitiatingProcessFileName: 'explorer.exe'
      },
      starter: String.raw`// What ActionTypes exist in your tenant, and how often - start here before hunting in DeviceEvents
DeviceEvents
| where Timestamp > ago(1d)
| summarize Events = count(), Devices = dcount(DeviceId) by ActionType
| order by Events desc`
    },
    {
      name: 'DeviceInfo',
      source: 'Defender for Endpoint / XDR',
      docs: MS_DOCS + 'deviceinfo-table',
      summary: 'Inventory snapshots of every device: OS, sensor version and health, public IP, exposure level, asset value, tags and internet exposure.',
      huntFor: [
        'Enriching hunts with OS, criticality and tags (join on DeviceId)',
        'Devices with unhealthy or inactive sensors (blind spots)',
        'Internet-facing devices to prioritise for patching and hunting'
      ],
      columns: [
        { name: 'Timestamp', type: 'datetime', desc: 'Time of this inventory snapshot' },
        { name: 'DeviceId', type: 'string', desc: 'Stable device ID - the join key across Device* tables' },
        { name: 'DeviceName', type: 'string', desc: 'Device FQDN' },
        { name: 'OSPlatform', type: 'string', desc: 'Windows11, WindowsServer2022, Linux, macOS...' },
        { name: 'OSVersion', type: 'string', desc: 'OS version' },
        { name: 'PublicIP', type: 'string', desc: 'Public IP the device uses to reach Defender (NAT/proxy)' },
        { name: 'IsInternetFacing', type: 'bool', desc: 'Defender determined the device is reachable from the internet' },
        { name: 'SensorHealthState', type: 'string', desc: 'Active / Inactive / Misconfigured / No sensor data' },
        { name: 'ExposureLevel', type: 'string', desc: 'Low / Medium / High from vulnerability management' },
        { name: 'AssetValue', type: 'string', desc: 'Low / Normal / High business criticality' },
        { name: 'MachineGroup', type: 'string', desc: 'RBAC device group' },
        { name: 'DeviceManualTags', type: 'string', desc: 'Tags set by admins (e.g. "Tier0", "PCI")' }
      ],
      actionTypes: [],
      sample: {
        Timestamp: '2026-11-05T12:00:00Z', DeviceId: 'a1b2c3d4e5f6...', DeviceName: 'srv-app01.contoso.local',
        OSPlatform: 'WindowsServer2022', PublicIP: '198.51.100.10', IsInternetFacing: true,
        SensorHealthState: 'Active', ExposureLevel: 'High', AssetValue: 'High', DeviceManualTags: '["Tier1"]'
      },
      starter: String.raw`// Latest state per device: internet-facing servers with unhealthy sensors
DeviceInfo
| where Timestamp > ago(7d)
| summarize arg_max(Timestamp, *) by DeviceId
| where IsInternetFacing == true and SensorHealthState != "Active"
| project DeviceName, OSPlatform, PublicIP, SensorHealthState, ExposureLevel, AssetValue, Timestamp`
    },
    {
      name: 'DeviceTvmSoftwareVulnerabilities',
      source: 'Defender Vulnerability Management',
      docs: MS_DOCS + 'devicetvmsoftwarevulnerabilities-table',
      summary: 'Current snapshot of which CVEs affect which installed software on which devices. No timestamp - it always reflects the latest assessment.',
      huntFor: [
        'Exposure checks for CVEs in the news (see the Hunt Hypotheses tab)',
        'Critical vulnerabilities on internet-facing or high-value devices (join DeviceInfo)',
        'Software that keeps reappearing unpatched'
      ],
      columns: [
        { name: 'DeviceId', type: 'string', desc: 'Device ID (join to DeviceInfo)' },
        { name: 'DeviceName', type: 'string', desc: 'Device FQDN' },
        { name: 'OSPlatform', type: 'string', desc: 'Operating system' },
        { name: 'SoftwareVendor', type: 'string', desc: 'Vendor of the vulnerable software' },
        { name: 'SoftwareName', type: 'string', desc: 'Product name' },
        { name: 'SoftwareVersion', type: 'string', desc: 'Installed version' },
        { name: 'CveId', type: 'string', desc: 'CVE identifier' },
        { name: 'VulnerabilitySeverityLevel', type: 'string', desc: 'Low / Medium / High / Critical' },
        { name: 'RecommendedSecurityUpdate', type: 'string', desc: 'Update that fixes it' }
      ],
      actionTypes: [],
      sample: {
        DeviceId: 'a1b2c3d4e5f6...', DeviceName: 'srv-app01.contoso.local', SoftwareVendor: 'fortinet',
        SoftwareName: 'forticlient', SoftwareVersion: '7.0.9', CveId: 'CVE-2025-00000',
        VulnerabilitySeverityLevel: 'Critical', RecommendedSecurityUpdate: 'Update FortiClient to 7.0.14'
      },
      starter: String.raw`// Critical vulnerabilities on internet-facing devices
DeviceTvmSoftwareVulnerabilities
| where VulnerabilitySeverityLevel == "Critical"
| join kind=inner (
    DeviceInfo
    | where Timestamp > ago(7d)
    | summarize arg_max(Timestamp, *) by DeviceId
    | where IsInternetFacing == true
    | project DeviceId
  ) on DeviceId
| summarize CVEs = make_set(CveId, 20), Software = make_set(SoftwareName, 10) by DeviceName
| order by array_length(CVEs) desc`
    },
    {
      name: 'EmailEvents',
      source: 'Defender for Office 365',
      docs: MS_DOCS + 'emailevents-table',
      summary: 'One row per email processed by Exchange Online Protection: sender, recipient, subject, direction, delivery action and threat verdicts.',
      huntFor: [
        'Phishing campaigns: same sender/subject hitting many recipients',
        'Delivered mail that was later found malicious, and lookalike sender domains',
        'Outbound spikes that suggest a compromised mailbox'
      ],
      columns: [
        { name: 'Timestamp', type: 'datetime', desc: 'When the email was processed' },
        { name: 'NetworkMessageId', type: 'string', desc: 'Unique email ID - join key for EmailAttachmentInfo / EmailUrlInfo / UrlClickEvents' },
        { name: 'SenderFromAddress', type: 'string', desc: 'Address in the From header (what the user sees)' },
        { name: 'SenderMailFromAddress', type: 'string', desc: 'Envelope sender (MAIL FROM) - mismatches can mean spoofing' },
        { name: 'SenderFromDomain', type: 'string', desc: 'Domain of the From address' },
        { name: 'SenderIPv4', type: 'string', desc: 'Sending server IP' },
        { name: 'RecipientEmailAddress', type: 'string', desc: 'Recipient' },
        { name: 'Subject', type: 'string', desc: 'Subject line' },
        { name: 'EmailDirection', type: 'string', desc: 'Inbound / Outbound / Intra-org' },
        { name: 'DeliveryAction', type: 'string', desc: 'Delivered, Junked, Blocked, Replaced' },
        { name: 'ThreatTypes', type: 'string', desc: 'Phish, Malware, Spam verdicts' },
        { name: 'AttachmentCount', type: 'int', desc: 'Number of attachments' },
        { name: 'UrlCount', type: 'int', desc: 'Number of URLs' }
      ],
      actionTypes: [],
      sample: {
        Timestamp: '2026-11-05T09:12:44Z', NetworkMessageId: '5b1f...-...', SenderFromAddress: 'billing@invoice-portal.example',
        SenderFromDomain: 'invoice-portal.example', SenderIPv4: '203.0.113.77', RecipientEmailAddress: 'jdoe@contoso.com',
        Subject: 'Overdue invoice #44812', EmailDirection: 'Inbound', DeliveryAction: 'Delivered', ThreatTypes: '', AttachmentCount: 1
      },
      starter: String.raw`// Campaign view: delivered inbound mail from senders hitting many recipients today
EmailEvents
| where Timestamp > ago(1d)
| where EmailDirection == "Inbound" and DeliveryAction == "Delivered"
| summarize Recipients = dcount(RecipientEmailAddress), Subjects = make_set(Subject, 5) by SenderFromDomain, SenderIPv4
| where Recipients >= 20
| order by Recipients desc`
    },
    {
      name: 'EmailAttachmentInfo',
      source: 'Defender for Office 365',
      docs: MS_DOCS + 'emailattachmentinfo-table',
      summary: 'Attachments on processed emails, with file name, type and SHA256. Join to endpoint tables on SHA256 to see if an attachment ran.',
      huntFor: [
        'Risky attachment types (iso, img, lnk, html, one, js) reaching inboxes',
        'An attachment hash later seen executing on a device',
        'One attachment hash sent to many users (campaign scoping)'
      ],
      columns: [
        { name: 'Timestamp', type: 'datetime', desc: 'When the email was processed' },
        { name: 'NetworkMessageId', type: 'string', desc: 'Join key to EmailEvents' },
        { name: 'SenderFromAddress', type: 'string', desc: 'Sender' },
        { name: 'RecipientEmailAddress', type: 'string', desc: 'Recipient' },
        { name: 'FileName', type: 'string', desc: 'Attachment name' },
        { name: 'FileType', type: 'string', desc: 'Detected file type' },
        { name: 'SHA256', type: 'string', desc: 'Attachment hash - join to DeviceProcessEvents / DeviceFileEvents' },
        { name: 'FileSize', type: 'long', desc: 'Size in bytes' },
        { name: 'ThreatTypes', type: 'string', desc: 'Verdict for the attachment' },
        { name: 'ThreatNames', type: 'string', desc: 'Detection name if malicious' }
      ],
      actionTypes: [],
      sample: {
        Timestamp: '2026-11-05T09:12:44Z', NetworkMessageId: '5b1f...-...', SenderFromAddress: 'billing@invoice-portal.example',
        RecipientEmailAddress: 'jdoe@contoso.com', FileName: 'Invoice_44812.iso', FileType: 'iso',
        SHA256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', FileSize: 1835008
      },
      starter: String.raw`// Container and script attachments delivered this week
EmailAttachmentInfo
| where Timestamp > ago(7d)
| where FileType in~ ("iso", "img", "vhd", "lnk", "html", "htm", "one", "js", "vbs", "hta", "zip", "rar")
| summarize Recipients = dcount(RecipientEmailAddress), Names = make_set(FileName, 5) by SHA256, FileType, SenderFromAddress
| order by Recipients desc`
    },
    {
      name: 'EmailUrlInfo',
      source: 'Defender for Office 365',
      docs: MS_DOCS + 'emailurlinfo-table',
      summary: 'Every URL found in processed emails - in the body, subject, attachments and QR codes.',
      huntFor: [
        'QR-code phishing (UrlLocation == "QRCode")',
        'Emails pointing at newly seen or lookalike domains',
        'Scoping a malicious URL: who else received it'
      ],
      columns: [
        { name: 'Timestamp', type: 'datetime', desc: 'When the email was processed' },
        { name: 'NetworkMessageId', type: 'string', desc: 'Join key to EmailEvents / UrlClickEvents' },
        { name: 'Url', type: 'string', desc: 'Full URL' },
        { name: 'UrlDomain', type: 'string', desc: 'Domain of the URL' },
        { name: 'UrlLocation', type: 'string', desc: 'Where the URL was found (body, attachment, QR code...)' },
        { name: 'UrlChainPosition', type: 'int', desc: 'Position in a redirect chain (0 = original)' }
      ],
      actionTypes: [],
      sample: {
        Timestamp: '2026-11-05T09:12:44Z', NetworkMessageId: '5b1f...-...', Url: 'https://login-contoso.example/auth',
        UrlDomain: 'login-contoso.example', UrlLocation: 'QRCode', UrlChainPosition: 0
      },
      starter: String.raw`// Who received a given domain (replace the domain)
EmailUrlInfo
| where Timestamp > ago(30d)
| where UrlDomain endswith "login-contoso.example"
| join kind=inner (EmailEvents | where Timestamp > ago(30d) | project NetworkMessageId, RecipientEmailAddress, Subject, DeliveryAction) on NetworkMessageId
| project Timestamp, RecipientEmailAddress, Subject, DeliveryAction, Url`
    },
    {
      name: 'UrlClickEvents',
      source: 'Defender for Office 365',
      docs: MS_DOCS + 'urlclickevents-table',
      summary: 'Safe Links clicks from email, Teams and Office apps: who clicked what, the verdict, and whether they clicked through a warning.',
      huntFor: [
        'Users who clicked phishing links (allowed or clicked through)',
        'Click timelines for incident scoping',
        'Repeat clickers for awareness training'
      ],
      columns: [
        { name: 'Timestamp', type: 'datetime', desc: 'When the click happened' },
        { name: 'Url', type: 'string', desc: 'URL clicked' },
        { name: 'ActionType', type: 'string', desc: 'ClickAllowed, ClickBlocked, ClickBlockedByTenantPolicy...' },
        { name: 'AccountUpn', type: 'string', desc: 'User who clicked' },
        { name: 'Workload', type: 'string', desc: 'Email, Teams or Office' },
        { name: 'NetworkMessageId', type: 'string', desc: 'Email the link came from (join to EmailEvents)' },
        { name: 'ThreatTypes', type: 'string', desc: 'Verdict at click time (Phish, Malware...)' },
        { name: 'IsClickedThrough', type: 'bool', desc: 'User ignored the warning page and continued' },
        { name: 'IPAddress', type: 'string', desc: 'Public IP the click came from' }
      ],
      actionTypes: ['ClickAllowed', 'ClickBlocked', 'ClickBlockedByTenantPolicy'],
      sample: {
        Timestamp: '2026-11-05T09:20:03Z', Url: 'https://login-contoso.example/auth', ActionType: 'ClickAllowed',
        AccountUpn: 'jdoe@contoso.com', Workload: 'Email', ThreatTypes: 'Phish', IsClickedThrough: false, IPAddress: '198.51.100.88'
      },
      starter: String.raw`// Users who clicked links later flagged as phishing
UrlClickEvents
| where Timestamp > ago(7d)
| where ThreatTypes has "Phish"
| summarize Clicks = count(), Urls = make_set(Url, 5), ClickedThrough = countif(IsClickedThrough == true) by AccountUpn
| order by Clicks desc`
    },
    {
      name: 'IdentityLogonEvents',
      source: 'Defender for Identity / Cloud Apps',
      docs: MS_DOCS + 'identitylogonevents-table',
      summary: 'Authentication against on-prem Active Directory (Kerberos, NTLM, LDAP) seen by Defender for Identity sensors on DCs, plus some cloud logons from Defender for Cloud Apps.',
      huntFor: [
        'Password spraying and brute force against AD (LogonFailed by IP)',
        'NTLM or cleartext LDAP use by accounts that should use Kerberos',
        'Service accounts logging on from unexpected devices'
      ],
      columns: [
        { name: 'Timestamp', type: 'datetime', desc: 'When the authentication happened' },
        { name: 'ActionType', type: 'string', desc: 'LogonSuccess / LogonFailed' },
        { name: 'LogonType', type: 'string', desc: 'Resource access, Interactive, Credentials validation, Remote desktop, LDAP cleartext...' },
        { name: 'Protocol', type: 'string', desc: 'Kerberos, NTLM, LDAP...' },
        { name: 'FailureReason', type: 'string', desc: 'Why it failed (wrong password, disabled, locked...)' },
        { name: 'AccountUpn', type: 'string', desc: 'Account authenticating' },
        { name: 'DeviceName', type: 'string', desc: 'Source device' },
        { name: 'IPAddress', type: 'string', desc: 'Source IP' },
        { name: 'DestinationDeviceName', type: 'string', desc: 'DC or server that processed it' },
        { name: 'TargetDeviceName', type: 'string', desc: 'Resource being accessed' }
      ],
      actionTypes: ['LogonSuccess', 'LogonFailed'],
      sample: {
        Timestamp: '2026-11-05T03:41:09Z', ActionType: 'LogonFailed', LogonType: 'Credentials validation', Protocol: 'Ntlm',
        FailureReason: 'WrongPassword', AccountUpn: 'asmith@contoso.com', DeviceName: 'ws-0388', IPAddress: '10.20.7.31',
        DestinationDeviceName: 'dc01.contoso.local'
      },
      starter: String.raw`// AD password spray: one source failing for many accounts
IdentityLogonEvents
| where Timestamp > ago(1d)
| where ActionType == "LogonFailed"
| summarize Accounts = dcount(AccountUpn), Failures = count(), Protocols = make_set(Protocol) by IPAddress, DeviceName
| where Accounts >= 10
| order by Accounts desc`
    },
    {
      name: 'IdentityQueryEvents',
      source: 'Defender for Identity',
      docs: MS_DOCS + 'identityqueryevents-table',
      summary: 'Queries against Active Directory objects (LDAP, SAMR, DNS) observed by Defender for Identity - the reconnaissance layer of AD attacks.',
      huntFor: [
        'SPN enumeration before Kerberoasting',
        'BloodHound/SharpHound-style mass LDAP enumeration',
        'SAMR queries for privileged groups from workstations'
      ],
      columns: [
        { name: 'Timestamp', type: 'datetime', desc: 'When the query happened' },
        { name: 'ActionType', type: 'string', desc: 'LDAP query, SAMR query, DNS query...' },
        { name: 'QueryType', type: 'string', desc: 'QueryUser, QueryGroup, EnumerateUsers...' },
        { name: 'QueryTarget', type: 'string', desc: 'Object being queried (user, group, domain)' },
        { name: 'Query', type: 'string', desc: 'The query itself, e.g. the LDAP filter' },
        { name: 'AccountUpn', type: 'string', desc: 'Account running the query' },
        { name: 'DeviceName', type: 'string', desc: 'Source device' },
        { name: 'IPAddress', type: 'string', desc: 'Source IP' },
        { name: 'DestinationDeviceName', type: 'string', desc: 'DC answering the query' }
      ],
      actionTypes: ['LDAP query', 'SAMR query', 'DNS query'],
      sample: {
        Timestamp: '2026-11-05T10:15:27Z', ActionType: 'LDAP query', QueryType: 'EnumerateUsers',
        Query: '(&(objectCategory=person)(servicePrincipalName=*))', AccountUpn: 'jdoe@contoso.com',
        DeviceName: 'ws-0142', IPAddress: '10.20.4.17', DestinationDeviceName: 'dc01.contoso.local'
      },
      starter: String.raw`// Accounts querying many privileged groups via SAMR
IdentityQueryEvents
| where Timestamp > ago(1d)
| where ActionType == "SAMR query"
| where QueryTarget has_any ("Domain Admins", "Enterprise Admins", "Administrators", "Schema Admins")
| summarize Queries = count(), Targets = make_set(QueryTarget, 10) by AccountUpn, DeviceName
| order by Queries desc`
    },
    {
      name: 'IdentityDirectoryEvents',
      source: 'Defender for Identity',
      docs: MS_DOCS + 'identitydirectoryevents-table',
      summary: 'Changes and activity on domain controllers: password changes, group membership changes, account enable/disable, replication, and some DC system activity.',
      huntFor: [
        'Additions to privileged groups',
        'Password resets on admin or service accounts',
        'Replication requests from non-DCs (DCSync)'
      ],
      columns: [
        { name: 'Timestamp', type: 'datetime', desc: 'When the change happened' },
        { name: 'ActionType', type: 'string', desc: 'What changed - check the in-portal schema reference for the full list' },
        { name: 'AccountUpn', type: 'string', desc: 'Account that made the change' },
        { name: 'TargetAccountUpn', type: 'string', desc: 'Account the change was applied to' },
        { name: 'DeviceName', type: 'string', desc: 'Source device' },
        { name: 'IPAddress', type: 'string', desc: 'Source IP' },
        { name: 'DestinationDeviceName', type: 'string', desc: 'DC that processed it' },
        { name: 'AdditionalFields', type: 'dynamic', desc: 'Details such as group name, old/new values' }
      ],
      actionTypes: ['Group Membership changed', 'Account Password changed', 'Account Disabled', 'Account Enabled'],
      sample: {
        Timestamp: '2026-11-05T11:02:48Z', ActionType: 'Group Membership changed', AccountUpn: 'helpdesk7@contoso.com',
        TargetAccountUpn: 'temp.admin@contoso.com', DestinationDeviceName: 'dc01.contoso.local',
        AdditionalFields: { 'TO.GROUP': 'Domain Admins' }
      },
      starter: String.raw`// Group membership changes involving admin groups
IdentityDirectoryEvents
| where Timestamp > ago(7d)
| where ActionType == "Group Membership changed"
| where tostring(AdditionalFields) has_any ("Domain Admins", "Enterprise Admins", "Administrators", "Schema Admins")
| project Timestamp, AccountUpn, TargetAccountUpn, DeviceName, AdditionalFields
| order by Timestamp desc`
    },
    {
      name: 'CloudAppEvents',
      source: 'Defender for Cloud Apps',
      docs: MS_DOCS + 'cloudappevents-table',
      summary: 'Activity in Microsoft 365 (Exchange, SharePoint, OneDrive, Teams) and other connected SaaS apps, enriched with geo, ISP and "uncommon for user" signals.',
      huntFor: [
        'Inbox rule creation, mailbox permission changes and MailItemsAccessed by unusual clients',
        'Mass downloads or external sharing from SharePoint/OneDrive',
        'Admin operations from anonymous proxies or new countries'
      ],
      columns: [
        { name: 'Timestamp', type: 'datetime', desc: 'When the activity happened' },
        { name: 'ActionType', type: 'string', desc: 'Operation name (FileDownloaded, New-InboxRule, Add member to role...)' },
        { name: 'Application', type: 'string', desc: 'Microsoft Exchange Online, Microsoft SharePoint Online...' },
        { name: 'AccountDisplayName', type: 'string', desc: 'Display name of the user' },
        { name: 'AccountObjectId', type: 'string', desc: 'Entra object ID - stable join key' },
        { name: 'IPAddress', type: 'string', desc: 'Client IP' },
        { name: 'CountryCode', type: 'string', desc: 'Geolocated country' },
        { name: 'IsAnonymousProxy', type: 'bool', desc: 'IP is a known anonymiser (Tor, VPN services)' },
        { name: 'IsAdminOperation', type: 'bool', desc: 'Admin-level activity' },
        { name: 'ObjectName', type: 'string', desc: 'File, mailbox or object acted on' },
        { name: 'UncommonForUser', type: 'dynamic', desc: 'Attributes unusual for this user - great anomaly filter' },
        { name: 'RawEventData', type: 'dynamic', desc: 'Full raw audit record (parameters, client info)' }
      ],
      actionTypes: ['FileDownloaded', 'FileUploaded', 'New-InboxRule', 'Set-Mailbox', 'MailItemsAccessed', 'Add member to role'],
      sample: {
        Timestamp: '2026-11-05T09:31:15Z', ActionType: 'New-InboxRule', Application: 'Microsoft Exchange Online',
        AccountDisplayName: 'Jane Doe', IPAddress: '198.51.100.88', CountryCode: 'NG', IsAnonymousProxy: true,
        ObjectName: 'jdoe@contoso.com', UncommonForUser: ['CountryCode', 'ISP']
      },
      starter: String.raw`// Admin operations from anonymous proxies
CloudAppEvents
| where Timestamp > ago(7d)
| where IsAdminOperation == true and IsAnonymousProxy == true
| project Timestamp, AccountDisplayName, Application, ActionType, IPAddress, CountryCode, ObjectName
| order by Timestamp desc`
    },
    {
      name: 'AlertInfo',
      source: 'Defender XDR (all services)',
      docs: MS_DOCS + 'alertinfo-table',
      summary: 'One row per alert from every Defender product (and onboarded Sentinel): title, category, severity, detection source and ATT&CK techniques.',
      huntFor: [
        'Alert trends by category and severity',
        'Multi-stage intrusions (join AlertEvidence to group alerts by device or user)',
        'Low-severity alerts that cluster on one entity'
      ],
      columns: [
        { name: 'Timestamp', type: 'datetime', desc: 'When the alert was generated' },
        { name: 'AlertId', type: 'string', desc: 'Join key to AlertEvidence' },
        { name: 'Title', type: 'string', desc: 'Alert title' },
        { name: 'Category', type: 'string', desc: 'Kill-chain style category (Execution, Persistence, CredentialAccess...)' },
        { name: 'Severity', type: 'string', desc: 'Informational / Low / Medium / High' },
        { name: 'ServiceSource', type: 'string', desc: 'Product that raised it (Endpoint, Office 365, Identity...)' },
        { name: 'DetectionSource', type: 'string', desc: 'Detection technology (EDR, Antivirus, Custom detection...)' },
        { name: 'AttackTechniques', type: 'string', desc: 'ATT&CK techniques associated with the alert' }
      ],
      actionTypes: [],
      sample: {
        Timestamp: '2026-11-05T14:07:00Z', AlertId: 'da638...', Title: 'Suspicious PowerShell command line',
        Category: 'Execution', Severity: 'Medium', ServiceSource: 'Microsoft Defender for Endpoint',
        DetectionSource: 'EDR', AttackTechniques: '["PowerShell (T1059.001)"]'
      },
      starter: String.raw`// Alert volume by product, category and severity this week
AlertInfo
| where Timestamp > ago(7d)
| summarize Alerts = count() by ServiceSource, Category, Severity
| order by Alerts desc`
    },
    {
      name: 'AlertEvidence',
      source: 'Defender XDR (all services)',
      docs: MS_DOCS + 'alertevidence-table',
      summary: 'The entities behind each alert - devices, users, files, IPs, URLs, emails, processes, registry values. Multiple rows per alert.',
      huntFor: [
        'Every alert touching a given user, device, hash or IP',
        'Files and IPs that appear in several alerts (shared infrastructure)',
        'Pivoting from an alert to raw telemetry in Device* tables'
      ],
      columns: [
        { name: 'Timestamp', type: 'datetime', desc: 'When the evidence was recorded' },
        { name: 'AlertId', type: 'string', desc: 'Join key to AlertInfo' },
        { name: 'EntityType', type: 'string', desc: 'Machine, User, File, Process, Ip, Url, MailMessage...' },
        { name: 'EvidenceRole', type: 'string', desc: 'Impacted or Related' },
        { name: 'DeviceName', type: 'string', desc: 'Device (for Machine/Process/File evidence)' },
        { name: 'AccountUpn', type: 'string', desc: 'User (for User evidence)' },
        { name: 'FileName', type: 'string', desc: 'File name' },
        { name: 'SHA1', type: 'string', desc: 'File hash' },
        { name: 'RemoteIP', type: 'string', desc: 'IP evidence' },
        { name: 'RemoteUrl', type: 'string', desc: 'URL evidence' },
        { name: 'ProcessCommandLine', type: 'string', desc: 'Command line for process evidence' }
      ],
      actionTypes: [],
      sample: {
        Timestamp: '2026-11-05T14:07:00Z', AlertId: 'da638...', EntityType: 'Process', EvidenceRole: 'Impacted',
        DeviceName: 'ws-0142.contoso.local', FileName: 'powershell.exe',
        ProcessCommandLine: 'powershell.exe -nop -w hidden -enc SQBFAFgA...'
      },
      starter: String.raw`// Hashes that appear in alerts on more than one device
AlertEvidence
| where Timestamp > ago(30d)
| where EntityType == "File" and isnotempty(SHA1)
| summarize Devices = dcount(DeviceName), Alerts = dcount(AlertId), Names = make_set(FileName, 5) by SHA1
| where Devices > 1
| order by Devices desc`
    }
  ];

  const crowdstrikeEvents = [
    {
      name: 'ProcessRollup2',
      source: 'Falcon sensor (Windows, macOS, Linux)',
      summary: 'Process execution - the backbone of Falcon hunting. One event per process start, with image path, command line, hashes, user and parent.',
      huntFor: [
        'Parent/child anomalies (Office -> PowerShell, web server -> cmd)',
        'Encoded PowerShell, LOLBins, credential dumping tools, discovery bursts',
        'Joining other events back to the process that caused them (TargetProcessId)'
      ],
      fields: [
        { name: 'aid', desc: 'Agent ID - unique per host; use with process IDs for joins' },
        { name: 'ComputerName', desc: 'Host name' },
        { name: 'UserName', desc: 'User that started the process' },
        { name: 'UserSid', desc: 'SID of that user' },
        { name: 'ImageFileName', desc: 'Full path of the process image' },
        { name: 'FileName', desc: 'Image name only (e.g. powershell.exe)' },
        { name: 'CommandLine', desc: 'Full command line' },
        { name: 'ParentBaseFileName', desc: 'Parent process name' },
        { name: 'TargetProcessId', desc: 'ID of this process - other events reference it as ContextProcessId' },
        { name: 'ParentProcessId', desc: 'ID of the parent process' },
        { name: 'SHA256HashData', desc: 'SHA256 of the image' },
        { name: 'MD5HashData', desc: 'MD5 of the image' }
      ],
      sample: {
        '#event_simpleName': 'ProcessRollup2', aid: '4e1a...c9', ComputerName: 'WS-0142', UserName: 'jdoe',
        ImageFileName: '\\Device\\HarddiskVolume3\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
        CommandLine: 'powershell.exe -nop -w hidden -enc SQBFAFgA...', ParentBaseFileName: 'WINWORD.EXE',
        TargetProcessId: '1234567890123', SHA256HashData: '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08'
      },
      starter: String.raw`// Most common parent -> child pairs for script interpreters (baseline, then hunt the rare ones)
#event_simpleName=ProcessRollup2
| in(field="FileName", values=["powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe"], ignoreCase=true)
| groupBy([ParentBaseFileName, FileName], function=[count(as=Executions), count(aid, distinct=true, as=Hosts)], limit=max)
| sort(Executions, order=asc, limit=200)`
    },
    {
      name: 'NetworkConnectIP4',
      source: 'Falcon sensor',
      summary: 'Outbound IPv4 connections made by processes. (NetworkConnectIP6 covers IPv6.)',
      huntFor: [
        'Beaconing: many connections to the same external IP/port over hours',
        'Internal fan-out on 445/3389/5985 (lateral movement)',
        'Unexpected processes connecting out (join on ContextProcessId)'
      ],
      fields: [
        { name: 'aid', desc: 'Agent ID' },
        { name: 'ComputerName', desc: 'Host name' },
        { name: 'ContextProcessId', desc: 'Process that made the connection (= TargetProcessId in ProcessRollup2)' },
        { name: 'LocalAddressIP4', desc: 'Local IP' },
        { name: 'LocalPort', desc: 'Local port' },
        { name: 'RemoteAddressIP4', desc: 'Destination IP - use cidr() to split internal/external, ipLocation() for geo' },
        { name: 'RemotePort', desc: 'Destination port' }
      ],
      sample: {
        '#event_simpleName': 'NetworkConnectIP4', aid: '4e1a...c9', ComputerName: 'WS-0142', ContextProcessId: '1234567890123',
        LocalAddressIP4: '10.20.4.17', LocalPort: '51544', RemoteAddressIP4: '203.0.113.45', RemotePort: '443'
      },
      starter: String.raw`// Top external destinations by number of hosts
#event_simpleName=NetworkConnectIP4
| !cidr(RemoteAddressIP4, subnet=["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8"])
| groupBy([RemoteAddressIP4, RemotePort], function=[count(aid, distinct=true, as=Hosts), count(as=Connections)], limit=max)
| sort(Hosts, order=desc, limit=200)`
    },
    {
      name: 'NetworkListenIP4',
      source: 'Falcon sensor',
      summary: 'A process started listening on a local IPv4 port.',
      huntFor: [
        'Backdoors and reverse proxies opening listening ports',
        'Unexpected services listening on workstations',
        'Tools like ngrok, chisel or socat (join to ProcessRollup2)'
      ],
      fields: [
        { name: 'aid', desc: 'Agent ID' },
        { name: 'ComputerName', desc: 'Host name' },
        { name: 'ContextProcessId', desc: 'Listening process (join to ProcessRollup2.TargetProcessId)' },
        { name: 'LocalAddressIP4', desc: 'Address bound (0.0.0.0 = all interfaces)' },
        { name: 'LocalPort', desc: 'Port listened on' }
      ],
      sample: {
        '#event_simpleName': 'NetworkListenIP4', aid: '4e1a...c9', ComputerName: 'WS-0142', ContextProcessId: '1234567899999',
        LocalAddressIP4: '0.0.0.0', LocalPort: '4444'
      },
      starter: String.raw`// Listening ports seen on only a few hosts
#event_simpleName=NetworkListenIP4
| groupBy([LocalPort], function=[count(aid, distinct=true, as=Hosts), collect([ComputerName], limit=10)], limit=max)
| Hosts <= 3
| sort(Hosts, order=asc, limit=200)`
    },
    {
      name: 'DnsRequest',
      source: 'Falcon sensor',
      summary: 'DNS lookups made by processes on the host - which process asked for which domain.',
      huntFor: [
        'Rare domains queried repeatedly (beaconing)',
        'DGA-looking or very long subdomains (tunnelling)',
        'Which process resolved a known-bad domain'
      ],
      fields: [
        { name: 'aid', desc: 'Agent ID' },
        { name: 'ComputerName', desc: 'Host name' },
        { name: 'DomainName', desc: 'Domain looked up' },
        { name: 'ContextProcessId', desc: 'Process that made the request (join to ProcessRollup2)' }
      ],
      sample: {
        '#event_simpleName': 'DnsRequest', aid: '4e1a...c9', ComputerName: 'WS-0142',
        DomainName: 'update-check.example', ContextProcessId: '1234567890123'
      },
      starter: String.raw`// Which processes looked up a domain of interest (replace the domain)
#event_simpleName=DnsRequest DomainName=/update-check\.example$/i
| join(query={#event_simpleName=ProcessRollup2}, field=[aid, ContextProcessId], key=[aid, TargetProcessId], include=[ImageFileName, CommandLine])
| table([@timestamp, ComputerName, DomainName, ImageFileName, CommandLine], limit=1000)`
    },
    {
      name: 'UserLogon',
      source: 'Falcon sensor',
      summary: 'Successful user logons with logon type, source address and whether the user is an administrator.',
      huntFor: [
        'RDP (LogonType 10) from public IPs',
        'Impossible travel between logons (ipLocation + neighbor())',
        'Admin logons on hosts where that user never logs on'
      ],
      fields: [
        { name: 'aid', desc: 'Agent ID' },
        { name: 'ComputerName', desc: 'Host name' },
        { name: 'UserName', desc: 'User who logged on' },
        { name: 'UserSid', desc: 'User SID' },
        { name: 'LogonType', desc: 'Windows logon type: 2 interactive, 3 network, 10 RDP, 11 cached...' },
        { name: 'LogonDomain', desc: 'Domain of the account' },
        { name: 'LogonTime', desc: 'Logon time (epoch seconds)' },
        { name: 'RemoteAddressIP4', desc: 'Source IP for remote logons' },
        { name: 'UserIsAdmin', desc: '1 if the user is a local administrator' }
      ],
      sample: {
        '#event_simpleName': 'UserLogon', aid: '7c2d...41', ComputerName: 'SRV-APP01', UserName: 'svc_backup',
        LogonType: '10', LogonDomain: 'CONTOSO', RemoteAddressIP4: '198.51.100.23', UserIsAdmin: '1'
      },
      starter: String.raw`// Admin logons by user and host
#event_simpleName=UserLogon UserIsAdmin=1
| groupBy([UserName], function=[count(aid, distinct=true, as=Hosts), collect([ComputerName], limit=20)], limit=max)
| sort(Hosts, order=desc, limit=200)`
    },
    {
      name: 'UserLogonFailed2',
      source: 'Falcon sensor',
      summary: 'Failed logon attempts with user name, logon type, source address and the Windows failure sub-status.',
      huntFor: [
        'Password spraying (one IP, many accounts)',
        'Brute force against a single account',
        'Attempts against disabled or non-existent accounts (SubStatus)'
      ],
      fields: [
        { name: 'aid', desc: 'Agent ID' },
        { name: 'ComputerName', desc: 'Host name' },
        { name: 'UserName', desc: 'Account that failed' },
        { name: 'LogonType', desc: 'Logon type attempted' },
        { name: 'RemoteAddressIP4', desc: 'Source IP' },
        { name: 'SubStatus', desc: 'Windows sub-status: 0xC000006A bad password, 0xC0000064 unknown user, 0xC0000072 disabled...' }
      ],
      sample: {
        '#event_simpleName': 'UserLogonFailed2', aid: '7c2d...41', ComputerName: 'SRV-APP01', UserName: 'administrator',
        LogonType: '3', RemoteAddressIP4: '203.0.113.99', SubStatus: '0xC000006A'
      },
      starter: String.raw`// Failure reasons overview
#event_simpleName=UserLogonFailed2
| groupBy([SubStatus, LogonType], function=[count(as=Failures), count(UserName, distinct=true, as=Accounts)], limit=max)
| sort(Failures, order=desc, limit=100)`
    },
    {
      name: 'NewExecutableWritten / PeFileWritten',
      eventPattern: '/^(NewExecutableWritten|PeFileWritten)$/',
      source: 'Falcon sensor',
      summary: 'A new executable (PE) file was written to disk - the moment a payload lands.',
      huntFor: [
        'Executables written to Downloads, Temp, Public or web roots',
        'Payloads written by browsers, Office or script hosts',
        'Tools dropped over SMB onto servers'
      ],
      fields: [
        { name: 'aid', desc: 'Agent ID' },
        { name: 'ComputerName', desc: 'Host name' },
        { name: 'TargetFileName', desc: 'Full path of the written file' },
        { name: 'FileName', desc: 'File name' },
        { name: 'ContextProcessId', desc: 'Process that wrote it (join to ProcessRollup2)' }
      ],
      sample: {
        '#event_simpleName': 'NewExecutableWritten', aid: '4e1a...c9', ComputerName: 'WS-0142',
        TargetFileName: '\\Device\\HarddiskVolume3\\Users\\jdoe\\Downloads\\Invoice_44812.exe',
        FileName: 'Invoice_44812.exe', ContextProcessId: '1234567811111'
      },
      starter: String.raw`// Executables written into user-writable folders
#event_simpleName=/^(NewExecutableWritten|PeFileWritten)$/
| TargetFileName=/\\(Downloads|AppData|Temp|Users\\Public|ProgramData)\\/i
| groupBy([TargetFileName], function=[count(aid, distinct=true, as=Hosts), collect([ComputerName], limit=10)], limit=max)
| sort(Hosts, order=desc, limit=200)`
    },
    {
      name: 'NewScriptWritten',
      source: 'Falcon sensor',
      summary: 'A script file (PowerShell, batch, VBS, JS...) was written to disk.',
      huntFor: [
        'Scripts dropped into Startup folders or Temp',
        'Scripts written by Office, browsers or web servers',
        'Staging of attacker tooling on servers'
      ],
      fields: [
        { name: 'aid', desc: 'Agent ID' },
        { name: 'ComputerName', desc: 'Host name' },
        { name: 'TargetFileName', desc: 'Full path of the script' },
        { name: 'FileName', desc: 'Script name' },
        { name: 'ContextProcessId', desc: 'Process that wrote it' },
        { name: 'size', desc: 'Size in bytes' }
      ],
      sample: {
        '#event_simpleName': 'NewScriptWritten', aid: '4e1a...c9', ComputerName: 'WS-0142',
        TargetFileName: '\\Device\\HarddiskVolume3\\Users\\jdoe\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\update.vbs',
        FileName: 'update.vbs', size: '2184'
      },
      starter: String.raw`// Scripts written to Startup folders
#event_simpleName=NewScriptWritten
| TargetFileName=/\\Start Menu\\Programs\\Startup\\/i
| table([@timestamp, ComputerName, TargetFileName, ContextProcessId], limit=1000)`
    },
    {
      name: 'ScheduledTaskRegistered',
      source: 'Falcon sensor (Windows)',
      summary: 'A scheduled task was registered - by schtasks.exe, PowerShell, COM or the API. Catches tasks that never appear in a command line.',
      huntFor: [
        'Tasks that run script hosts or files in user folders',
        'Tasks with random or masquerading names',
        'Tasks created on many hosts at once (deployment by an attacker)'
      ],
      fields: [
        { name: 'aid', desc: 'Agent ID' },
        { name: 'ComputerName', desc: 'Host name' },
        { name: 'TaskName', desc: 'Name/path of the task' },
        { name: 'TaskExecCommand', desc: 'Program the task runs' },
        { name: 'TaskExecArguments', desc: 'Arguments passed to it' }
      ],
      sample: {
        '#event_simpleName': 'ScheduledTaskRegistered', aid: '4e1a...c9', ComputerName: 'WS-0142',
        TaskName: '\\Microsoft\\Windows\\UpdateOrchestrator\\OneDriveSync', TaskExecCommand: 'C:\\Users\\Public\\odupd.exe',
        TaskExecArguments: '-silent'
      },
      starter: String.raw`// Task names seen on many hosts (mass deployment) - review the rare commands
#event_simpleName=ScheduledTaskRegistered
| groupBy([TaskName, TaskExecCommand], function=[count(aid, distinct=true, as=Hosts)], limit=max)
| sort(Hosts, order=desc, limit=200)`
    },
    {
      name: 'AsepValueUpdate',
      source: 'Falcon sensor (Windows)',
      summary: 'A value in an auto-start extensibility point (ASEP) in the registry was changed - Run keys, services, Winlogon and similar persistence locations.',
      huntFor: [
        'New Run/RunOnce values pointing to user-writable paths',
        'Service and Winlogon modifications',
        'Persistence installed right after a suspicious download'
      ],
      fields: [
        { name: 'aid', desc: 'Agent ID' },
        { name: 'ComputerName', desc: 'Host name' },
        { name: 'RegValueName', desc: 'Name of the registry value that changed' },
        { name: 'RegObjectName', desc: 'Registry key path', verify: true },
        { name: 'RegStringValue', desc: 'String data written to the value', verify: true },
        { name: 'ContextProcessId', desc: 'Process that made the change' }
      ],
      sample: {
        '#event_simpleName': 'AsepValueUpdate', aid: '4e1a...c9', ComputerName: 'WS-0142',
        RegObjectName: '\\REGISTRY\\USER\\S-1-5-21-...\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
        RegValueName: 'OneDriveUpdate', RegStringValue: 'C:\\Users\\Public\\odupd.exe'
      },
      starter: String.raw`// Rarest ASEP value names across the fleet
#event_simpleName=AsepValueUpdate
| groupBy([RegValueName], function=[count(aid, distinct=true, as=Hosts), collect([ComputerName], limit=10)], limit=max)
| Hosts <= 2
| sort(Hosts, order=asc, limit=200)`
    },
    {
      name: 'FileOpenInfo',
      source: 'Falcon sensor (when file-open telemetry is enabled)',
      summary: 'A file was opened. Not collected for every file or on every policy - check availability before relying on it.',
      huntFor: [
        'Browser credential stores read by non-browsers (infostealers)',
        'Access to sensitive files (NTDS.dit copies, SAM/SYSTEM hives, KeePass databases)',
        'Which process touched a file of interest'
      ],
      fields: [
        { name: 'aid', desc: 'Agent ID' },
        { name: 'ComputerName', desc: 'Host name' },
        { name: 'TargetFileName', desc: 'Full path of the opened file' },
        { name: 'ContextProcessId', desc: 'Process that opened it (join to ProcessRollup2)' }
      ],
      sample: {
        '#event_simpleName': 'FileOpenInfo', aid: '4e1a...c9', ComputerName: 'WS-0142',
        TargetFileName: '\\Device\\HarddiskVolume3\\Users\\jdoe\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data',
        ContextProcessId: '1234567822222'
      },
      starter: String.raw`// Password database and hive files opened
#event_simpleName=FileOpenInfo
| TargetFileName=/(\.kdbx$|\\ntds\.dit$|\\config\\SAM$|\\config\\SYSTEM$)/i
| table([@timestamp, ComputerName, TargetFileName, ContextProcessId], limit=1000)`
    }
  ];

  /** How Falcon events relate to each other - shown above the CrowdStrike reference. */
  const crowdstrikeJoinNotes = [
    'Process IDs only make sense together with aid: always join on both.',
    'ProcessRollup2.TargetProcessId is the process itself; most other events point back to it with ContextProcessId.',
    'ProcessRollup2.ParentProcessId links a process to its parent (another ProcessRollup2 with that TargetProcessId).',
    'Timestamps: @timestamp is ingest-normalised event time; some events also carry their own epoch fields (e.g. LogonTime).',
    'Field availability depends on sensor version, platform and policy - confirm in Falcon\'s Event Data Dictionary (Support and resources > Documentation).'
  ];

  return { defenderTables, crowdstrikeEvents, crowdstrikeJoinNotes };
});
