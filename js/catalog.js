/*
 * Table / event catalog shown on the Detection Queries page: which Microsoft
 * Defender XDR table or CrowdStrike Falcon #event_simpleName to use for what.
 */
(function (root, factory) {
  const api = factory();
  if (typeof module === 'object' && module.exports) module.exports = api;
  else root.THQV = Object.assign(root.THQV || {}, api);
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  const defenderCatalog = [
    {
      category: 'Endpoint & Host Telemetry (Device*)',
      items: [
        { names: ['DeviceProcessEvents'], desc: 'Captures process creation events, executable filenames, parent-child process lineage, file hashes (SHA256), and command-line arguments.' },
        { names: ['DeviceFileEvents'], desc: 'Logs file creation, modification, deletion, and renaming actions on host endpoints.' },
        { names: ['DeviceNetworkEvents'], desc: 'Records inbound and outbound TCP/UDP socket network connections, remote IP addresses, ports, protocol types, and initiating processes.' },
        { names: ['DeviceEvents'], desc: 'Audits endpoint security events, including antivirus detections, USB drive mounts, exploit protection and ASR triggers, and other Defender sensor events.' },
        { names: ['DeviceLogonEvents'], desc: 'Tracks local and network authentication events on endpoints (interactive, RDP, batch, and service logons).' },
        { names: ['DeviceInfo'], desc: 'Provides host hardware specs, OS platform/build details, domain membership, and machine enrollment status.' },
        { names: ['DeviceNetworkInfo'], desc: 'Details physical and virtual network adapter configurations, IP assignments, MAC addresses, and active interfaces.' },
        { names: ['DeviceImageLoadEvents'], desc: 'Logs executable DLLs and driver image loads into active memory.' },
        { names: ['DeviceRegistryEvents'], desc: 'Audits Windows Registry key and value creations, modifications, and deletions.' }
      ]
    },
    {
      category: 'Threat & Vulnerability Management (DeviceTvm*)',
      items: [
        { names: ['DeviceTvmSoftwareVulnerabilities'], desc: 'Maps active software vulnerabilities and CVE IDs to specific endpoint assets.' },
        { names: ['DeviceTvmSoftwareVulnerabilitiesKB'], desc: 'Vulnerability knowledge base providing CVSS scores, exploit availability, descriptions, and patch metadata.' },
        { names: ['DeviceTvmSoftwareInventory'], desc: 'Inventories all installed software products, vendors, and versions across devices.' },
        { names: ['DeviceTvmBrowserExtensions'], desc: 'Catalogues installed browser extensions and add-ons across host endpoints.' },
        { names: ['DeviceTvmSecureConfigurationAssessment'], desc: 'Tracks device security baseline configuration states and compliance checks.' }
      ]
    },
    {
      category: 'Identity & Cloud Authentication (EntraId* / Identity*)',
      items: [
        { names: ['EntraIdSignInEvents'], desc: 'Audits interactive and non-interactive Entra ID (Azure AD) user authentications, capturing IP addresses, location (city/country), User-Agent strings, applications, and error codes.' },
        { names: ['EntraIdSpnSignInEvents'], desc: 'Tracks authentication events for service principals and workload identities.' },
        { names: ['IdentityLogonEvents'], desc: 'Captures on-premises Active Directory and domain controller authentications (Kerberos, NTLM).' },
        { names: ['IdentityDirectoryEvents'], desc: 'Audits on-premises Active Directory changes captured by Defender for Identity on domain controllers (password changes, group membership changes, account enable/disable).' },
        { names: ['IdentityQueryEvents'], desc: 'Tracks LDAP and Active Directory directory queries for reconnaissance detection.' },
        { names: ['IdentityInfo'], desc: 'Provides user profile metadata, job titles, departments, manager details, and risk levels.' }
      ]
    },
    {
      category: 'Multicloud Control Plane & SaaS (Cloud* / OAuth*)',
      items: [
        { names: ['CloudAppEvents'], desc: 'Tracks user and administrative activities across SaaS platforms (Office 365, Teams, Exchange, Defender for Cloud Apps) and OAuth consents.' },
        { names: ['CloudAuditEvents'], desc: 'Logs multicloud management plane operations across AWS CloudTrail, Azure Resource Manager (ARM), and GCP.' },
        { names: ['CloudStorageAggregatedEvents'], desc: 'Aggregates read, write, and deletion operations against cloud storage infrastructure (Amazon S3 buckets, Azure Blobs).' },
        { names: ['CloudDnsEvents'], desc: 'Logs cloud and endpoint DNS queries, resolved IP addresses, and query types.' },
        { names: ['CloudProcessEvents'], desc: 'Audits process execution within containerized workloads and cloud serverless environments.' },
        { names: ['OAuthAppInfo'], desc: 'Contains details on registered OAuth applications, requested API permissions, and admin consent status.' }
      ]
    },
    {
      category: 'Email & Collaboration Security (Email* / Message* / File*)',
      items: [
        { names: ['EmailEvents'], desc: 'Audits inbound, outbound, and intra-org email processing (senders, recipients, subjects, delivery actions).' },
        { names: ['EmailAttachmentInfo'], desc: 'Details email file attachments, names, extensions, sizes, and file hashes.' },
        { names: ['EmailUrlInfo'], desc: 'Tracks web URLs embedded within delivered email bodies.' },
        { names: ['EmailPostDeliveryEvents'], desc: 'Logs post-delivery remediation actions (e.g., ZAP / Zero-hour Auto Purge) taken on delivered mail.' },
        { names: ['MessageEvents'], desc: 'Tracks message traffic and activity within Microsoft Teams and collaboration apps.' },
        { names: ['MessageUrlInfo'], desc: 'Catalogues URLs embedded inside Microsoft Teams chats and channel posts.' },
        { names: ['FileMaliciousContentInfo'], desc: 'Logs malware detections across M365 cloud storage (SharePoint, OneDrive, Teams).' }
      ]
    },
    {
      category: 'Security Alerts & Automated Response (Alert* / Disruption*)',
      items: [
        { names: ['AlertInfo'], desc: 'Contains high-level alert metadata (Title, Severity, Category, Service Source, Description).' },
        { names: ['AlertEvidence'], desc: 'Links specific entities (Files, IP Addresses, User Accounts, Devices, Process CLIs) as evidence to open security alerts.' },
        { names: ['DisruptionAndResponseEvents'], desc: 'Tracks automated containment and response actions executed by Defender (e.g., automatic device isolation, user containment).' }
      ]
    }
  ];

  const crowdstrikeCatalog = [
    {
      category: 'Process Execution & Lifecycle Events',
      items: [
        { names: ['ProcessRollup2'], desc: 'Primary process creation/execution event in Falcon. Records process start, binary file name, full file path, command line arguments, parent process, user context, hashes, and process tree lineage.' },
        { names: ['SyntheticProcessRollup2'], desc: 'Synthesized or enriched process execution record generated by Falcon for tracking background or complex process trees.' },
        { names: ['EndOfProcess'], desc: 'Process termination event. Records when a process exits, used to calculate runtime duration and process lifecycle.' },
        { names: ['ProcessExecOnSMBFile'], desc: 'Triggered when a process is executed directly from a remote SMB share or SMB-mapped network path (often associated with lateral movement).' },
        { names: ['ProcessInjectionSummary'], desc: 'Detects process memory injection attempts (e.g., thread injection, function hooking, or AMSI bypass).' }
      ]
    },
    {
      category: 'Network & DNS Telemetry',
      items: [
        { names: ['NetworkConnectIP4'], desc: 'Outbound or established IPv4 socket connection initiated by a process to a remote IP address and port.' },
        { names: ['NetworkReceiveIP4', 'NetworkReceiveAcceptIP4'], desc: 'Inbound IPv4 network connection received or accepted by a local listening port on the endpoint.' },
        { names: ['NetworkListenIP4'], desc: 'Indicates a process binding to a network socket and listening for incoming connections.' },
        { names: ['DnsRequest'], desc: 'DNS domain lookup/resolution query initiated by an endpoint process.' },
        { names: ['SuspiciousDnsRequest'], desc: 'Falcon-flagged DNS query involving suspicious, newly registered, or high-risk domains (e.g., C2 channels, dynamic DNS).' }
      ]
    },
    {
      category: 'User Authentication & Account Management',
      items: [
        { names: ['UserLogon'], desc: 'Successful user logon event on the endpoint (e.g., Interactive Type 2, Network Share Type 3, Remote Interactive RDP Type 10).' },
        { names: ['UserLogonFailed2'], desc: 'Failed user authentication attempt, recording failure sub-status codes, target account, and logon type.' },
        { names: ['UserAccountCreated'], desc: 'Logged when a new local or domain user account is created.' },
        { names: ['UserAccountAddedToGroup'], desc: 'Triggered when a user account is added to a local or domain security group (e.g., Administrators, Domain Admins).' }
      ]
    },
    {
      category: 'File, Disk & Media Operations',
      items: [
        { names: ['FileWritten'], desc: 'General file creation or modification write operation on the endpoint filesystem.' },
        { names: ['PeFileWritten'], desc: 'Specific write event when a Portable Executable file (.exe, .dll, .sys) is written to disk.' },
        { names: ['ELFFileWritten'], desc: 'Linux-specific file write event for Executable and Linkable Format (ELF) binaries.' },
        { names: ['AsepFileWritten'], desc: 'Auto-Start Execution Point file write event, indicating file creation/modification in persistence locations (e.g., Startup folders).' },
        { names: ['NewExecutableWritten'], desc: 'Triggered when a brand-new executable file is written to the filesystem for the first time.' },
        { names: ['NewScriptWritten'], desc: 'Triggered when a script file (.ps1, .vbs, .js, .bat, .sh) is written to disk.' },
        { names: ['DocumentFileWritten'], desc: 'File write event specifically for document files (.pdf, .docx, .xlsx, .zip, .iso, .img).' },
        { names: ['ZipFileWritten'], desc: 'Generated when a compressed ZIP archive file is written to disk.' },
        { names: ['PackedExecutableWritten'], desc: 'Detects when a packed, compressed, or obfuscated executable is written to disk.' },
        { names: ['FileOpen', 'FileRead', 'FileOpenInfo'], desc: 'File access, open, or read operations by a process (used for tracking access to browser credentials, SSH keys, or .env files).' },
        { names: ['FsVolumeMounted', 'RemovableMediaVolumeMounted', 'SnapshotVolumeMounted'], desc: 'Logged when a local/virtual filesystem volume, USB removable drive, ISO image, or VHD is mounted.' }
      ]
    },
    {
      category: 'Scripting, Memory & Detection Control',
      items: [
        { names: ['ScriptControlStart', 'ScriptControlScanTelemetry'], desc: 'Captures executed script content (PowerShell, VBScript, JavaScript) inspected via AMSI / Falcon Script Control.' },
        { names: ['CommandHistory'], desc: 'Shell command execution history captured directly from interactive command-line or PowerShell sessions.' },
        { names: ['ModuleLoad', 'ModuleLoadV3DetectInfo'], desc: 'Loading of a DLL or module into a process memory space.' },
        { names: ['DriverLoad'], desc: 'Kernel driver load event, capturing driver signatures, certificate details, and load paths.' },
        { names: ['ReflectiveDotnetModuleLoad'], desc: 'Detects in-memory / reflective loading of .NET assemblies without writing them to disk.' },
        { names: ['FalconProcessHandleOpDetectInfo'], desc: 'Triggered when an external process attempts to open an unauthorized handle to the Falcon sensor process (EDR tampering check).' }
      ]
    },
    {
      category: 'Active Directory & Identity Events',
      items: [
        { names: ['ActiveDirectoryAuthentication'], desc: 'Logs Active Directory authentication activity (NTLM v1/v2, Kerberos) across domain services.' },
        { names: ['ActiveDirectoryServiceAccessRequest', 'ActiveDirectoryServiceAccessRequestFailure'], desc: 'Tracks Kerberos SPN / service ticket requests (used for Kerberoasting detection).' }
      ]
    },
    {
      category: 'System Metadata & Sensor Health',
      items: [
        { names: ['SensorHeartbeat'], desc: 'Periodic ping event sent by the Falcon sensor to confirm endpoint connectivity and operational status.' },
        { names: ['AgentOnline'], desc: 'Event recorded when a sensor connects online with the Falcon cloud infrastructure.' },
        { names: ['OsVersionInfo'], desc: 'Periodic endpoint inventory event capturing OS build version, kernel strings, and agent version data.' }
      ]
    }
  ];

  return { defenderCatalog, crowdstrikeCatalog };
});
