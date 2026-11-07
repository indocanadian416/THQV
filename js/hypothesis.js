/*
 * Rule-based hunt hypothesis builder.
 *
 * Not an AI model: each article is matched against rules (CVEs mentioned,
 * defanged IOCs present, ransomware, phishing, supply chain, social
 * engineering, account compromise, APT, malware, vulnerabilities) and the best
 * match produces a hypothesis plus a Defender XDR advanced hunting query.
 *
 * To avoid repeating the same hunt for similar stories:
 *  - each rule has several hunt "angles" (variants) that rotate when the same
 *    rule matches more than one article;
 *  - titles name the threat or product from the headline where possible;
 *  - a query that has already been shown is never shown again.
 * Generated queries are type-checked in tests/osint-hypothesis.test.js.
 */
(function (root, factory) {
  const deps = typeof module === 'object' && module.exports ? require('./ioc.js') : root.THQV;
  const api = factory(deps);
  if (typeof module === 'object' && module.exports) module.exports = api;
  else root.THQV = Object.assign(root.THQV || {}, api);
})(typeof self !== 'undefined' ? self : this, function (ioc) {
  'use strict';

  const STOPWORDS = new Set((
    'about after again against also amid among analysis attack attacks attacker attackers being campaign campaigns ' +
    'could critical cyber data details discloses exploited exploit exploits flaw flaws from have hackers hacker into ' +
    'just more news over patch patched patches report reports researchers says security since some still than that ' +
    'their them then there these they this threat threats under used users using warns week what when where which ' +
    'while with your year years million billion new now how why who has had was were will its it’s ' +
    'fixes fixed fixing breach breached breaches claims claimed steal steals stole stolen abuse abuses abused ' +
    'target targets targeted targeting gang group groups leak leaks leaked wave rise rising actively update updates ' +
    'updated severe emergency months days hours warning alert alerts customer customers people firms companies ' +
    'company says hits hit linked tied behind spreads spread uses poses pose fake malicious ' +
    'ransomware malware stealer infostealer trojan botnet backdoor loader phishing vulnerability vulnerabilities zero-day ' +
    '2023 2024 2025 2026'
  ).split(/\s+/));

  /** Build a KQL dynamic([...]) literal from values (escapes quotes and backslashes). */
  function kqlList(values) {
    return 'dynamic([' + values.map((v) => '"' + String(v).replace(/\\/g, '\\\\').replace(/"/g, '\\"') + '"').join(', ') + '])';
  }

  function keywords(title, max) {
    const words = (String(title).toLowerCase().match(/[a-z0-9][a-z0-9-]{3,}/g) || [])
      .filter((w) => !STOPWORDS.has(w) && !/^\d+$/.test(w));
    return Array.from(new Set(words)).slice(0, max || 4);
  }

  const NOT_A_NAME = new Set(['New', 'The', 'A', 'An', 'This', 'Android', 'Windows', 'Linux', 'MacOS', 'Mac', 'iOS', 'Mobile', 'Banking', 'Chinese', 'Russian', 'Iranian', 'North', 'Korean', 'Info', 'Information', 'Data', 'Credential', 'Infostealer', 'Stealer', 'Malware', 'Ransomware', 'Botnet', 'Loader']);

  /** Family / actor name from the headline, e.g. "Qilin" in "Qilin ransomware claims ...". */
  function threatName(title) {
    const m = /\b([A-Z][A-Za-z0-9.-]{2,})\s+(?:ransomware|stealer|infostealer|malware|botnet|loader|trojan|backdoor|RAT|wiper|spyware)\b/.exec(String(title));
    return m && !NOT_A_NAME.has(m[1]) ? m[1] : null;
  }

  function isPublicIPv4(ip) {
    const [a, b] = ip.split('.').map(Number);
    return !(a === 10 || a === 127 || a === 0 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 169 && b === 254) || a >= 224);
  }

  /** IOCs that the article itself presented in defanged form (real indicators, not vendor links). */
  function articleIOCs(article) {
    const raw = article.title + ' ' + article.description;
    const found = ioc.extractIOCs(raw);
    const defangedOnly = (list) => list.filter((v) => !raw.includes(v));
    return {
      ips: found.ipv4.filter(isPublicIPv4),
      domains: defangedOnly(found.domains).filter((d) => d.toLowerCase() !== String(article.source || '').toLowerCase()),
      hashes: found.sha256.concat(found.sha1, found.md5),
      cves: found.cves
    };
  }

  const dateLabel = (a) => (a.date instanceof Date && !isNaN(a.date) ? a.date.toISOString().slice(0, 10) : 'recently');
  const has = (a, re) => re.test((a.title + ' ' + a.description).toLowerCase());
  const hasTag = (a, name) => (a.tags || []).some((t) => t.name === name);
  const named = (ctx, fallback) => (ctx.name ? ctx.name + ' ' + fallback : fallback.charAt(0).toUpperCase() + fallback.slice(1));

  /*
   * Each rule: match(article, iocs) and variants[] of build(article, ctx) where
   * ctx = { iocs, name (threat name or null), kw (headline keywords) }.
   * A variant may return null when it does not apply (e.g. no keywords).
   */
  const RULES = [
    {
      id: 'cve',
      match: (a, x) => x.cves.length > 0,
      variants: [
        (a, { iocs: x }) => ({
          title: 'Exposure check: are we running software affected by ' + x.cves.slice(0, 3).join(', ') + '?',
          hypothesis: 'The article reports ' + x.cves.join(', ') + '. If vulnerable versions exist in our estate and are reachable, attackers may exploit them before patching completes.',
          ttps: [{ id: 'T1190', name: 'Exploit Public-Facing Application' }, { id: 'T1203', name: 'Exploitation for Client Execution' }],
          query: 'DeviceTvmSoftwareVulnerabilities\n' +
            '| where CveId in (' + kqlList(x.cves) + ')\n' +
            '| summarize Devices = dcount(DeviceId), DeviceNames = make_set(DeviceName, 50)\n' +
            '    by CveId, SoftwareVendor, SoftwareName, SoftwareVersion, VulnerabilitySeverityLevel, RecommendedSecurityUpdate\n' +
            '| order by Devices desc',
          next: 'Prioritise internet-facing hosts in the result; then hunt for exploitation indicators published for these CVEs.'
        })
      ]
    },
    {
      id: 'ioc',
      match: (a, x) => x.ips.length + x.domains.length > 0,
      variants: [
        (a, { iocs: x }) => {
          const parts = [];
          if (x.ips.length) parts.push('RemoteIP in (' + kqlList(x.ips) + ')');
          if (x.domains.length) parts.push('RemoteUrl has_any (' + kqlList(x.domains) + ')');
          return {
            title: 'Retro-hunt the indicators published in this report',
            hypothesis: 'The report lists ' + (x.ips.length + x.domains.length) + ' network indicator(s). If any host in our environment contacted them, the campaign may already have reached us.',
            ttps: [{ id: 'T1071', name: 'Application Layer Protocol' }],
            query: 'DeviceNetworkEvents\n' +
              '| where Timestamp > ago(30d)\n' +
              '| where ' + parts.join('\n    or ') + '\n' +
              '| summarize Connections = count(), FirstSeen = min(Timestamp), LastSeen = max(Timestamp),\n' +
              '            Processes = make_set(InitiatingProcessFileName, 10)\n' +
              '    by DeviceName, RemoteIP, RemoteUrl\n' +
              '| order by LastSeen desc',
            next: 'Also search proxy/DNS logs - endpoint telemetry does not cover unmanaged devices. Extract the full IOC list in the IOC tab.'
          };
        }
      ]
    },
    {
      id: 'ransomware',
      match: (a) => hasTag(a, 'Ransomware') || has(a, /ransom/),
      variants: [
        (a, ctx) => ({
          title: named(ctx, 'ransomware') + ': look for mass file renames (encryption in progress)',
          hypothesis: 'Ransomware operators like those in this story rename large numbers of files within minutes when encryption starts. A burst of renames by one process is the clearest late-stage signal.',
          ttps: [{ id: 'T1486', name: 'Data Encrypted for Impact' }],
          query: 'DeviceFileEvents\n' +
            '| where Timestamp > ago(1d)\n' +
            '| where ActionType == "FileRenamed"\n' +
            '| extend Extension = tostring(split(FileName, ".")[-1])\n' +
            '| summarize Renamed = count(), Extensions = make_set(Extension, 10), Folders = dcount(FolderPath)\n' +
            '    by DeviceName, InitiatingProcessFileName, InitiatingProcessAccountName, bin(Timestamp, 5m)\n' +
            '| where Renamed > 200\n' +
            '| order by Renamed desc',
          next: 'Isolate any device in the result immediately, then trace the initiating process back to its parent.'
        }),
        (a, ctx) => ({
          title: named(ctx, 'ransomware') + ': check for shadow copy and backup deletion',
          hypothesis: 'Before encrypting, ransomware crews delete shadow copies and disable recovery so victims cannot restore. These commands rarely have a legitimate reason on workstations.',
          ttps: [{ id: 'T1490', name: 'Inhibit System Recovery' }],
          query: 'DeviceProcessEvents\n' +
            '| where Timestamp > ago(7d)\n' +
            '| where (FileName =~ "vssadmin.exe" and ProcessCommandLine has "delete" and ProcessCommandLine has "shadows")\n' +
            '    or (FileName =~ "wmic.exe" and ProcessCommandLine has "shadowcopy" and ProcessCommandLine has "delete")\n' +
            '    or (FileName =~ "bcdedit.exe" and ProcessCommandLine has_any ("recoveryenabled", "ignoreallfailures"))\n' +
            '    or (FileName =~ "wbadmin.exe" and ProcessCommandLine has "delete")\n' +
            '| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName\n' +
            '| order by Timestamp desc',
          next: 'Treat any hit as an active incident: check the same account for lateral movement in the previous 24 hours.'
        }),
        (a, ctx) => ({
          title: named(ctx, 'ransomware') + ': hunt for pre-ransomware tooling (AdFind, Rclone, network scanners)',
          hypothesis: 'Affiliates typically spend days on discovery and data theft before encryption, using the same handful of tools. Finding them early stops the attack before impact.',
          ttps: [{ id: 'T1087.002', name: 'Domain Account Discovery' }, { id: 'T1046', name: 'Network Service Discovery' }, { id: 'T1567.002', name: 'Exfiltration to Cloud Storage' }],
          query: 'DeviceProcessEvents\n' +
            '| where Timestamp > ago(7d)\n' +
            '| where FileName in~ ("adfind.exe", "rclone.exe", "advanced_ip_scanner.exe", "netscan.exe", "sharphound.exe", "psexec.exe", "psexec64.exe")\n' +
            '    or ProcessCommandLine has_any ("adfind", "rclone", "sharphound")\n' +
            '| summarize Tools = make_set(FileName, 10), Commands = make_set(ProcessCommandLine, 10), FirstSeen = min(Timestamp)\n' +
            '    by DeviceName, AccountName\n' +
            '| order by FirstSeen asc',
          next: 'Compare accounts against your admin list; an unexpected account running AdFind or Rclone warrants an incident.'
        }),
        (a, ctx) => ({
          title: named(ctx, 'ransomware') + ': look for data exfiltration before encryption (MEGA, Rclone, FTP tools)',
          hypothesis: 'Double-extortion groups steal data before encrypting it, usually to MEGA or with Rclone/WinSCP. Connections from these tools are an early warning.',
          ttps: [{ id: 'T1567.002', name: 'Exfiltration to Cloud Storage' }, { id: 'T1048', name: 'Exfiltration Over Alternative Protocol' }],
          query: 'DeviceNetworkEvents\n' +
            '| where Timestamp > ago(7d)\n' +
            '| where RemoteUrl has_any ("mega.nz", "mega.io", "mega.co.nz")\n' +
            '    or InitiatingProcessFileName in~ ("rclone.exe", "megasync.exe", "winscp.exe", "filezilla.exe")\n' +
            '| summarize Connections = count(), Destinations = make_set(RemoteUrl, 10)\n' +
            '    by DeviceName, InitiatingProcessFileName, InitiatingProcessAccountName\n' +
            '| order by Connections desc',
          next: 'Confirm transfer volume in proxy or firewall logs; endpoint network events have no byte counts.'
        })
      ]
    },
    {
      id: 'phishing',
      match: (a) => hasTag(a, 'Phishing') || has(a, /phish|lure|credential harvest|business email compromise|\bbec\b/),
      variants: [
        (a, ctx) => {
          if (!ctx.kw.length) return null;
          return {
            title: 'Hunt for inbound email themed on this story (' + ctx.kw.join(', ') + ')',
            hypothesis: 'Attackers turn breaking security news into lures within 24-48 hours. Delivered messages with subjects matching this story are candidates for credential-harvesting or malware delivery.',
            ttps: [{ id: 'T1566', name: 'Phishing' }, { id: 'T1598', name: 'Phishing for Information' }],
            query: 'EmailEvents\n' +
              '| where Timestamp > ago(2d)\n' +
              '| where EmailDirection == "Inbound"\n' +
              '| where Subject has_any (' + kqlList(ctx.kw) + ')\n' +
              '| where DeliveryAction == "Delivered"\n' +
              '| summarize Messages = count(), Recipients = dcount(RecipientEmailAddress), Subjects = make_set(Subject, 10)\n' +
              '    by SenderFromDomain, SenderIPv4\n' +
              '| order by Recipients desc',
            next: 'Keywords taken from the headline: ' + ctx.kw.join(', ') + '. Edit them to sharpen the hunt.'
          };
        },
        () => ({
          title: 'Phishing follow-up: who clicked through to a malicious link?',
          hypothesis: 'Campaigns like this succeed when a user clicks. Safe Links clicks that were allowed or clicked through despite a phishing verdict identify the people to protect first.',
          ttps: [{ id: 'T1566.002', name: 'Spearphishing Link' }, { id: 'T1204.001', name: 'Malicious Link' }],
          query: 'UrlClickEvents\n' +
            '| where Timestamp > ago(7d)\n' +
            '| where ActionType == "ClickAllowed" or IsClickedThrough == true\n' +
            '| where ThreatTypes has_any ("Phish", "Malware")\n' +
            '| project Timestamp, AccountUpn, Url, ActionType, IsClickedThrough, ThreatTypes, Workload, NetworkMessageId\n' +
            '| order by Timestamp desc',
          next: 'Reset sessions for the users found, then review their sign-ins after the click time.'
        }),
        () => ({
          title: 'Phishing variant check: QR-code lures delivered to inboxes',
          hypothesis: 'Current phishing campaigns increasingly hide the link in a QR code so it is opened on a personal phone, outside corporate protection.',
          ttps: [{ id: 'T1566.002', name: 'Spearphishing Link' }],
          query: 'EmailUrlInfo\n' +
            '| where Timestamp > ago(7d)\n' +
            '| where UrlLocation == "QRCode"\n' +
            '| join kind=inner (\n' +
            '    EmailEvents\n' +
            '    | where Timestamp > ago(7d)\n' +
            '    | where EmailDirection == "Inbound" and DeliveryAction == "Delivered"\n' +
            '    | project NetworkMessageId, RecipientEmailAddress, Subject\n' +
            '  ) on NetworkMessageId\n' +
            '| summarize Recipients = dcount(RecipientEmailAddress), Subjects = make_set(Subject, 5) by UrlDomain\n' +
            '| order by Recipients desc',
          next: 'Block the top domains and warn the recipients.'
        })
      ]
    },
    {
      id: 'supply-chain',
      match: (a) => has(a, /supply.?chain|\bnpm\b|pypi|package|dependency|malicious update|software update|third.?party/),
      variants: [
        () => ({
          title: 'Supply chain: package managers spawning shells or download tools',
          hypothesis: 'Supply-chain compromises like this one usually execute through install scripts. Package managers launching shells or download tools on our hosts would indicate a poisoned dependency.',
          ttps: [{ id: 'T1195.002', name: 'Compromise Software Supply Chain' }, { id: 'T1059', name: 'Command and Scripting Interpreter' }],
          query: 'DeviceProcessEvents\n' +
            '| where Timestamp > ago(7d)\n' +
            '| where InitiatingProcessFileName in~ ("node.exe", "npm.cmd", "python.exe", "pip.exe", "pip3.exe", "java.exe", "dotnet.exe")\n' +
            '| where FileName in~ ("cmd.exe", "powershell.exe", "pwsh.exe", "curl.exe", "wget.exe", "bitsadmin.exe", "certutil.exe")\n' +
            '| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine\n' +
            '| order by Timestamp desc',
          next: 'Compare the package names and versions named in the article against your lockfiles and SBOMs.'
        }),
        () => ({
          title: 'Supply chain: software updaters launching shells or script hosts',
          hypothesis: 'A trojanised update runs with the updater\'s trust. Updater processes starting cmd, PowerShell or script hosts are rare and worth reviewing after a story like this.',
          ttps: [{ id: 'T1195.002', name: 'Compromise Software Supply Chain' }],
          query: 'DeviceProcessEvents\n' +
            '| where Timestamp > ago(7d)\n' +
            '| where InitiatingProcessFileName contains "update" or InitiatingProcessFileName contains "updater"\n' +
            '| where FileName in~ ("cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe")\n' +
            '| summarize Executions = count(), Commands = make_set(ProcessCommandLine, 10)\n' +
            '    by InitiatingProcessFileName, InitiatingProcessFolderPath, FileName\n' +
            '| order by Executions asc',
          next: 'Rare updater/child pairs (bottom of the list) are the interesting ones.'
        }),
        (a, ctx) => {
          if (!ctx.kw.length) return null;
          return {
            title: 'Supply chain: where does the affected software run? (' + ctx.kw.join(', ') + ')',
            hypothesis: 'Before hunting for compromise, scope exposure: find the devices that run binaries from the vendor or product named in the story.',
            ttps: [{ id: 'T1195', name: 'Supply Chain Compromise' }],
            query: 'DeviceProcessEvents\n' +
              '| where Timestamp > ago(7d)\n' +
              '| where FolderPath has_any (' + kqlList(ctx.kw) + ')\n' +
              '| summarize Devices = dcount(DeviceId), Executions = count() by FileName, FolderPath, SHA256\n' +
              '| order by Devices desc',
            next: 'Keywords taken from the headline: ' + ctx.kw.join(', ') + '. Check the SHA256 values against the vendor\'s list of affected builds.'
          };
        }
      ]
    },
    {
      id: 'social',
      match: (a) => has(a, /scam|social engineering|impersonat|recruiter|job offer|fake job|tech support|callback|vishing|help ?desk|clickfix|fake captcha/),
      variants: [
        () => ({
          title: 'Social engineering: remote access tools launched on our devices',
          hypothesis: 'Tech-support, help-desk and fake-recruiter scams end with the victim installing a remote access tool. New launches of AnyDesk, ScreenConnect or Quick Assist show where a scam may have worked.',
          ttps: [{ id: 'T1219', name: 'Remote Access Software' }, { id: 'T1566.004', name: 'Spearphishing Voice' }],
          query: 'DeviceProcessEvents\n' +
            '| where Timestamp > ago(7d)\n' +
            '| where FileName in~ ("anydesk.exe", "teamviewer.exe", "screenconnect.windowsclient.exe", "quickassist.exe", "rustdesk.exe", "splashtop.exe", "atera_agent.exe")\n' +
            '| summarize Launches = count(), FirstSeen = min(Timestamp), Users = make_set(AccountName, 5)\n' +
            '    by DeviceName, FileName, FolderPath\n' +
            '| order by FirstSeen desc',
          next: 'Ask each user whether they started the session; tools running from Downloads or Temp are the most suspicious.'
        }),
        () => ({
          title: 'Social engineering: files downloaded from social and messaging platforms',
          hypothesis: 'Fake recruiters and impersonators deliver payloads through LinkedIn, Discord, Telegram and file-sharing links. Executables and archives downloaded from those sources deserve a look.',
          ttps: [{ id: 'T1566.003', name: 'Spearphishing via Service' }, { id: 'T1204.002', name: 'Malicious File' }],
          query: 'DeviceFileEvents\n' +
            '| where Timestamp > ago(7d)\n' +
            '| where ActionType == "FileCreated"\n' +
            '| where FileOriginUrl has_any ("linkedin.com", "discord", "telegram", "whatsapp", "dropbox.com", "drive.google.com")\n' +
            '| where FileName endswith ".exe" or FileName endswith ".zip" or FileName endswith ".iso" or FileName endswith ".msi" or FileName endswith ".lnk" or FileName endswith ".js"\n' +
            '| project Timestamp, DeviceName, FileName, FolderPath, FileOriginUrl, SHA256, InitiatingProcessAccountName\n' +
            '| order by Timestamp desc',
          next: 'Check the SHA256 values in VirusTotal from the OSINT tab.'
        })
      ]
    },
    {
      id: 'account',
      match: (a) => has(a, /\bbreach|\bstolen\b|\bsteal(s|ing)?\b|\bcredentials?\b|account takeover|\bpasswords?\b|data theft|\bleak(s|ed)?\b|compromised account|session hijack|token theft/),
      variants: [
        () => ({
          title: 'Account compromise: Microsoft 365 activity from anonymous proxies or unusual locations',
          hypothesis: 'Breaches like this one are often followed by attackers reusing stolen credentials or session tokens. Cloud activity from anonymisers or attributes uncommon for the user points to account takeover.',
          ttps: [{ id: 'T1078.004', name: 'Cloud Accounts' }, { id: 'T1550.004', name: 'Web Session Cookie' }],
          query: 'CloudAppEvents\n' +
            '| where Timestamp > ago(7d)\n' +
            '| where IsAnonymousProxy == true or array_length(UncommonForUser) > 0\n' +
            '| summarize Events = count(), Actions = make_set(ActionType, 10), Countries = make_set(CountryCode, 5), IPs = make_set(IPAddress, 5)\n' +
            '    by AccountDisplayName, AccountObjectId\n' +
            '| order by Events desc',
          next: 'Revoke sessions and reset credentials for accounts with anonymous-proxy activity.'
        }),
        () => ({
          title: 'Data theft: bulk downloads from SharePoint and OneDrive',
          hypothesis: 'Data-theft incidents usually involve one account pulling far more files than normal. A sudden bulk download is the signal to check.',
          ttps: [{ id: 'T1530', name: 'Data from Cloud Storage' }],
          query: 'CloudAppEvents\n' +
            '| where Timestamp > ago(7d)\n' +
            '| where ActionType in ("FileDownloaded", "FileSyncDownloadedFull")\n' +
            '| summarize Files = dcount(ObjectName), IPs = make_set(IPAddress, 5), Countries = make_set(CountryCode, 5)\n' +
            '    by AccountDisplayName, Application, bin(Timestamp, 1h)\n' +
            '| where Files >= 200\n' +
            '| order by Files desc',
          next: 'Departing employees and new sync clients are the usual benign causes - confirm with the user\'s manager.'
        }),
        () => ({
          title: 'Credential attacks: brute force followed by a successful logon',
          hypothesis: 'Stolen or guessed passwords show up as a burst of failures followed by a success from the same source.',
          ttps: [{ id: 'T1110', name: 'Brute Force' }],
          query: 'DeviceLogonEvents\n' +
            '| where Timestamp > ago(1d)\n' +
            '| summarize Failures = countif(ActionType == "LogonFailed"), Successes = countif(ActionType == "LogonSuccess"),\n' +
            '            Accounts = make_set(AccountName, 10)\n' +
            '    by RemoteIP, DeviceName\n' +
            '| where Failures >= 20 and Successes > 0\n' +
            '| order by Failures desc',
          next: 'Block the source IPs and reset the affected accounts.'
        })
      ]
    },
    {
      id: 'apt',
      match: (a) => hasTag(a, 'APT') || has(a, /state.?sponsored|nation.?state|espionage|\bapt\b|backdoor/),
      variants: [
        (a, ctx) => ({
          title: named(ctx, 'APT activity') + ': rare outbound destinations that could be stealthy C2',
          hypothesis: 'Targeted actors like the one reported favour low-volume C2 to destinations almost no other host contacts. Domains reached by only one or two devices but contacted repeatedly deserve review.',
          ttps: [{ id: 'T1071.001', name: 'Web Protocols' }, { id: 'T1573', name: 'Encrypted Channel' }],
          query: 'DeviceNetworkEvents\n' +
            '| where Timestamp > ago(7d)\n' +
            '| where RemoteIPType == "Public" and isnotempty(RemoteUrl)\n' +
            '| summarize Devices = dcount(DeviceId), Connections = count(), DeviceNames = make_set(DeviceName, 5),\n' +
            '            Processes = make_set(InitiatingProcessFileName, 5)\n' +
            '    by RemoteUrl\n' +
            '| where Devices <= 2 and Connections >= 20\n' +
            '| order by Connections desc',
          next: 'Look up the top destinations in the OSINT tab (paste each into the indicator box).'
        }),
        (a, ctx) => ({
          title: named(ctx, 'APT activity') + ': hands-on-keyboard discovery bursts',
          hypothesis: 'Once inside, operators run the same discovery commands (whoami, net, nltest, systeminfo) in quick succession. Several different tools from one account within minutes is a strong signal.',
          ttps: [{ id: 'T1087', name: 'Account Discovery' }, { id: 'T1082', name: 'System Information Discovery' }],
          query: 'DeviceProcessEvents\n' +
            '| where Timestamp > ago(7d)\n' +
            '| where FileName in~ ("whoami.exe", "net.exe", "net1.exe", "nltest.exe", "ipconfig.exe", "systeminfo.exe", "tasklist.exe", "quser.exe", "dsquery.exe", "adfind.exe")\n' +
            '| summarize Tools = dcount(FileName), ToolList = make_set(FileName, 20) by DeviceName, AccountName, bin(Timestamp, 10m)\n' +
            '| where Tools >= 5\n' +
            '| order by Tools desc',
          next: 'Check the parent process of the burst - Office, w3wp or an unknown binary is a red flag.'
        }),
        (a, ctx) => ({
          title: named(ctx, 'APT activity') + ': remote execution via WMI or PsExec',
          hypothesis: 'Advanced actors move laterally with built-in remote execution (WMI, service-based PsExec clones). Shells started by these mechanisms show where they went next.',
          ttps: [{ id: 'T1047', name: 'Windows Management Instrumentation' }, { id: 'T1569.002', name: 'Service Execution' }],
          query: 'DeviceProcessEvents\n' +
            '| where Timestamp > ago(7d)\n' +
            '| where InitiatingProcessFileName in~ ("wmiprvse.exe", "psexesvc.exe", "paexec.exe", "remcomsvc.exe")\n' +
            '| where FileName in~ ("cmd.exe", "powershell.exe", "pwsh.exe", "rundll32.exe", "mshta.exe")\n' +
            '| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine\n' +
            '| order by Timestamp desc',
          next: 'Map each hit to its source host with DeviceLogonEvents (Network logons just before).'
        }),
        (a, ctx) => ({
          title: named(ctx, 'APT activity') + ': Active Directory reconnaissance (SPN and admin-group queries)',
          hypothesis: 'Espionage actors map Active Directory early - service accounts for Kerberoasting and privileged groups to target. Defender for Identity sees these queries.',
          ttps: [{ id: 'T1087.002', name: 'Domain Account Discovery' }, { id: 'T1558.003', name: 'Kerberoasting' }],
          query: 'IdentityQueryEvents\n' +
            '| where Timestamp > ago(7d)\n' +
            '| where Query contains "servicePrincipalName" or QueryTarget has_any ("Domain Admins", "Enterprise Admins")\n' +
            '| summarize Queries = count(), Targets = make_set(QueryTarget, 10) by AccountUpn, DeviceName\n' +
            '| order by Queries desc',
          next: 'Allow-list known management tools; anything else querying admin groups needs an owner.'
        })
      ]
    },
    {
      id: 'malware',
      match: (a) => hasTag(a, 'Malware') || has(a, /malware|stealer|trojan|loader|botnet|\brat\b|wiper|spyware/),
      variants: [
        (a, ctx) => ({
          title: named(ctx, 'malware') + ': LOLBins pulling payloads from the internet',
          hypothesis: 'Loaders and stealers like the one described commonly use built-in Windows binaries to fetch their payloads. LOLBin downloads are a high-signal place to catch the initial stage.',
          ttps: [{ id: 'T1105', name: 'Ingress Tool Transfer' }, { id: 'T1218', name: 'System Binary Proxy Execution' }],
          query: 'DeviceProcessEvents\n' +
            '| where Timestamp > ago(7d)\n' +
            '| where FileName in~ ("certutil.exe", "bitsadmin.exe", "mshta.exe", "regsvr32.exe", "rundll32.exe", "msiexec.exe")\n' +
            '| where ProcessCommandLine has_any ("http", "urlcache", "transfer")\n' +
            '| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName\n' +
            '| order by Timestamp desc',
          next: 'Extract hashes/domains from the article in the IOC tab and pivot on them in VirusTotal or ThreatFox.'
        }),
        (a, ctx) => ({
          title: named(ctx, 'malware') + ': executables dropped in user folders and run within an hour',
          hypothesis: 'Malware delivered by download or attachment is written to Downloads, AppData or Temp and executed shortly after. Matching file creation to execution by hash finds it.',
          ttps: [{ id: 'T1204.002', name: 'Malicious File' }],
          query: 'let Dropped = DeviceFileEvents\n' +
            '    | where Timestamp > ago(7d)\n' +
            '    | where ActionType == "FileCreated" and FileName endswith ".exe"\n' +
            '    | where FolderPath has_any ("Downloads", "AppData", "Temp", "Public")\n' +
            '    | project DropTime = Timestamp, DeviceId, SHA256, DroppedPath = FolderPath, DroppedBy = InitiatingProcessFileName;\n' +
            'DeviceProcessEvents\n' +
            '| where Timestamp > ago(7d)\n' +
            '| join kind=inner Dropped on DeviceId, SHA256\n' +
            '| where Timestamp between (DropTime .. (DropTime + 1h))\n' +
            '| project Timestamp, DeviceName, AccountName, FileName, DroppedPath, DroppedBy, ProcessCommandLine\n' +
            '| order by Timestamp desc',
          next: 'Look up the SHA256 values in the OSINT tab; unsigned binaries from browsers or Outlook are the priority.'
        }),
        (a, ctx) => ({
          title: named(ctx, 'malware') + ': non-browser processes talking to Telegram, Discord or paste sites',
          hypothesis: 'Infostealers and RATs often exfiltrate or receive commands through Telegram bots, Discord webhooks or paste sites. Non-browser processes contacting them are suspicious.',
          ttps: [{ id: 'T1102', name: 'Web Service' }, { id: 'T1567', name: 'Exfiltration Over Web Service' }],
          query: 'DeviceNetworkEvents\n' +
            '| where Timestamp > ago(7d)\n' +
            '| where RemoteUrl has_any ("api.telegram.org", "discord.com", "discordapp.com", "pastebin.com")\n' +
            '| where InitiatingProcessFileName !in~ ("chrome.exe", "msedge.exe", "firefox.exe", "brave.exe", "opera.exe", "telegram.exe", "discord.exe", "update.exe")\n' +
            '| summarize Connections = count(), Urls = make_set(RemoteUrl, 10) by DeviceName, InitiatingProcessFileName, InitiatingProcessFolderPath\n' +
            '| order by Connections desc',
          next: 'Processes running from AppData or Temp in this list should be isolated and analysed.'
        }),
        (a, ctx) => ({
          title: named(ctx, 'malware') + ': new Run-key persistence pointing to user folders',
          hypothesis: 'Commodity malware persists through Run keys that launch a binary or script from a user-writable folder.',
          ttps: [{ id: 'T1547.001', name: 'Registry Run Keys / Startup Folder' }],
          query: 'DeviceRegistryEvents\n' +
            '| where Timestamp > ago(7d)\n' +
            '| where ActionType == "RegistryValueSet"\n' +
            '| where RegistryKey contains @"\\CurrentVersion\\Run"\n' +
            '| where RegistryValueData has_any ("AppData", "Temp", "Public", "ProgramData", "powershell", "mshta", "rundll32")\n' +
            '| project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName\n' +
            '| order by Timestamp desc',
          next: 'Compare value names across devices - the same odd name on several machines points to a campaign.'
        })
      ]
    },
    {
      id: 'vuln',
      match: (a) => hasTag(a, 'Vulnerability') || hasTag(a, 'Zero-Day') || has(a, /vulnerab|flaw|zero.?day|exploit|\bbug\b|\brce\b|patch/),
      variants: [
        (a, ctx) => {
          if (!ctx.kw.length) return null;
          return {
            title: 'Exposure check: vulnerable software from the vendor or product in this story (' + ctx.kw.join(', ') + ')',
            hypothesis: 'The story describes a flaw being fixed or exploited. Matching the vendor and product names from the headline against vulnerability data shows where we are exposed.',
            ttps: [{ id: 'T1190', name: 'Exploit Public-Facing Application' }, { id: 'T1203', name: 'Exploitation for Client Execution' }],
            query: 'DeviceTvmSoftwareVulnerabilities\n' +
              '| where SoftwareVendor has_any (' + kqlList(ctx.kw) + ') or SoftwareName has_any (' + kqlList(ctx.kw) + ')\n' +
              '| summarize Devices = dcount(DeviceId), CVEs = make_set(CveId, 20)\n' +
              '    by SoftwareVendor, SoftwareName, SoftwareVersion, VulnerabilitySeverityLevel\n' +
              '| order by Devices desc',
            next: 'Keywords taken from the headline: ' + ctx.kw.join(', ') + '. Narrow to the CVE once the advisory is published.'
          };
        },
        () => ({
          title: 'Exploitation aftermath: web servers spawning shells or recon tools',
          hypothesis: 'Successful exploitation of internet-facing software usually ends with the server process running commands. Web server workers starting shells are a reliable post-exploitation signal.',
          ttps: [{ id: 'T1190', name: 'Exploit Public-Facing Application' }, { id: 'T1505.003', name: 'Web Shell' }],
          query: 'DeviceProcessEvents\n' +
            '| where Timestamp > ago(7d)\n' +
            '| where InitiatingProcessFileName in~ ("w3wp.exe", "httpd.exe", "nginx.exe", "tomcat9.exe", "php-cgi.exe", "UMWorkerProcess.exe", "java.exe")\n' +
            '| where FileName in~ ("cmd.exe", "powershell.exe", "pwsh.exe", "whoami.exe", "net.exe", "certutil.exe", "nltest.exe")\n' +
            '| project Timestamp, DeviceName, InitiatingProcessFileName, FileName, ProcessCommandLine, AccountName\n' +
            '| order by Timestamp desc',
          next: 'Java application servers can be noisy - review command lines before escalating.'
        }),
        (a, ctx) => {
          if (!ctx.kw.length) return null;
          return {
            title: 'Exposure check: where does the affected product run? (' + ctx.kw.join(', ') + ')',
            hypothesis: 'Vulnerability data can lag behind a disclosure. Process telemetry shows today which devices actually run the product named in the story.',
            ttps: [{ id: 'T1190', name: 'Exploit Public-Facing Application' }],
            query: 'DeviceProcessEvents\n' +
              '| where Timestamp > ago(7d)\n' +
              '| where FolderPath has_any (' + kqlList(ctx.kw) + ') or FileName has_any (' + kqlList(ctx.kw) + ')\n' +
              '| summarize Devices = dcount(DeviceId), DeviceNames = make_set(DeviceName, 20) by FileName, FolderPath\n' +
              '| order by Devices desc',
            next: 'Keywords taken from the headline: ' + ctx.kw.join(', ') + '. Prioritise internet-facing devices (DeviceInfo.IsInternetFacing).'
          };
        }
      ]
    },
    {
      id: 'exfil',
      match: () => true,
      variants: [
        () => ({
          title: 'Opportunistic data movement to personal cloud storage',
          hypothesis: 'High-profile incidents pull defender attention. Insiders or intruders may use that window to move data to personal cloud storage.',
          ttps: [{ id: 'T1567.002', name: 'Exfiltration to Cloud Storage' }],
          query: 'DeviceNetworkEvents\n' +
            '| where Timestamp > ago(2d)\n' +
            '| where RemoteUrl has_any (' + kqlList(['dropbox.com', 'drive.google.com', 'mega.nz', 'wetransfer.com', 'onedrive.live.com']) + ')\n' +
            '| summarize Connections = count(), Destinations = make_set(RemoteUrl, 10)\n' +
            '    by DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName\n' +
            '| order by Connections desc',
          next: 'Endpoint events have no byte counts - confirm volume with proxy logs (see "Large Upload to Cloud Storage").'
        }),
        () => ({
          title: 'Data staging: password-protected archives created',
          hypothesis: 'Data is usually packed into encrypted archives before it leaves. Password-protected 7-Zip or RAR archives on workstations are uncommon.',
          ttps: [{ id: 'T1560.001', name: 'Archive via Utility' }],
          query: 'DeviceProcessEvents\n' +
            '| where Timestamp > ago(7d)\n' +
            '| where FileName in~ ("7z.exe", "7za.exe", "rar.exe", "winrar.exe")\n' +
            '| where ProcessCommandLine matches regex @"(?i)\\s-(h)?p\\S+"\n' +
            '| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName\n' +
            '| order by Timestamp desc',
          next: 'Look at where the archive was written - PerfLogs, ProgramData or web roots are classic staging folders.'
        }),
        () => ({
          title: 'Removable media: USB drives mounted this week',
          hypothesis: 'Insiders take advantage of busy periods to copy data to USB drives. A device or user mounting drives far more than peers stands out.',
          ttps: [{ id: 'T1052.001', name: 'Exfiltration over USB' }],
          query: 'DeviceEvents\n' +
            '| where Timestamp > ago(7d)\n' +
            '| where ActionType == "UsbDriveMounted"\n' +
            '| extend Details = parse_json(AdditionalFields)\n' +
            '| summarize Mounts = count(), Drives = make_set(tostring(Details.ProductName), 5) by DeviceName, InitiatingProcessAccountName\n' +
            '| order by Mounts desc',
          next: 'Pair with DeviceFileEvents on the same device to see what was copied.'
        })
      ]
    }
  ];

  /** Query text without comment lines - used to detect duplicates. */
  const queryBody = (q) => q.split('\n').filter((l) => !l.trim().startsWith('//')).join('\n').trim();

  /**
   * Build up to `limit` hypotheses from articles (most recent first).
   * Each result: { rule, title, hypothesis, ttps, query, next, article }.
   * No two results share the same query; repeated rules rotate through variants.
   */
  function buildHypotheses(articles, limit) {
    const max = limit || 10;
    const out = [];
    const usedQueries = new Set();
    const ruleUse = {};
    for (const article of articles || []) {
      if (out.length >= max) break;
      const a = Object.assign({ title: '', description: '', tags: [] }, article);
      const ctx = { iocs: articleIOCs(a), name: threatName(a.title), kw: keywords(a.title, 4) };
      // Try every matching rule in priority order (the fallback always matches),
      // and within a rule start from its next unused variant.
      let built = null;
      let ruleId = null;
      for (const rule of RULES.filter((r) => r.match(a, ctx.iocs))) {
        const start = ruleUse[rule.id] || 0;
        for (let i = 0; i < rule.variants.length && !built; i++) {
          const candidate = rule.variants[(start + i) % rule.variants.length](a, ctx);
          if (candidate && !usedQueries.has(queryBody(candidate.query))) {
            built = candidate;
            ruleId = rule.id;
            ruleUse[rule.id] = start + i + 1;
          }
        }
        if (built) break;
      }
      if (!built) continue; // every applicable hunt was already shown for an earlier article
      usedQueries.add(queryBody(built.query));
      built.query = '// Hypothesis: ' + built.title + '\n// Source: ' + (a.source || 'news feed') + ', ' + dateLabel(a) +
        '\n// Platform: Microsoft Defender XDR advanced hunting (KQL)\n' + built.query;
      out.push(Object.assign({ rule: ruleId, article: a }, built));
    }
    return out;
  }

  return { buildHypotheses, kqlList, keywords, threatName };
});
