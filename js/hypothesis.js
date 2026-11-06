/*
 * Rule-based hunt hypothesis builder.
 *
 * Not an AI model: each article is matched against rules (CVEs mentioned,
 * defanged IOCs present, ransomware, phishing, supply chain, APT, malware) and
 * the best match produces a hypothesis plus a Defender XDR advanced hunting
 * query built from the article's own content (CVE IDs, IOCs, subject keywords).
 * Generated queries are type-checked in tests/hypothesis.test.js.
 */
(function (root, factory) {
  const deps = typeof module === 'object' && module.exports ? require('./ioc.js') : root.THQV;
  const api = factory(deps);
  if (typeof module === 'object' && module.exports) module.exports = api;
  else root.THQV = Object.assign(root.THQV || {}, api);
})(typeof self !== 'undefined' ? self : this, function (ioc) {
  'use strict';

  const STOPWORDS = new Set((
    'about after again against also amid among analysis attack attacks being campaign could critical cyber data ' +
    'details discloses exploited exploit exploits flaw flaws from have hackers hacker into just more news over ' +
    'patch patched patches report reports researchers says security since some still than that their them then ' +
    'there these they this threat threats under used users using warns week what when where which while with ' +
    'your year years million new now how why who has had was were will its it’s 2023 2024 2025 2026'
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

  const RULES = [
    {
      id: 'cve',
      match: (a, x) => x.cves.length > 0,
      build: (a, x) => ({
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
    },
    {
      id: 'ioc',
      match: (a, x) => x.ips.length + x.domains.length > 0,
      build: (a, x) => {
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
    },
    {
      id: 'ransomware',
      match: (a) => (a.tags || []).some((t) => t.name === 'Ransomware') || has(a, /ransom/),
      build: () => ({
        title: 'Look for ransomware staging: recovery inhibition and mass file renames',
        hypothesis: 'Ransomware operators covered here typically delete shadow copies and rename large numbers of files minutes before impact. Catching the staging step buys response time.',
        ttps: [{ id: 'T1490', name: 'Inhibit System Recovery' }, { id: 'T1486', name: 'Data Encrypted for Impact' }],
        query: 'DeviceFileEvents\n' +
          '| where Timestamp > ago(1d)\n' +
          '| where ActionType == "FileRenamed"\n' +
          '| extend Extension = tostring(split(FileName, ".")[-1])\n' +
          '| summarize Renamed = count(), Extensions = make_set(Extension, 10), Folders = dcount(FolderPath)\n' +
          '    by DeviceName, InitiatingProcessFileName, InitiatingProcessAccountName, bin(Timestamp, 5m)\n' +
          '| where Renamed > 200\n' +
          '| order by Renamed desc',
        next: 'Pair with the "Ransomware Precursor - Shadow Copy / Recovery Deletion" query in the Detection Queries tab (Defender XDR > Impact).'
      })
    },
    {
      id: 'phishing',
      match: (a) => (a.tags || []).some((t) => t.name === 'Phishing') || has(a, /phish|lure|credential harvest|business email compromise|\bbec\b/),
      build: (a) => {
        const words = keywords(a.title, 4);
        const subject = words.length ? '| where Subject has_any (' + kqlList(words) + ')\n' : '';
        return {
          title: 'Hunt for inbound email themed on this story',
          hypothesis: 'Attackers turn breaking security news into lures within 24-48 hours. Delivered messages with subjects matching this story are candidates for credential-harvesting or malware delivery.',
          ttps: [{ id: 'T1566', name: 'Phishing' }, { id: 'T1598', name: 'Phishing for Information' }],
          query: 'EmailEvents\n' +
            '| where Timestamp > ago(2d)\n' +
            '| where EmailDirection == "Inbound"\n' +
            subject +
            '| where DeliveryAction == "Delivered"\n' +
            '| summarize Messages = count(), Recipients = dcount(RecipientEmailAddress), Subjects = make_set(Subject, 10)\n' +
            '    by SenderFromDomain, SenderIPv4\n' +
            '| order by Recipients desc',
          next: words.length ? 'Keywords taken from the headline: ' + words.join(', ') + '. Edit them to sharpen the hunt.' : 'Add subject keywords for this story before running.'
        };
      }
    },
    {
      id: 'supply-chain',
      match: (a) => has(a, /supply.?chain|\bnpm\b|pypi|package|dependency|malicious update|software update|third.?party/),
      build: () => ({
        title: 'Check developer and build hosts for package managers spawning shells',
        hypothesis: 'Supply-chain compromises like this one usually execute through install scripts. Package managers launching shells or download tools on our hosts would indicate a poisoned dependency.',
        ttps: [{ id: 'T1195.002', name: 'Compromise Software Supply Chain' }, { id: 'T1059', name: 'Command and Scripting Interpreter' }],
        query: 'DeviceProcessEvents\n' +
          '| where Timestamp > ago(7d)\n' +
          '| where InitiatingProcessFileName in~ ("node.exe", "npm.cmd", "python.exe", "pip.exe", "pip3.exe", "java.exe", "dotnet.exe")\n' +
          '| where FileName in~ ("cmd.exe", "powershell.exe", "pwsh.exe", "curl.exe", "wget.exe", "bitsadmin.exe", "certutil.exe")\n' +
          '| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine\n' +
          '| order by Timestamp desc',
        next: 'Compare the package names and versions named in the article against your lockfiles and SBOMs.'
      })
    },
    {
      id: 'apt',
      match: (a) => (a.tags || []).some((t) => t.name === 'APT') || has(a, /state.?sponsored|nation.?state|espionage|\bapt\b|backdoor/),
      build: () => ({
        title: 'Hunt for rare outbound destinations that could be stealthy C2',
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
      })
    },
    {
      id: 'malware',
      match: (a) => (a.tags || []).some((t) => t.name === 'Malware') || has(a, /malware|stealer|trojan|loader|botnet|\brat\b/),
      build: () => ({
        title: 'Hunt for the delivery stage: LOLBins pulling payloads from the internet',
        hypothesis: 'Loaders and stealers like the one described commonly use built-in Windows binaries to fetch their payloads. LOLBin downloads are a high-signal place to catch the initial stage.',
        ttps: [{ id: 'T1105', name: 'Ingress Tool Transfer' }, { id: 'T1218', name: 'System Binary Proxy Execution' }],
        query: 'DeviceProcessEvents\n' +
          '| where Timestamp > ago(7d)\n' +
          '| where FileName in~ ("certutil.exe", "bitsadmin.exe", "mshta.exe", "regsvr32.exe", "rundll32.exe", "msiexec.exe")\n' +
          '| where ProcessCommandLine has_any ("http", "urlcache", "transfer")\n' +
          '| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName\n' +
          '| order by Timestamp desc',
        next: 'Extract hashes/domains from the article in the IOC tab and pivot on them in VirusTotal or ThreatFox.'
      })
    },
    {
      id: 'exfil',
      match: () => true,
      build: () => ({
        title: 'Check for opportunistic data movement to personal cloud storage',
        hypothesis: 'High-profile incidents pull defender attention. Insiders or intruders may use that window to move data to personal cloud storage.',
        ttps: [{ id: 'T1567.002', name: 'Exfiltration to Cloud Storage' }],
        query: 'DeviceNetworkEvents\n' +
          '| where Timestamp > ago(2d)\n' +
          '| where RemoteUrl has_any (' + kqlList(['dropbox.com', 'drive.google.com', 'mega.nz', 'wetransfer.com', 'onedrive.live.com']) + ')\n' +
          '| summarize Connections = count(), Destinations = make_set(RemoteUrl, 10)\n' +
          '    by DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName\n' +
          '| order by Connections desc',
        next: 'Endpoint events have no byte counts - confirm volume with proxy logs (see "Large Upload to Cloud Storage").'
      })
    }
  ];

  /**
   * Build up to `limit` hypotheses from articles (most recent first).
   * Each result: { rule, title, hypothesis, ttps, query, next, article }.
   */
  function buildHypotheses(articles, limit) {
    const max = limit || 10;
    const out = [];
    for (const article of articles || []) {
      if (out.length >= max) break;
      const a = Object.assign({ title: '', description: '', tags: [] }, article);
      const iocs = articleIOCs(a);
      const rule = RULES.find((r) => r.match(a, iocs));
      const built = rule.build(a, iocs);
      built.query = '// Hypothesis: ' + built.title + '\n// Source: ' + (a.source || 'news feed') + ', ' + dateLabel(a) +
        '\n// Platform: Microsoft Defender XDR advanced hunting (KQL)\n' + built.query;
      out.push(Object.assign({ rule: rule.id, article: a }, built));
    }
    return out;
  }

  return { buildHypotheses, kqlList, keywords };
});
