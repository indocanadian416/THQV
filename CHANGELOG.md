# Changelog

## 2.1.0 - 2026-11-06

### Added
- **43 new hunting queries (66 total)**: Entra ID (legacy auth, multi-country sign-ins, privileged role assignment, MFA method changes, OAuth consent), Microsoft 365 (BEC inbox rules, mass SharePoint downloads), Azure (mass deletion), Windows Security (brute force then success, privileged group changes, malicious services, short-lived accounts, log clearing), Defender XDR (LSASS handle access, web shells, WMI/PsExec lateral movement, recon bursts, quishing, risky clicks, alert-chain triage) and 15 CrowdStrike LogScale hunts.
- **Table Reference tab**: 19 Defender XDR tables and 11 CrowdStrike Falcon events with key fields, ActionTypes, sample records, starter queries and links to related library queries.
- Full-text search across the query library.
- "Which table to use for what" guide on the Detection Queries page: Microsoft Defender XDR tables and CrowdStrike Falcon `#event_simpleName` events by category, each linked to the query search.
- Test schemas for 12 more tables from Microsoft Learn; tests that check every reference column against them.

### Fixed
- Optional page sections could render as the text "null" (metrics panel, reference view); now covered by a browser test.

## 2.0.0 - 2026-11-06

A full review-and-fix release. Highlights below; see the commit history for detail.

### Security
- Feed titles, descriptions and links can no longer inject script (all untrusted data rendered as text, links limited to http/https).
- Strict Content-Security-Policy; all inline JavaScript and styles removed.
- Font Awesome upgraded from a 6.0 beta to 6.5.2 with Subresource Integrity.
- OSINT tabs open with `noopener noreferrer`.

### Fixed
- Clicking a tab's icon broke tab highlighting; tabs are now accessible (ARIA, arrow keys, `#hash` links).
- Feed dates from rss2json were read as local time (or rejected in Safari); now parsed as UTC.
- Feed failures showed "No articles found"; now the failed sources are named, requests are retried, and a 15-minute cache is used as fallback.
- Query stats tiles were hard-coded and wrong (said 5 categories); now computed.
- Detection queries that would not run or could never match: wrong MFA result codes, non-existent columns (`BytesSent`, `TicketEncryptionType`), `project` after `summarize`, invented `DeviceEvents` action types, and CrowdStrike queries mixing SPL and LogScale syntax.
- IOC extractor missed `[dot]`/`(.)`/`[at]` defanging, reported `report.docx` as a domain and email addresses as domains, and exported broken CSV.

### Added
- IPv6, email and CVE extraction; MD5/SHA-1/SHA-256/SHA-512 labelling; defanged export option; CSV formula-injection protection.
- Indicator pivoting in the OSINT keyboard (direct lookups for 17 of 26 tools).
- Kerberoasting (4769), DCSync (4662 and Defender for Identity), ransomware recovery-inhibition and SPN-enumeration hunts; each query lists its data source.
- Rule-based hypothesis builder that generates validated KQL from each article's CVEs, IOCs and keywords.
- Active Threats and Feed Metrics computed from the last 7 days of feeds.
- Test suite: 49 unit tests (every KQL query parsed and type-checked with Microsoft's Kusto parser) and 9 browser end-to-end tests; GitHub Actions CI; Dependabot.
- MIT LICENSE, SECURITY.md, CONTRIBUTING.md, issue/PR templates, screenshots, favicon.

### Changed
- Code split from one minified file into readable modules under `css/` and `js/`.
- "AI Hypothesis" renamed to "Hunt Hypotheses" and labelled rule-based, because it is not an AI model.
- BGPView (shut down) replaced with Hurricane Electric's BGP Toolkit.

## 1.x - 2025
Initial versions: threat intel feed, hypothesis templates, A-Z OSINT keyboard, IOC extractor, query library.
