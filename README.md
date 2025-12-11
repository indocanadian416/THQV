# THQV 🐊 - Threat Hunting Command Center

**The Ultimate Threat Hunting Query Viewer & Intelligence Platform**

THQV (Threat Hunting Query Viewer) is a comprehensive, all-in-one threat hunting command center that combines multi-platform detection query generation, AI-powered hypothesis creation, live threat intelligence aggregation, OSINT tool integration, IOC extraction, and query translation capabilities.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Platform](https://img.shields.io/badge/platform-web-green.svg)
![Status](https://img.shields.io/badge/status-production-success.svg)

## 🚀 Features Overview

### 1. **Multi-Platform Detection Query Builder** 🔍
- **14 MITRE ATT&CK techniques** with ready-to-deploy detection queries
- **5 SIEM/EDR platforms** supported:
  - Microsoft Sentinel (KQL)
  - Splunk (SPL)
  - CrowdStrike Falcon (CQL)
  - Elastic SIEM (Lucene)
  - Wazuh SIEM
- **70+ detection queries** across all techniques and platforms
- **One-click copy** to clipboard
- **Export functionality** for documentation
- **Query library** to save and reuse custom queries

### 2. **AI-Powered Threat Hunting Hypothesis Generator** 🧠
- **Automated hypothesis generation** based on current threat intelligence
- **Creative hunting strategies** with context and TTPs
- **News-driven hunting** - hypotheses linked to real-world threats
- **MITRE ATT&CK mapping** for each hypothesis
- **Actionable detection guidance** with specific query suggestions
- **Unconventional insights** for proactive threat hunting

### 3. **Live Threat Intelligence Feed** 🌐
- **10+ RSS feeds** from trusted cybersecurity sources
- **Auto-tagging system** (Ransomware, Zero-Day, APT, Phishing, Malware, Exploit)
- **Time-based filtering** (Today, 24h, 7d, All)
- **Keyword search** across all articles
- **Severity indicators** (Critical, High, Medium, Low)
- **Real-time updates** with latest threat landscape

### 4. **OSINT Keyboard Shortcuts** ⌨️
- **26 OSINT tools** mapped to A-Z keys
- **Instant access** - press any key or click
- **Comprehensive coverage**:
  - IP reputation (AbuseIPDB, GreyNoise, IPinfo)
  - Domain intel (WHOIS, DNSTrails, IPVoid)
  - Threat platforms (VirusTotal, AlienVault, Talos)
  - Sandboxes (Hybrid Analysis, JoeSandbox, YARAify)
  - Search engines (Shodan, Censys, ZoomEye, Fofa)
- **Visual keyboard interface** with color-coded categories
- **Perfect for rapid IOC investigation**

### 5. **IOC Extractor** 🔎
- **Automatic extraction** from threat intelligence text
- **Regex-based detection** for:
  - IPv4 addresses
  - Domains
  - URLs (HTTP/HTTPS)
  - File hashes (MD5, SHA1, SHA256)
- **Deduplication** of extracted IOCs
- **Multiple export formats**:
  - TXT (organized by type)
  - JSON (structured data)
  - CSV (spreadsheet-ready)
- **Real-time extraction** as you paste

### 6. **Query Translator** 🔄
- **Multi-platform query conversion**
- **Supported platforms**:
  - Microsoft Sentinel (KQL)
  - Splunk (SPL)
  - Elastic (Lucene)
- **Syntax transformation** for cross-platform compatibility
- **One-click translation** between query languages
- **Copy translated queries** directly to clipboard

## 📊 MITRE ATT&CK Coverage

THQV provides detection queries for these critical MITRE ATT&CK techniques:

| Technique ID | Name | Platforms |
|-------------|------|----------|
| **T1059** | Command and Scripting Interpreter | 5 |
| **T1566** | Phishing | 4 |
| **T1021** | Remote Services | 3 |
| **T1041** | Exfiltration Over C2 Channel | 2 |
| **T1105** | Remote File Copy | 2 |
| **T1547** | Boot or Logon Autostart Execution | 2 |
| **T1071** | Application Layer Protocol | 2 |
| **T1110** | Brute Force | 3 |
| **T1055** | Process Injection | 2 |
| **T1621** | Multi-Factor Authentication Fatigue | 2 |
| **T1003** | Credential Dumping | 3 |
| **T1078** | Valid Accounts | 2 |
| **T1486** | Data Encrypted for Impact | 2 |
| **T1567** | Exfiltration Over Web Service | 2 |

## 🛠️ Installation

### Option 1: GitHub Pages (Recommended)
Visit the live deployment:
```
https://indocanadian416.github.io/THQV/
```

### Option 2: Local Deployment
```bash
# Clone the repository
git clone https://github.com/indocanadian416/THQV.git

# Navigate to directory
cd THQV

# Open in browser
open index.html
```

### Option 3: Web Server
```bash
# Using Python
python -m http.server 8000

# Using Node.js
npx http-server

# Then navigate to http://localhost:8000
```

## 📖 Usage Guide

### Detection Query Builder
1. Select a MITRE ATT&CK technique from dropdown
2. Review detection queries for all supported platforms
3. Copy query to clipboard or export as TXT
4. Save frequently-used queries to library
5. Deploy queries in your SIEM/EDR platform

### AI Hypothesis Generator
1. Click "Generate Hunting Hypotheses" button
2. Wait for AI to analyze current threat intelligence
3. Review 10 generated hunting hypotheses
4. Each hypothesis includes:
   - **Threat context**: Why hunt for this now?
   - **TTPs**: MITRE ATT&CK techniques involved
   - **Search guidance**: What to look for
   - **Detection strategy**: How to find it
5. Implement hypotheses in your hunting program

### Threat Intelligence Feed
1. Auto-loads on page visit
2. Use filters to scope by time (Today, 24h, 7d)
3. Search by keywords (e.g., "ransomware", "CVE")
4. Click tags to see threat categories
5. Open articles for full context
6. Use articles as input for hypothesis generation

### OSINT Keyboard
1. Navigate to OSINT Tools tab
2. Press any letter (A-Z) to open that tool
3. Or click on visual keyboard buttons
4. Tools open in new tab for investigation
5. Perfect workflow:
   - Extract IOCs from threat intel
   - Press V for VirusTotal
   - Press S for Shodan
   - Press G for GreyNoise

### IOC Extractor
1. Paste threat intelligence text into input box
2. Click "Extract IOCs" button
3. Review extracted IPs, domains, URLs, hashes
4. Export in desired format (TXT, JSON, CSV)
5. Use exported IOCs for:
   - SIEM queries
   - Blocklist updates
   - OSINT investigation
   - Threat hunting campaigns

### Query Translator
1. Select source platform (e.g., KQL)
2. Select target platform (e.g., SPL)
3. Paste your query in source field
4. Click "Translate Query"
5. Copy translated query for use in target platform
6. Note: May require manual adjustment for complex queries

## 🎯 Use Cases

### For SOC Analysts
- **Daily hunting**: Generate fresh hypotheses from overnight threat intel
- **Alert triage**: Use detection queries to investigate suspicious activity
- **IOC investigation**: Extract and pivot on indicators across OSINT tools
- **Multi-platform ops**: Translate queries when working across different SIEMs

### For Threat Hunters
- **Proactive hunting**: AI-generated hypotheses for unexplored threat vectors
- **News-driven hunting**: React to breaking threats with immediate detection ideas
- **Query library**: Build and maintain hunting query collections
- **MITRE coverage**: Ensure comprehensive ATT&CK technique coverage

### For Threat Intel Analysts
- **Feed aggregation**: Centralized view of major security news sources
- **IOC extraction**: Rapidly pull indicators from reports and articles
- **Threat tagging**: Auto-categorize threats by type and severity
- **Intelligence sharing**: Export IOCs and queries for team distribution

### For Security Researchers
- **Trend analysis**: Monitor threat landscape through tagged articles
- **Hypothesis testing**: Generate testable hunting theories from real threats
- **Tool discovery**: Access 26 OSINT platforms in one interface
- **Cross-platform research**: Translate queries to test across environments

### For Incident Responders
- **Rapid IOC lookup**: Keyboard shortcuts for instant OSINT access
- **Query deployment**: Ready-to-use detection queries for common threats
- **Context gathering**: Live threat feeds for incident background
- **Evidence extraction**: Pull IOCs from incident reports and logs

## 🔧 Technical Architecture

### Frontend Technologies
- **Pure HTML/CSS/JavaScript** - no dependencies
- **Responsive design** - works on desktop, tablet, mobile
- **Dark theme** optimized for extended monitoring
- **Font Awesome** for icons

### Data Sources
- **RSS feeds** via AllOrigins CORS proxy
- **10 cybersecurity news sources**
- **Client-side processing** for privacy
- **Session storage** for caching

### Detection Query Database
- **70+ queries** across 14 MITRE techniques
- **5 platform syntaxes** (KQL, SPL, CQL, Lucene, Wazuh)
- **Continuously updated** with new techniques

### OSINT Tool Integration
- **26 external tools** via direct links
- **Keyboard event listeners** for shortcuts
- **New tab isolation** for each tool

### IOC Extraction Engine
- **Regex-based detection**:
  - IPv4: `\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b`
  - Domains: `\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b`
  - URLs: `https?:\/\/[^\s<>"{}|\\^`\[\]]+`
  - Hashes: MD5 (32), SHA1 (40), SHA256 (64) hex patterns
- **Validation** to filter false positives
- **Deduplication** using Set data structure

## 🌟 What Makes THQV Unique?

### Integration of Three Platforms
THQV combines the best features from:
- **CyberGator**: AI hypothesis generation + OSINT keyboard shortcuts
- **FeedGator**: Enhanced RSS feed management + threat tagging
- **Original THQV**: Multi-platform MITRE detection queries

### Complete Threat Hunting Workflow
```
1. Consume Threat Intel → Live feeds with auto-tagging
2. Generate Hypotheses → AI-powered ideas from current threats
3. Build Detections → Multi-platform queries for MITRE techniques
4. Extract IOCs → Auto-extract from any text source
5. Investigate IOCs → One-key OSINT tool access
6. Deploy Queries → Copy/export for any SIEM platform
```

### Time-Saving Features
- **Seconds to OSINT**: Press 'V' for VirusTotal instead of typing URL
- **Instant queries**: Select technique, copy query, paste in SIEM
- **Auto IOC extraction**: No manual copy-paste from reports
- **Pre-built hypotheses**: Don't start from scratch every day
- **Cross-platform**: One query, five platform translations

## 📈 Statistics

- **Detection Queries**: 70+ ready-to-deploy
- **MITRE Techniques**: 14 high-priority tactics
- **SIEM Platforms**: 5 major platforms
- **OSINT Tools**: 26 integrated tools
- **Threat Feeds**: 10 trusted sources
- **IOC Types**: 4 (IP, Domain, URL, Hash)
- **Export Formats**: 3 (TXT, JSON, CSV)
- **Query Languages**: 3 translatable platforms

## 🎨 Design Philosophy

### Command Center Aesthetic
- **Tactical dark theme** for SOC environments
- **Color-coded severity** (Red=Critical, Yellow=High, Blue=Low)
- **Monospace fonts** for technical content
- **Tabbed navigation** for workflow efficiency
- **Visual feedback** on all interactions

### User Experience Priorities
1. **Speed**: Everything loads fast, operates instantly
2. **Accessibility**: Keyboard shortcuts, ARIA labels, clear contrast
3. **Clarity**: No clutter, clear labels, logical organization
4. **Efficiency**: Minimize clicks, maximize automation
5. **Flexibility**: Works for various skill levels and use cases

## 🌐 Browser Compatibility

- Chrome/Edge (Chromium) 90+
- Firefox 88+
- Safari 14+
- Opera 76+

**Requirements**:
- JavaScript enabled
- Session storage support
- Modern CSS (Flexbox, Grid)
- Clipboard API (for copy functions)

## 📱 Responsive Design

- **Desktop (1200px+)**: Full multi-column layout with all features
- **Tablet (768px-1199px)**: Two-column adaptive grid
- **Mobile (<768px)**: Single column, touch-optimized buttons

## 🔐 Privacy & Security

- **No telemetry** - zero tracking or analytics
- **Client-side only** - no data sent to servers (except RSS proxies)
- **No authentication** - no accounts or personal data collection
- **Session storage** - cleared when browser closes
- **HTTPS links** - all external tools use secure connections
- **Open source** - fully transparent, auditable code

## 🤝 Contributing

Contributions welcome! Areas for improvement:

### Detection Queries
- Add more MITRE ATT&CK techniques
- Expand platform coverage (QRadar, LogRhythm, etc.)
- Improve query efficiency and accuracy

### Features
- Query performance metrics
- Sigma rule generation
- STIX/TAXII integration
- Custom RSS feed management
- Threat correlation engine
- Query testing sandbox

### OSINT Tools
- Add more specialized tools
- Tool recommendation engine
- API integrations for automated lookups

### UI/UX
- Additional themes
- Customizable layouts
- Saved preferences
- Mobile app version

## 📝 License

MIT License - free for personal and commercial use.

## 👤 Author

**Pratik Goswami**
- GitHub: [@indocanadian416](https://github.com/indocanadian416)
- Role: Threat Researcher & Hunter
- Mission: Empowering the cybersecurity community with free, powerful tools

## 🙏 Acknowledgments

- All cybersecurity RSS feed providers for free threat intelligence
- [AllOrigins](https://allorigins.win/) for CORS proxy service
- OSINT tool providers for free threat intelligence platforms
- MITRE Corporation for the ATT&CK framework
- Cybersecurity community for continuous knowledge sharing
- Open source contributors worldwide

## 🔗 Related Projects

- **[CyberGator](https://github.com/indocanadian416/CyberGator)** - AI Threat Hunting Hypothesis Generator + OSINT Keyboard
- **[FeedGator](https://github.com/indocanadian416/Feedgator)** - Cybersecurity Threat Intelligence Feed Aggregator

## 📚 Resources

### MITRE ATT&CK
- [ATT&CK Framework](https://attack.mitre.org/)
- [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)

### Detection Engineering
- [Sigma Rules](https://github.com/SigmaHQ/sigma)
- [Detection Lab](https://github.com/clong/DetectionLab)
- [ThreatHunter-Playbook](https://github.com/OTRF/ThreatHunter-Playbook)

### Threat Intelligence
- [MISP Project](https://www.misp-project.org/)
- [OpenCTI](https://www.opencti.io/)
- [Ransomware.live](https://www.ransomware.live/)

---

**Built with ❤️ for threat hunters, SOC analysts, and security researchers**

*Hunt smarter. Detect faster. Defend better.*

---

## 🚦 Quick Start

```bash
# 1. Visit live site
https://indocanadian416.github.io/THQV/

# 2. Or run locally
git clone https://github.com/indocanadian416/THQV.git
cd THQV
python -m http.server 8000

# 3. Open browser
http://localhost:8000

# 4. Start hunting!
- Select MITRE technique → Copy query
- Generate AI hypotheses → Implement in hunting program  
- Extract IOCs → Investigate with OSINT tools
- Translate queries → Deploy across platforms
```

**Welcome to the future of threat hunting. Welcome to THQV.** 🐊