# CyberGator1 - Threat Hunting Command Center 🛡️

**Live Demo:** [https://indocanadian416.github.io/THQV/](https://indocanadian416.github.io/THQV/)

A comprehensive, single-page threat hunting dashboard designed for Security Operations Centers (SOCs), threat hunters, and detection engineers. Built with pure HTML/CSS/JavaScript - no frameworks required.

---

## 🚀 Features

### 1. **Threat Intelligence Feed**
- Real-time cybersecurity news aggregation from 5+ trusted sources:
  - BleepingComputer
  - The Hacker News
  - Krebs on Security
  - SecurityWeek
  - Dark Reading
- Intelligent auto-tagging (Ransomware, Zero-Day, APT, Phishing, Malware)
- Time-based filtering (24h, 7d, all-time)
- Live search across articles
- Full 450-character article descriptions
- Clickable links opening in new tabs

### 2. **AI Hypothesis Generator**
Generates threat hunting hypotheses from live threat intelligence using 5 unique templates:
- Shadow IT exploitation analysis
- APT activity masking detection
- Phishing campaign weaponization
- Supply chain risk investigation
- Insider threat amplification

Each hypothesis includes:
- Contextualized threat scenario
- MITRE ATT&CK TTPs
- Actionable hunt queries (KQL format)

### 3. **OSINT Tools Keyboard (A-Z)**
26 threat intelligence platforms accessible via keyboard shortcuts or click:
- **A** - AbuseIPDB
- **B** - BGPView
- **C** - Censys
- **D** - DNSTrails
- **V** - VirusTotal
- **S** - Shodan
- And 20 more...

**Usage:** Press any key (A-Z) while on the OSINT tab to instantly open that tool.

### 4. **IOC Extractor**
Automatically extracts and defangs indicators of compromise:
- **IPs:** Converts `8[.]8[.]8[.]8` → `8.8.8.8`
- **Domains:** Validates and extracts domain names
- **URLs:** Full URL extraction with defanging (`hxxp` → `http`)
- **Hashes:** MD5, SHA-1, SHA-256 detection

**Export formats:** TXT, JSON, CSV

### 5. **MITRE ATT&CK Detection Queries**
14 MITRE techniques with detection queries for 4 SIEM platforms:
- Microsoft Sentinel (KQL)
- Splunk (SPL)
- CrowdStrike Falcon (LogScale)
- Elastic SIEM (Lucene)

**Techniques covered:**
- T1059 - Command Interpreter
- T1566 - Phishing
- T1621 - MFA Fatigue
- T1486 - Ransomware Encryption
- And 10 more...

### 6. **Dark/Light Theme Toggle**
Perplexity-style theme switcher with persistent preferences (stored in localStorage).

---

## 📸 Screenshots

### Threat Intel Feed
![Threat Intel](https://img.shields.io/badge/Status-Live-brightgreen)

### Dark Theme
![Dark Mode](https://img.shields.io/badge/Theme-Dark%2FLight-blue)

---

## 🛠️ Tech Stack

- **Pure HTML5/CSS3/JavaScript** (no frameworks)
- **RSS Proxy:** rss2json.com API
- **Icons:** Font Awesome 6
- **Hosting:** GitHub Pages

---

## 🚀 Quick Start

### Option 1: Use Live Demo
Simply visit: [https://indocanadian416.github.io/THQV/](https://indocanadian416.github.io/THQV/)

### Option 2: Self-Host
1. Clone the repository:
   ```bash
   git clone https://github.com/indocanadian416/THQV.git
   cd THQV
   ```

2. Open `index.html` in any modern browser:
   ```bash
   open index.html  # macOS
   start index.html # Windows
   xdg-open index.html # Linux
   ```

### Option 3: Deploy to Your Own GitHub Pages
1. Fork this repository
2. Go to Settings → Pages
3. Source: `Deploy from a branch`
4. Branch: `main` → `/root`
5. Save

Your site will be live at `https://YOUR-USERNAME.github.io/THQV/`

---

## 📋 Usage Guide

### Threat Intel Tab
1. Wait 5-10 seconds for feeds to load
2. Use time filters to narrow results (24h recommended)
3. Search bar for keyword filtering
4. Click any article title to open source

### AI Hypothesis Generator
1. Ensure threat intel feeds are loaded first
2. Click "Generate Hypotheses"
3. Wait 1-2 seconds for AI processing
4. Review 10 unique hunting scenarios

### OSINT Tools
- **Click method:** Click any tool tile
- **Keyboard method:** Press corresponding letter key (A-Z)

### IOC Extractor
1. Paste threat intelligence text (supports defanged IOCs)
2. Click "Extract IOCs"
3. Review categorized results
4. Export via TXT/JSON/CSV buttons

### Detection Queries
1. Select MITRE technique from dropdown
2. View multi-platform queries
3. Click "Copy" button to clipboard

---

## 🔧 Customization

### Add More RSS Feeds
Edit line 65 in `index.html`:
```javascript
const rssFeeds=['https://example.com/feed.xml'];
```

### Modify OSINT Tools
Edit line 120+ in `index.html`:
```javascript
const osintTools=[{key:'A',name:'ToolName',url:'https://...'}];
```

### Add Detection Queries
Edit `detections` object starting at line 35.

---

## 🐛 Known Limitations

- RSS feed loading depends on rss2json.com availability
- Some RSS feeds may be rate-limited (10 articles max per feed)
- IOC extraction uses regex (may miss complex obfuscations)
- Detection queries are examples (tune for your environment)

---

## 🤝 Contributing

Contributions welcome! Please:
1. Fork the repo
2. Create a feature branch
3. Test thoroughly
4. Submit a pull request

**Ideas for contributions:**
- Additional MITRE techniques
- More OSINT tools
- Improved IOC regex patterns
- Dark theme refinements

---

## 📜 License

MIT License - feel free to use for personal or commercial projects.

---

## 👤 Author

**Pratik (CyberGator)**
- GitHub: [@indocanadian416](https://github.com/indocanadian416)

---

## 🌟 Star This Repo

If you find this useful, please ⭐ star this repository!

---

## 📞 Support

For issues or questions:
1. Check [Issues](https://github.com/indocanadian416/THQV/issues)
2. Open a new issue with detailed description
3. Include browser/OS information

---

**Last Updated:** December 2025
