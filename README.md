# 🛡️ SOC Analyst Resources Hub

<div align="center">

![GitHub stars](https://img.shields.io/github/stars/yourusername/SOC-Analyst-Resources?style=social)
![GitHub forks](https://img.shields.io/github/forks/yourusername/SOC-Analyst-Resources?style=social)
![GitHub last commit](https://img.shields.io/github/last-commit/yourusername/SOC-Analyst-Resources)
![License](https://img.shields.io/badge/license-MIT-blue.svg)

**A comprehensive collection of tools, detection rules, challenges, writeups, and resources for Security Operations Center (SOC) Analysts**

[Quick Start](#-quick-start) • [Features](#-features) • [Structure](#-repository-structure) • [Roadmap](#-roadmap) • [Contributing](#-contributing)

</div>

---

## 📋 Table of Contents

- [About](#-about)
- [Features](#-features)
- [Repository Structure](#-repository-structure)
- [Quick Start](#-quick-start)
- [What's Inside](#-whats-inside)
  - [Tools & Resources](#-tools--resources)
  - [Detection Rules](#-detection-rules)
  - [Challenges & Labs](#-challenges--labs)
  - [Writeups](#-writeups)
  - [Learning Path](#-learning-path)
- [How to Use This Repository](#-how-to-use-this-repository)
- [Roadmap](#-roadmap)
- [Contributing](#-contributing)
- [Connect](#-connect)
- [License](#-license)

---

## 🎯 About

This repository serves as a **comprehensive knowledge base** for SOC Analysts at all levels - from beginners building their first home lab to experienced professionals looking for detection rules and threat hunting queries.

### Why This Exists

As a SOC Analyst, I found myself constantly searching for:
- Quality detection rules that actually work
- Practical tools for daily SOC operations
- Real-world scenarios to practice incident response
- Curated resources without the noise

This repository is my attempt to create **the resource I wish I had** when starting in cybersecurity.

### Who This Is For

- 🎓 **Students** preparing for SOC analyst roles
- 💼 **Job Seekers** building their portfolio and skills
- 🔍 **SOC Analysts** looking for detection rules and automation tools
- 🎯 **Threat Hunters** seeking hunting queries and methodologies
- 🧪 **Blue Teamers** wanting hands-on practice scenarios

---

## ✨ Features

- 🔧 **100+ Curated Tools** - SIEM, EDR, log analysis, and automation tools
- 📜 **Detection Rules Library** - Sigma, YARA, Snort/Suricata, and SIEM-specific queries
- 🎮 **Practice Challenges** - Custom blue team scenarios with solutions
- 📝 **Detailed Writeups** - CTF solutions, malware analysis, incident investigations
- 📚 **Cheat Sheets** - Quick references for CLI tools, log analysis, and MITRE ATT&CK
- 🧪 **Lab Guides** - Step-by-step guides for building SOC home labs
- 🗺️ **Learning Paths** - Structured progression from beginner to advanced
- 🔄 **Regular Updates** - New content added consistently

---

## 📁 Repository Structure

```
SOC-Analyst-Resources/
│
├── 🔧 Tools/
│   ├── SIEM-Platforms/          # Splunk, ELK, Sentinel, QRadar guides
│   ├── EDR-XDR-Solutions/       # Endpoint detection and response tools
│   ├── Log-Analysis/            # Tools for parsing and analyzing logs
│   ├── Threat-Intelligence/     # TI platforms and feeds
│   ├── Network-Analysis/        # Wireshark, tcpdump, Zeek
│   ├── Incident-Response/       # IR tools and frameworks
│   └── Automation/              # Scripts for SOC automation
│
├── 🎯 Detection-Rules/
│   ├── Sigma/                   # Universal detection rules
│   ├── YARA/                    # Malware detection rules
│   ├── Snort-Suricata/          # Network IDS rules
│   ├── Splunk-SPL/              # Splunk queries and searches
│   ├── KQL/                     # Kusto Query Language (Sentinel)
│   └── ELK/                     # Elasticsearch queries
│
├── 🎮 Challenges/
│   ├── Custom-Scenarios/        # Original blue team challenges
│   ├── HackTheBox/              # HTB challenge guides
│   ├── TryHackMe/               # THM room walkthroughs
│   ├── BlueTeamLabs/            # BTL investigation scenarios
│   └── CyberDefenders/          # CyberDefenders challenges
│
├── 📝 Writeups/
│   ├── CTF-Writeups/            # Capture The Flag solutions
│   ├── Malware-Analysis/        # Malware sample analysis reports
│   ├── Incident-Analysis/       # Real-world incident breakdowns
│   ├── Vulnerability-Research/  # CVE analysis and PoCs
│   └── Threat-Intel-Reports/    # Threat actor and campaign analysis
│
├── 📚 Resources/
│   ├── Cheatsheets/             # Quick reference guides
│   ├── Playbooks/               # Incident response playbooks
│   ├── MITRE-ATT&CK-Mappings/   # ATT&CK framework references
│   ├── Threat-Intel-Feeds/      # Curated TI feed sources
│   ├── Compliance/              # Security frameworks (NIST, ISO, etc.)
│   └── Documentation/           # Best practices and procedures
│
├── 🧪 Labs/
│   ├── Home-Lab-Setup/          # Build your own SOC lab
│   ├── Detection-Lab-Scenarios/ # Attack simulation + detection
│   ├── Malware-Lab/             # Safe malware analysis environment
│   └── Practice-Environments/   # Pre-configured VMs and containers
│
└── 🎓 Learning-Path/
    ├── Beginner/                # Start here if you're new
    ├── Intermediate/            # Level up your skills
    ├── Advanced/                # Expert-level content
    ├── Certifications/          # Cert study guides and resources
    ├── Daily-Notes/             # Learning journal and progress
    └── Skills-Matrix/           # Self-assessment and tracking
```

---

## 🚀 Quick Start

### For Complete Beginners

1. **Start Here**: [Beginner Learning Path](Learning-Path/Beginner/)
2. **Set Up Your Lab**: [Home Lab Setup Guide](Labs/Home-Lab-Setup/)
3. **First Challenge**: [Custom Scenario 01](Challenges/Custom-Scenarios/Challenge-01/)
4. **Essential Tools**: [CLI Tools Cheatsheet](Resources/Cheatsheets/CLI-Tools.md)

### For Job Seekers

1. **Build Skills**: Complete challenges in [Challenges/](Challenges/)
2. **Create Portfolio**: Write your own [Writeups/](Writeups/)
3. **Learn Detection**: Study [Detection Rules](Detection-Rules/)
4. **Interview Prep**: [SOC Interview Guide](Learning-Path/interview-prep.md)

### For Active SOC Analysts

1. **Detection Rules**: Browse [Detection-Rules/](Detection-Rules/) by platform
2. **Automation**: Check [Tools/Automation/](Tools/Automation/) for scripts
3. **Threat Hunting**: [Threat Hunting Queries](Resources/Threat-Hunting/)
4. **IR Playbooks**: [Incident Response Templates](Resources/Playbooks/)

---

## 🔍 What's Inside

### 🛠️ Tools & Resources

#### SIEM Platforms
- **Splunk** - Installation, configuration, essential apps, SPL queries
- **ELK Stack** - Setup guides, Kibana dashboards, detection rules
- **Microsoft Sentinel** - KQL queries, workbooks, automation playbooks
- **QRadar** - Rules, custom properties, AQL queries
- **Chronicle** - YARA-L rules, UDM search examples

#### EDR/XDR Solutions
- Open-source: Wazuh, LimaCharlie, Velociraptor
- Commercial: CrowdStrike, SentinelOne, Carbon Black (trial guides)
- Comparison matrix and use case recommendations

#### Log Analysis Tools
- Windows Event Log parsers (EVTX, XML)
- Syslog analyzers and aggregators
- Web server log analysis (Apache, Nginx, IIS)
- Firewall log parsers (pfSense, Cisco, Palo Alto)

### 🎯 Detection Rules

All detection rules include:
- ✅ Rule logic explanation
- ✅ MITRE ATT&CK mapping
- ✅ Test data and validation steps
- ✅ False positive considerations
- ✅ Tuning recommendations

#### Coverage by Category
- **Initial Access**: Phishing, exploit public-facing apps, valid accounts
- **Execution**: PowerShell, command-line, scripting
- **Persistence**: Registry run keys, scheduled tasks, services
- **Privilege Escalation**: Token manipulation, bypass UAC
- **Defense Evasion**: Obfuscated files, indicator removal
- **Credential Access**: Credential dumping, brute force
- **Discovery**: Account/system discovery, network scanning
- **Lateral Movement**: Remote services, pass-the-hash
- **Collection**: Data staging, screen capture
- **Exfiltration**: Exfiltration over C2, data transfer size limits

### 🎮 Challenges & Labs

#### Custom Blue Team Scenarios
Each scenario includes:
- 📖 Realistic incident description
- 📁 Log files and artifacts (PCAP, EVTX, memory dumps)
- 🎯 Investigation objectives
- 🔍 IOCs to discover
- ✅ Complete solution with methodology

**Available Scenarios:**
1. **Brute Force Attack** - Detect and analyze credential stuffing
2. **Phishing Campaign** - Email analysis and user compromise
3. **Ransomware Outbreak** - Rapid response and containment
4. **Data Exfiltration** - Insider threat investigation
5. **APT Simulation** - Multi-stage attack detection

#### Platform Challenges
- **TryHackMe**: Blue team room walkthroughs
- **HackTheBox**: Forensics and DFIR challenges
- **BlueTeamLabs**: Investigation scenario solutions
- **CyberDefenders**: DFIR challenge writeups

### 📝 Writeups

#### CTF Writeups
Detailed solutions with:
- Tools used and why
- Step-by-step methodology
- Alternative approaches
- Lessons learned
- Key takeaways for real SOC work

#### Malware Analysis Reports
Professional-grade analysis including:
- Static analysis (strings, PE headers, imports)
- Dynamic analysis (behavioral observations)
- Network indicators (C2 servers, DNS requests)
- File system artifacts
- Complete IOC list
- Detection recommendations

#### Incident Analysis
Real-world breach case studies:
- Attack timeline reconstruction
- Threat actor TTPs (MITRE ATT&CK mapped)
- Detection gaps analysis
- Remediation recommendations
- Lessons learned

### 🎓 Learning Path

#### Beginner Track (0-6 months)
- ✅ Security fundamentals
- ✅ Networking basics
- ✅ Linux & Windows administration
- ✅ Log analysis fundamentals
- ✅ First SIEM (Splunk fundamentals)
- ✅ Basic Python scripting

#### Intermediate Track (6-12 months)
- ✅ Advanced SIEM queries
- ✅ Threat hunting methodologies
- ✅ Malware analysis basics
- ✅ Incident response procedures
- ✅ Network traffic analysis
- ✅ Security automation

#### Advanced Track (12+ months)
- ✅ Advanced threat hunting
- ✅ Detection engineering
- ✅ Threat intelligence operations
- ✅ Advanced malware analysis
- ✅ Purple team operations
- ✅ SOC process optimization

---

## 📖 How to Use This Repository

### As a Learning Resource
1. **Follow the Learning Path** - Start with beginner content, progress systematically
2. **Complete Challenges** - Practice makes perfect; try all custom scenarios
3. **Study Writeups** - Learn from detailed analysis and methodologies
4. **Build Your Lab** - Hands-on experience is crucial

### As a Reference Guide
1. **Bookmark Cheatsheets** - Quick access during investigations
2. **Copy Detection Rules** - Adapt rules for your environment
3. **Use Playbooks** - Follow proven IR procedures
4. **Reference Tools** - Find the right tool for each task

### As a Portfolio
1. **Fork This Repo** - Make it your own
2. **Add Your Writeups** - Document your learning journey
3. **Contribute Improvements** - Show collaboration skills
4. **Share on LinkedIn** - Showcase your commitment to learning

### For Daily Practice
- **Monday**: Learn a new tool from the catalog
- **Tuesday**: Write or improve a detection rule
- **Wednesday**: Complete a CTF challenge
- **Thursday**: Work on a lab scenario
- **Friday**: Write up your findings from the week

---

## 🗺️ Roadmap

### Current Focus (Month 1)
- [x] Repository structure and organization
- [ ] Core detection rules library (50+ rules)
- [ ] Essential cheatsheets and playbooks
- [ ] First 5 custom challenges
- [ ] Home lab setup guide

### Next Quarter
- [ ] 100+ detection rules across all platforms
- [ ] 20+ CTF writeups
- [ ] 10+ malware analysis reports
- [ ] Advanced threat hunting guide
- [ ] Video tutorials for complex topics

### Long-term Goals
- [ ] Automated detection rule testing framework
- [ ] Interactive challenge platform
- [ ] Community contribution system
- [ ] SOC analyst certification path
- [ ] Partnerships with blue team platforms

### Wish List (Community Requests)
- [ ] Mobile app for on-the-go learning
- [ ] Discord community for discussions
- [ ] Monthly webinars and workshops
- [ ] Gamified learning tracks
- [ ] Career mentorship program

---

## 🤝 Contributing

Contributions are **highly encouraged**! This repository grows stronger with community input.

### Ways to Contribute

1. **Add Detection Rules** - Share rules that work in production
2. **Write Challenges** - Create blue team scenarios
3. **Submit Writeups** - Document your CTF solutions or analyses
4. **Improve Documentation** - Fix typos, clarify explanations
5. **Suggest Resources** - Recommend tools or learning materials
6. **Report Issues** - Found something wrong? Let me know!

### Contribution Guidelines

- **Quality over Quantity**: Well-documented content preferred
- **Attribution**: Credit original sources appropriately
- **Testing**: Verify detection rules before submitting
- **Formatting**: Follow existing markdown style
- **No Malicious Content**: Ethical hacking only

See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed guidelines.

### Recognition

Contributors will be:
- ⭐ Listed in [CONTRIBUTORS.md](CONTRIBUTORS.md)
- 📢 Acknowledged in release notes
- 🏆 Featured in monthly highlights

---

## 📊 Repository Statistics

- **Detection Rules**: 50+ (and growing)
- **Challenges**: 15+ scenarios
- **Writeups**: 20+ detailed analyses
- **Tools Documented**: 100+
- **Cheatsheets**: 10+
- **Playbooks**: 8+
- **Last Updated**: Check commit history

---

## 🌟 Featured Content

### Most Popular Detection Rules
1. [PowerShell Exploitation Detection](Detection-Rules/Sigma/powershell-exploitation.yml)
2. [Credential Dumping (LSASS Access)](Detection-Rules/Sigma/credential-dumping.yml)
3. [Ransomware Behavior Detection](Detection-Rules/YARA/ransomware-detection.yar)

### Must-Read Writeups
1. [TryHackMe: Investigating Windows](Writeups/CTF-Writeups/TryHackMe/investigating-windows.md)
2. [Emotet Malware Analysis](Writeups/Malware-Analysis/emotet-analysis.md)
3. [SolarWinds Supply Chain Attack Breakdown](Writeups/Incident-Analysis/solarwinds-supply-chain.md)

### Top Challenges
1. [Custom Scenario: Ransomware Outbreak](Challenges/Custom-Scenarios/Challenge-03/)
2. [Network Traffic Analysis: C2 Detection](Challenges/Custom-Scenarios/Challenge-05/)
3. [Memory Forensics: Finding the Backdoor](Challenges/Custom-Scenarios/Challenge-07/)

---

## 📚 Recommended External Resources

### Free Training Platforms
- [TryHackMe](https://tryhackme.com) - Guided blue team paths
- [LetsDefend](https://letsdefend.io) - SOC analyst simulations
- [CyberDefenders](https://cyberdefenders.org) - DFIR challenges
- [BlueTeamLabs Online](https://blueteamlabs.online) - Investigations

### Certifications Worth Pursuing
- **Entry Level**: Security+, CySA+
- **SOC Focused**: BTL1, GCFA, GCIA
- **Advanced**: GCIH, GREM, GNFA
- **Cloud**: AZ-500, SC-200

### Communities to Join
- Reddit: r/blueteamsec, r/SOC
- Discord: Blue Team Village, DFIR Discord
- Twitter: #BlueTeam, #ThreatHunting, #DFIR
- LinkedIn: SOC Analyst groups

---

## 💬 Connect

- **GitHub Issues**: Questions, bug reports, feature requests
- **Discussions**: Share ideas and get feedback
- **LinkedIn**: [Your LinkedIn Profile]
- **Twitter**: [@YourHandle]
- **Blog**: [Your Blog URL]

### Questions?

- 📧 **Email**: your.email@example.com
- 💬 **Discussions**: Use GitHub Discussions tab
- 🐛 **Issues**: Report bugs via Issues tab

---

## 📜 License

This repository is licensed under the **MIT License** - see [LICENSE](LICENSE) file for details.

**TL;DR**: You can use, modify, and distribute this content freely, even commercially. Just keep the attribution.

---

## ⚠️ Disclaimer

- **Educational Purpose**: All content is for **educational and ethical purposes only**
- **No Malicious Use**: Do not use tools, techniques, or knowledge for illegal activities
- **Test Safely**: Always use isolated lab environments for testing
- **Attribution**: Respect intellectual property; credit sources appropriately
- **No Warranty**: Content provided as-is without guarantees

---

## 🙏 Acknowledgments

Special thanks to:
- The cybersecurity community for sharing knowledge freely
- Content creators who inspire continuous learning
- Contributors who help improve this repository
- Platform maintainers (THM, HTB, BTL, etc.)
- Open-source tool developers

---

## 📈 Support This Project

If you find this repository useful:

⭐ **Star this repo** - Helps others discover it  
🔀 **Fork and contribute** - Make it better  
📢 **Share with others** - Spread the knowledge  
💬 **Provide feedback** - Help improve content  
☕ **Buy me a coffee** - [Optional donation link]

---

<div align="center">

**Built with ❤️ by a SOC Analyst, for SOC Analysts**

*Last Updated: [Current Date]*

[⬆ Back to Top](#-soc-analyst-resources-hub)

</div>
