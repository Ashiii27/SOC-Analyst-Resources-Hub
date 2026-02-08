# Blue Team Challenge Template

Use this template when creating custom SOC investigation scenarios.

---

## Directory Structure

```
Challenges/Custom-Scenarios/Your-Challenge-Name/
├── README.md              # Main challenge description (use this template)
├── artifacts/             # All evidence files
│   ├── logs/
│   │   ├── windows/
│   │   ├── network/
│   │   └── application/
│   ├── network/
│   │   └── capture.pcap
│   ├── memory/
│   │   └── memory.dmp
│   └── files/
│       └── suspicious-file.exe
├── solution/
│   └── SOLUTION.md        # Detailed walkthrough
├── hints/
│   └── HINTS.md           # Progressive hints (optional)
└── tools/
    └── RECOMMENDED-TOOLS.md
```

---

## Challenge README Template

```markdown
# Challenge Name

![Difficulty](https://img.shields.io/badge/Difficulty-Medium-yellow)
![Type](https://img.shields.io/badge/Type-Incident%20Response-blue)
![Estimated Time](https://img.shields.io/badge/Time-2--3%20hours-green)

## 🎯 Challenge Overview

**Scenario Type**: [Ransomware/Phishing/Data Breach/APT/Insider Threat/etc.]
**Skills Required**: [Log analysis, Network forensics, Malware analysis, etc.]
**Tools Needed**: [Wireshark, Splunk, Volatility, etc.]

### Backstory

[Provide a realistic scenario that sets the context]

**Example:**
> You are a SOC analyst at TechCorp Industries. At 2:47 AM on January 15, 2025, 
> your SIEM triggered multiple high-severity alerts indicating potential 
> ransomware activity on several file servers. The night shift analyst escalated 
> the incident to you. Your task is to investigate the compromise, determine 
> the initial access vector, identify affected systems, and provide containment 
> recommendations.

---

## 📋 Investigation Objectives

Your goals for this investigation:

1. **[Objective 1]** - Example: Determine the initial access vector
2. **[Objective 2]** - Example: Identify the compromised user account
3. **[Objective 3]** - Example: Find the C2 server IP address
4. **[Objective 4]** - Example: List all affected systems
5. **[Objective 5]** - Example: Extract IOCs for threat hunting

---

## 🔍 Available Evidence

### Timeline
- **Incident Start**: [Date/Time]
- **Detection Time**: [Date/Time]
- **Investigation Start**: [Date/Time]

### Artifacts Provided

#### Logs (`artifacts/logs/`)
- **Windows Event Logs**
  - `DC-01-Security.evtx` - Domain Controller security logs (24 hours)
  - `WS-ADMIN-Security.evtx` - Admin workstation logs
  - `FS-01-Security.evtx` - File server security logs
- **Sysmon Logs**
  - `sysmon-export.xml` - Sysmon data from affected hosts
- **Firewall Logs**
  - `firewall-2025-01-15.log` - Perimeter firewall logs
- **Proxy Logs**
  - `proxy-access.log` - Web proxy logs

#### Network Traffic (`artifacts/network/`)
- `suspicious-traffic.pcap` - Packet capture during incident window
- `dns-queries.csv` - DNS query logs

#### Memory Dumps (`artifacts/memory/`)
- `WS-ADMIN-memory.raw` - Memory dump from suspected compromised workstation

#### Suspicious Files (`artifacts/files/`)
- `document.pdf.exe` - Suspicious executable (MD5: abc123...)
- `persistence.ps1` - PowerShell script found on system

---

## 🎓 Learning Objectives

By completing this challenge, you will practice:

- [X] Analyzing Windows Event Logs for authentication anomalies
- [X] Performing network traffic analysis to identify C2 communication
- [X] Extracting and analyzing suspicious files safely
- [X] Memory forensics to find malware artifacts
- [X] Building a comprehensive timeline of attack events
- [X] Creating an incident report with actionable recommendations

---

## 🛠️ Recommended Tools

See [tools/RECOMMENDED-TOOLS.md](tools/RECOMMENDED-TOOLS.md) for detailed tool setup.

**Essential:**
- Log Analysis: Splunk Free, ELK, or Event Viewer
- Network Analysis: Wireshark, NetworkMiner
- Memory Forensics: Volatility 3
- Malware Analysis: PEStudio, CyberChef, VirusTotal

**Optional:**
- Timeline: Plaso/log2timeline
- Visualization: Maltego, Draw.io

---

## 📝 Deliverables

Create an investigation report that includes:

### Executive Summary
- Brief overview of the incident
- Key findings
- Business impact
- Immediate recommendations

### Technical Analysis
- Detailed timeline of events
- Attack chain reconstruction
- Evidence and artifacts analyzed
- Tools and techniques used

### Indicators of Compromise (IOCs)
- File hashes
- IP addresses
- Domain names
- Registry keys
- File paths
- User accounts involved

### Containment & Remediation
- Immediate containment steps taken
- Short-term remediation actions
- Long-term security improvements
- Detection gaps identified

### Lessons Learned
- What went well
- What could be improved
- Recommendations for prevention

---

## ⏱️ Estimated Time

**Beginner**: 4-5 hours  
**Intermediate**: 2-3 hours  
**Advanced**: 1-2 hours

---

## 🚦 Difficulty Breakdown

**Easy**: 
- [ ] Clear attack patterns
- [ ] Limited artifacts to analyze
- [ ] Straightforward investigation path
- [ ] Common attack techniques

**Medium**:
- [X] Multiple attack vectors
- [X] Several artifacts requiring correlation
- [X] Some obfuscation present
- [X] Requires systematic approach

**Hard**:
- [ ] Advanced persistent threat scenario
- [ ] Heavy obfuscation and anti-forensics
- [ ] Large volume of data to sift through
- [ ] Multiple simultaneous attack techniques

---

## 💡 Hints

Stuck? Progressive hints are available in [hints/HINTS.md](hints/HINTS.md)

**Hints are structured as:**
- Hint 1 (Gentle nudge)
- Hint 2 (Stronger direction)
- Hint 3 (Specific guidance)
- Hint 4 (Near-complete direction)

Try to solve without hints first! But don't waste hours being stuck.

---

## ✅ Solution

A complete walkthrough with methodology is available in [solution/SOLUTION.md](solution/SOLUTION.md)

**The solution includes:**
- Step-by-step investigation process
- Commands and tools used
- Screenshots of key findings
- Answers to all investigation objectives
- Sample incident report

**Please attempt the challenge before reading the solution!**

---

## 🎓 Skills Practiced

After completing this challenge, you'll have practiced:

- [X] **Skill Category 1**: Specific skills like log correlation
- [X] **Skill Category 2**: Network traffic analysis
- [X] **Skill Category 3**: Malware identification
- [X] **Skill Category 4**: Timeline creation
- [X] **Skill Category 5**: Report writing

**MITRE ATT&CK Techniques Covered:**
- T1078 - Valid Accounts
- T1059.001 - PowerShell
- T1486 - Data Encrypted for Impact
- [Add more based on your scenario]

---

## 📚 Additional Learning Resources

- [Link to related MITRE ATT&CK techniques]
- [Blog posts about similar attacks]
- [Documentation for tools used]
- [Related challenges or training]

---

## 🤝 Feedback & Issues

Found an error in the challenge? Have suggestions for improvement?

- Open an issue in the main repository
- Tag it with `challenge-feedback`
- Reference this challenge name

---

## 📜 Challenge Metadata

**Created by**: [Your Name]  
**Date**: YYYY-MM-DD  
**Last Updated**: YYYY-MM-DD  
**Version**: 1.0  
**Difficulty**: Medium  
**Estimated Completion Time**: 2-3 hours  
**Based on**: [Real attack / CTF / Original]

---

## 🏆 Bonus Challenges

Completed the main objectives? Try these advanced tasks:

1. **Threat Hunting**: Write Sigma rules to detect this attack in the future
2. **Automation**: Create a script to automate parts of the analysis
3. **Presentation**: Create a brief for executive leadership (non-technical)
4. **Purple Team**: Design a detection lab to test your rules

---

**Good luck with your investigation! Remember: Be methodical, document everything, and follow the evidence.** 🔍

```

---

## Solution Template (solution/SOLUTION.md)

```markdown
# [Challenge Name] - Complete Solution

⚠️ **SPOILER ALERT**: This document contains the complete solution. Attempt the challenge first!

---

## Investigation Summary

**Attack Type**: [Type]  
**Initial Access**: [How attacker got in]  
**Lateral Movement**: [How they moved]  
**Impact**: [What they did]  
**Key IOCs**: [Summary of important indicators]

---

## Detailed Walkthrough

### Step 1: Initial Triage

**Objective**: Understand the scope of the incident

**Tools Used**: 
- Windows Event Viewer
- Timeline analysis

**Procedure**:
```bash
# Commands used
command 1
command 2
```

**Findings**:
- Finding 1 with evidence
- Finding 2 with evidence

**Screenshots**:
![Initial Triage](screenshots/step1-triage.png)

---

### Step 2: [Next Investigation Phase]

[Continue with each step...]

---

## Investigation Questions Answered

### Q1: What was the initial access vector?
**Answer**: Phishing email with malicious attachment

**Evidence**:
- Email log entry at 2025-01-15 08:23:45
- File creation: `C:\Users\jsmith\Downloads\invoice.pdf.exe`
- Sysmon Event ID 1 (Process Creation)

---

### Q2: [Next Question]
[Answer with evidence...]

---

## Complete IOC List

### File Hashes
```
MD5: abc123...
SHA1: def456...
SHA256: ghi789...
```

### IP Addresses
```
C2 Server: 192.168.1.100
Staging Server: 10.0.0.50
```

### Domain Names
```
malicious-domain.com
phishing-site.net
```

### Registry Keys
```
HKLM\Software\Microsoft\Windows\CurrentVersion\Run\Malware
```

### File Paths
```
C:\Users\Public\malware.exe
C:\Windows\Temp\payload.dll
```

---

## Timeline of Attack

| Time | Event | Evidence Source |
|------|-------|----------------|
| 08:23 | Phishing email received | Email logs |
| 08:25 | Malicious file executed | Sysmon Event 1 |
| 08:27 | Persistence established | Registry changes |
| 08:30 | C2 communication initiated | Network logs |

---

## Alternative Investigation Paths

You might have approached this differently:

**Path 1: Network-First Approach**
- Start with PCAP analysis
- Identify C2 traffic
- Work backwards to find source

**Path 2: Timeline Approach**
- Build complete timeline first
- Identify anomalies
- Investigate specific events

Both are valid! The key is systematic methodology.

---

## Detection Rules

### Sigma Rule for This Attack

```yaml
title: Detection of [Attack Technique]
...
```

### Splunk Query

```spl
index=windows EventCode=4688
| where CommandLine LIKE "%malicious_pattern%"
```

---

## Lessons Learned

**What This Exercise Teaches:**
1. Importance of log correlation
2. Value of network visibility
3. Need for endpoint monitoring
4. Critical role of timeline analysis

**Common Mistakes:**
- Rushing to conclusions without evidence
- Missing lateral movement indicators
- Not documenting findings thoroughly

**Pro Tips:**
- Always validate findings with multiple sources
- Document your steps for the report
- Consider the attacker's objectives

---

## Sample Incident Report

[Include a complete example report]

---

**Congratulations on completing this challenge!** 🎉

Consider sharing your alternative solutions or asking questions in Discussions!
```

---

## Questions?

For assistance creating challenges, see [CONTRIBUTING.md](../CONTRIBUTING.md) or open a discussion!
