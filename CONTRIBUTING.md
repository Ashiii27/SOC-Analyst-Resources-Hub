# Contributing to SOC Analyst Resources Hub

First off, thank you for considering contributing to this project! 🎉

The SOC community thrives on shared knowledge, and your contributions help fellow analysts learn and grow.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [How Can I Contribute?](#how-can-i-contribute)
- [Contribution Guidelines](#contribution-guidelines)
- [Style Guide](#style-guide)
- [Submission Process](#submission-process)

---

## Code of Conduct

### Our Pledge

We are committed to providing a welcoming and inclusive environment for all contributors, regardless of experience level, background, or identity.

### Expected Behavior

- Be respectful and constructive in all interactions
- Welcome newcomers and help them get started
- Give credit where credit is due
- Focus on what's best for the community
- Accept constructive criticism gracefully

### Unacceptable Behavior

- Harassment, discrimination, or offensive language
- Sharing malicious code or tools for illegal purposes
- Plagiarism or failure to attribute sources
- Spam or self-promotion without adding value

---

## How Can I Contribute?

### 1. Add Detection Rules

**We Need:**
- Sigma rules for universal compatibility
- YARA rules for malware detection
- SIEM-specific queries (Splunk SPL, KQL, EQL)
- IDS/IPS rules (Snort, Suricata)

**Requirements:**
- Include detailed explanation of detection logic
- Map to MITRE ATT&CK techniques
- Provide test data or validation steps
- Document false positive scenarios
- Explain tuning recommendations

**Template:**
```yaml
# Rule Name: [Descriptive Name]
# Author: [Your Name/Handle]
# Date: YYYY-MM-DD
# MITRE ATT&CK: [Technique ID and Name]
# Description: [What this rule detects and why]

[Your rule here]

# Test Data:
# [How to validate this rule works]

# False Positives:
# [Known scenarios that may trigger this rule]

# Tuning:
# [How to reduce false positives]
```

### 2. Write Challenges

**We Need:**
- Blue team investigation scenarios
- Forensics challenges with artifacts
- Network traffic analysis (PCAPs)
- Log analysis exercises
- Malware analysis scenarios

**Requirements:**
- Realistic and educational scenario
- All necessary files (logs, PCAPs, memory dumps, etc.)
- Clear objectives for investigators
- Complete solution with methodology
- Difficulty level indication (Beginner/Intermediate/Advanced)

**Structure:**
```
Challenges/Custom-Scenarios/Your-Challenge-Name/
├── README.md              # Scenario description and objectives
├── artifacts/             # Evidence files
│   ├── logs/
│   ├── network/
│   └── memory/
├── solution/              # Complete walkthrough
│   └── SOLUTION.md
└── hints/                 # Optional progressive hints
    └── HINTS.md
```

### 3. Submit Writeups

**We Accept:**
- CTF challenge solutions (TryHackMe, HackTheBox, etc.)
- Malware analysis reports
- Incident investigation analyses
- Vulnerability research and PoCs
- Threat intelligence reports

**Requirements:**
- Detailed methodology explanation
- Tools used and why
- Screenshots or evidence
- Key learnings and takeaways
- Clear writing and proper formatting

**Template Structure:**
```markdown
# [Challenge/Malware/Incident Name]

**Platform**: [TryHackMe/HTB/Real-world/etc.]
**Difficulty**: [Easy/Medium/Hard]
**Date Completed**: YYYY-MM-DD
**Skills Practiced**: [List relevant skills]

## Overview
[Brief description]

## Methodology

### Step 1: [Phase Name]
[Detailed explanation with commands/screenshots]

### Step 2: [Next Phase]
[Continue...]

## Key Findings
- [Important discovery 1]
- [Important discovery 2]

## Tools Used
- Tool 1: [Purpose]
- Tool 2: [Purpose]

## Lessons Learned
[What you learned from this challenge]

## IOCs (if applicable)
[List of indicators of compromise]
```

### 4. Improve Documentation

**Ways to Help:**
- Fix typos and grammatical errors
- Clarify confusing explanations
- Add examples to existing content
- Update outdated information
- Improve formatting and readability
- Add diagrams or visualizations

### 5. Suggest Resources

**We Welcome:**
- Useful tools not yet documented
- Quality learning resources
- Training platforms
- Threat intelligence feeds
- Open-source projects

**Format:**
```markdown
**Tool/Resource Name**: [Name]
**Type**: [SIEM/EDR/Analysis Tool/Learning Platform/etc.]
**URL**: [Link]
**Cost**: [Free/Freemium/Paid]
**Why It's Useful**: [Brief explanation]
**Best For**: [Beginners/Intermediate/Advanced]
```

### 6. Report Issues

Found something wrong? Please open an issue with:
- Clear description of the problem
- Steps to reproduce (if applicable)
- Expected vs actual behavior
- Screenshots if relevant
- Suggested solution (optional)

---

## Contribution Guidelines

### Content Standards

✅ **Do:**
- Provide accurate and tested information
- Include proper attribution for sources
- Use clear and professional language
- Follow existing formatting conventions
- Test detection rules before submitting
- Provide context and explanations

❌ **Don't:**
- Submit untested or theoretical content
- Copy/paste without attribution
- Include malicious code or exploits for illegal use
- Submit low-quality or rushed content
- Violate copyright or licenses
- Share proprietary or confidential information

### Ethical Guidelines

**All content must be:**
- **Legal**: Compliant with applicable laws
- **Ethical**: For defensive/educational purposes only
- **Responsible**: No weaponized exploits or malware
- **Accurate**: Tested and verified information
- **Attributed**: Proper credit to original sources

**When Sharing:**
- Detection rules: Ensure they're tested and won't cause operational issues
- Malware samples: Use hashes, never live samples
- Exploits: Share detection methods, not attack tools
- PCAP files: Sanitize sensitive information

---

## Style Guide

### Markdown Formatting

**Headers:**
```markdown
# H1 - Main Title
## H2 - Major Section
### H3 - Subsection
#### H4 - Detail Level
```

**Code Blocks:**
```markdown
Use language-specific code blocks:

```python
# Python code
```

```bash
# Bash commands
```

```yaml
# YAML content
```
```

**Lists:**
- Use `-` for unordered lists
- Use `1.` for ordered lists
- Indent sub-items with 2 spaces

**Emphasis:**
- Use `**bold**` for important terms
- Use `*italic*` for emphasis
- Use `code` for commands, filenames, variables

### File Naming

**Use kebab-case:**
- ✅ `windows-event-log-analysis.md`
- ✅ `powershell-exploitation.yml`
- ❌ `Windows Event Log Analysis.md`
- ❌ `PowerShellExploitation.yml`

**Be descriptive:**
- ✅ `credential-dumping-lsass-detection.yml`
- ❌ `rule1.yml`

### Directory Structure

Place content in the appropriate directory:
- Detection rules → `Detection-Rules/[Type]/`
- Writeups → `Writeups/[Category]/`
- Challenges → `Challenges/[Platform or Custom-Scenarios]/`
- Tools → `Tools/[Category]/`
- Resources → `Resources/[Type]/`

---

## Submission Process

### For Small Changes (Typos, Minor Fixes)

1. **Fork the repository**
2. **Make your changes** in your fork
3. **Submit a pull request** with a clear description

### For New Content (Rules, Writeups, Challenges)

1. **Open an issue first** describing what you want to add
2. **Get feedback** to ensure it aligns with the repo goals
3. **Fork and create a branch** for your contribution
4. **Add your content** following the style guide
5. **Test thoroughly** (especially for detection rules)
6. **Submit a pull request** with:
   - Clear title describing the addition
   - Reference to the original issue
   - Summary of what's included
   - Testing/validation performed

### Pull Request Template

```markdown
## Description
[Brief description of changes]

## Type of Contribution
- [ ] Detection Rule
- [ ] Challenge/Lab
- [ ] Writeup
- [ ] Documentation
- [ ] Resource/Tool Addition
- [ ] Bug Fix

## Checklist
- [ ] I have tested this content
- [ ] I have followed the style guide
- [ ] I have attributed sources appropriately
- [ ] I have added necessary documentation
- [ ] This content is ethical and legal

## Additional Notes
[Any additional context or information]
```

### Review Process

1. **Automated checks** (if applicable)
2. **Content review** by maintainers
3. **Feedback or approval** within 3-5 days
4. **Merge** after approval

---

## Recognition

### Contributors Will Be:

- ⭐ Listed in [CONTRIBUTORS.md](CONTRIBUTORS.md)
- 📢 Acknowledged in release notes
- 🏆 Featured in monthly highlights (for significant contributions)
- 🎖️ Eligible for "Top Contributor" badge

### Contribution Tiers

**🥉 Bronze Contributor**: 1-4 accepted contributions  
**🥈 Silver Contributor**: 5-9 accepted contributions  
**🥇 Gold Contributor**: 10-19 accepted contributions  
**💎 Diamond Contributor**: 20+ accepted contributions

---

## Questions?

- **General questions**: Open a Discussion
- **Specific issues**: Open an Issue
- **Collaboration ideas**: Email [your.email@example.com]
- **Urgent matters**: Tag @yourusername in the issue

---

## Thank You!

Every contribution, no matter how small, makes this repository better for the entire SOC community. Your time and expertise are deeply appreciated! 🙏

**Remember**: The best way to learn is to teach. By contributing here, you're not just building this repository – you're building your own expertise and helping others grow theirs.

Happy hunting! 🔍🛡️

---

*This contributing guide is itself a living document. If you have suggestions to improve it, please contribute!*
