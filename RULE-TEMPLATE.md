# Sigma Detection Rule Template

## File Naming Convention
`technique-name-description.yml`

Example: `powershell-encoded-command-execution.yml`

---

## Rule Template

```yaml
title: [Descriptive Title - What This Rule Detects]
id: [Generate UUID at https://www.uuidgenerator.net/]
status: [experimental/test/stable]
description: |
    Detailed description of what this rule detects and why it's important.
    Include context about the attack technique and how adversaries use it.
    Explain what makes this activity suspicious or malicious.
references:
    - https://attack.mitre.org/techniques/[TECHNIQUE_ID]/
    - [Additional reference URLs]
author: Your Name (@YourHandle)
date: YYYY-MM-DD
modified: YYYY-MM-DD
tags:
    - attack.[tactic]
    - attack.[technique_id]
    - attack.[sub_technique_id]  # if applicable
logsource:
    category: [process_creation/network_connection/file_event/registry_event/etc]
    product: [windows/linux/macos/etc]
    service: [sysmon/security/etc]  # if applicable
detection:
    selection:
        # Define what to look for
        EventID: 1234
        FieldName|contains: 'suspicious_value'
    condition: selection
falsepositives:
    - Legitimate administrative activity
    - Specific software that may trigger this rule
    - Known business processes
level: [low/medium/high/critical]
```

---

## Detailed Field Explanations

### Title
- **Purpose**: Clear, concise description of what the rule detects
- **Format**: "Action - Target - Context"
- **Examples**:
  - ✅ "Suspicious PowerShell Encoded Command Execution"
  - ✅ "Credential Dumping via LSASS Process Access"
  - ❌ "PowerShell Rule"
  - ❌ "Detection Rule 1"

### ID
- **Purpose**: Unique identifier for the rule
- **Format**: UUID v4
- **Generate at**: https://www.uuidgenerator.net/
- **Example**: `a1b2c3d4-e5f6-7890-abcd-ef1234567890`

### Status
- `experimental`: New rule, needs testing
- `test`: Currently being tested in production
- `stable`: Proven to work well with low false positives

### Description
Should include:
- What the rule detects
- Why this activity is suspicious
- Adversary context (how/why they do this)
- Brief explanation of the detection logic

### References
- MITRE ATT&CK technique page (required)
- Blog posts or articles about the technique
- Malware reports or threat intelligence
- Microsoft documentation or vendor advisories

### Author
- Your name and/or handle
- GitHub username
- Organization (optional)

### Dates
- `date`: When the rule was created
- `modified`: Last modification date
- Format: YYYY-MM-DD

### Tags
MITRE ATT&CK mapping is essential:
- `attack.initial_access`
- `attack.execution`
- `attack.persistence`
- `attack.privilege_escalation`
- `attack.defense_evasion`
- `attack.credential_access`
- `attack.discovery`
- `attack.lateral_movement`
- `attack.collection`
- `attack.exfiltration`
- `attack.command_and_control`
- `attack.impact`

Add technique IDs:
- `attack.t1059` (for main technique)
- `attack.t1059.001` (for sub-technique)

### Logsource
Defines what type of logs this rule analyzes:

**Category options:**
- `process_creation`: Process execution events
- `network_connection`: Network activity
- `file_event`: File creation/modification/deletion
- `registry_event`: Registry modifications
- `dns_query`: DNS lookups
- `image_load`: DLL/module loading

**Product options:**
- `windows`
- `linux`
- `macos`
- `azure`
- `aws`
- `gcp`

**Service options (Windows):**
- `sysmon`: Sysmon events
- `security`: Windows Security logs
- `system`: Windows System logs
- `powershell`: PowerShell logs

### Detection
This is the core logic:

```yaml
detection:
    selection:
        # Fields that must match
        CommandLine|contains: 'encoded'
        ParentImage|endswith: '\explorer.exe'
    
    filter:
        # Exclude known good activity
        User|contains: 'SYSTEM'
    
    condition: selection and not filter
```

**Common modifiers:**
- `|contains`: Field contains the value
- `|endswith`: Field ends with value
- `|startswith`: Field starts with value
- `|all`: All values must be present
- `|re`: Regular expression match

### False Positives
List scenarios that might legitimately trigger the rule:
- Specific software or applications
- Administrative activities
- Scheduled tasks or automation
- Known business processes

Be specific! "Legitimate admin activity" is too vague.

### Level
Severity of the detection:
- `low`: Informational, investigate if time permits
- `medium`: Potentially suspicious, worth investigating
- `high`: Likely malicious, investigate promptly
- `critical`: Active compromise, immediate response needed

---

## Complete Example

```yaml
title: Suspicious PowerShell Encoded Command Execution
id: f26c6093-6f14-4b12-800f-0fcb46f5ffd0
status: stable
description: |
    Detects execution of PowerShell with encoded commands, often used by 
    adversaries to obfuscate malicious scripts and evade detection. 
    Encoded commands (-EncodedCommand or -enc) are commonly used in 
    malware droppers, fileless attacks, and post-exploitation frameworks 
    like Empire or Metasploit.
references:
    - https://attack.mitre.org/techniques/T1059/001/
    - https://blog.malwarebytes.com/threat-analysis/2017/03/obfuscation-in-powershell/
author: SOC Analyst (@yourhandle)
date: 2025-02-08
modified: 2025-02-08
tags:
    - attack.execution
    - attack.t1059.001
    - attack.defense_evasion
    - attack.t1027
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\powershell.exe'
        CommandLine|contains:
            - '-enc'
            - '-EncodedCommand'
            - '-e '
    filter_legitimate:
        CommandLine|contains:
            - 'WindowsAzure'
            - 'AzureAD'
    condition: selection and not filter_legitimate
falsepositives:
    - Azure AD Connect scripts
    - Some legitimate administrative scripts
    - Certain monitoring or deployment tools
level: high
```

---

## Testing Your Rule

### 1. Validate Syntax
Use Sigma tools to validate:
```bash
sigma-cli check your-rule.yml
```

### 2. Convert to SIEM Format
```bash
# For Splunk
sigma-cli convert -t splunk your-rule.yml

# For ELK
sigma-cli convert -t elasticsearch your-rule.yml

# For Microsoft Sentinel
sigma-cli convert -t sentinel your-rule.yml
```

### 3. Test with Sample Data
Create test scenarios:
- Generate benign activity that should NOT trigger
- Simulate malicious activity that SHOULD trigger
- Document both test cases

### 4. Tune for False Positives
Run in your environment and:
- Monitor alert volume
- Investigate false positives
- Add filters as needed
- Document tuning changes

---

## Submission Checklist

Before submitting your detection rule:

- [ ] Rule follows the template structure
- [ ] UUID is unique (newly generated)
- [ ] MITRE ATT&CK tags are accurate
- [ ] Description is clear and detailed
- [ ] References include ATT&CK + additional sources
- [ ] Detection logic is well-structured
- [ ] False positives are documented
- [ ] Rule has been tested with sample data
- [ ] Severity level is appropriate
- [ ] File naming follows convention
- [ ] Rule is placed in correct directory

---

## Additional Resources

- [Sigma GitHub Repository](https://github.com/SigmaHQ/sigma)
- [Sigma Specification](https://github.com/SigmaHQ/sigma/wiki/Specification)
- [MITRE ATT&CK](https://attack.mitre.org/)
- [Sigma Rule Creation Guide](https://github.com/SigmaHQ/sigma/wiki/Rule-Creation-Guide)

---

**Questions?** Open an issue or discussion in the repository!
