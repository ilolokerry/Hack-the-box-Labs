# HTB Academy — Introduction to Threat Hunting & Hunting With Elastic

## Module Overview

This module builds a solid foundation in Threat Hunting, covering core concepts, team structure, and the threat hunting process. It also covers Cyber Threat Intelligence (CTI) fundamentals and concludes with a practical threat hunting exercise using the Elastic Stack with real-world logs and threat intelligence reports.

**Platform:** Hack The Box Academy
**Tools:** Elastic Stack (Kibana), Zeek, Windows Sysmon

---

## What I Learned

**Threat Hunting Fundamentals**
- Definition and purpose of threat hunting in a SOC environment
- Structure of a threat hunting team and roles within it
- The threat hunting process and how it differs from reactive incident response
- The relationship between threat hunting, risk assessment, and incident handling

**Cyber Threat Intelligence (CTI)**
- Types of threat intelligence — strategic, tactical, operational, and technical
- How to read and interpret a threat intelligence report effectively
- Extracting and applying IOCs from threat intel to an active hunt

**Practical Threat Hunting with Elastic Stack**
- Querying Windows Sysmon logs, PowerShell logs, and Zeek network logs using KQL
- Pivoting across log sources to reconstruct a full attack chain
- Correlating threat intel IOCs against live environment logs to confirm compromise

---

## Skills Developed

- Threat hunting using a hypothesis-driven approach
- Reading and applying real-world threat intelligence reports
- Log analysis and correlation across multiple data sources
- Network traffic analysis using Zeek
- KQL query development for threat detection

---

## Tools Used

| Tool | Purpose |
|---|---|
| Elastic Stack (Kibana) | Primary SIEM and log analysis platform |
| Windows Sysmon | Process creation, file creation, network connection logs |
| Zeek | DNS and network traffic analysis |
| KQL | Query language for searching and filtering log data |

---

## Practical Work

| File | Description |
|---|---|
| [`Stuxbot_Threat_Hunt.md`](./Stuxbot_Threat_Hunt.md) | Full threat hunt investigation based on the Stuxbot threat intelligence report |

---

*Completed as part of the Hack The Box Academy SOC Analyst learning path.*
