# HTB Academy — Log Sources & Investigating With Splunk

## Module Overview

This module provides a comprehensive introduction to Splunk as a SIEM tool, covering its architecture, SPL query development, and hands-on security investigation. The module progresses from understanding Splunk's core components to building advanced detection searches and investigating real-world attack scenarios across large datasets.

**Platform:** Hack The Box Academy
**Tool:** Splunk
**Language:** SPL (Search Processing Language)

---

## What I Learned

**Splunk Architecture & Data**
- Splunk's core components and how data flows through the platform
- How to identify available sourcetypes and fields within an unknown dataset
- Why targeted field-specific queries outperform broad wildcard searches in large environments
- How to approach a 500,000+ event dataset systematically from scratch

**SPL Query Development**
- Writing efficient SPL searches targeting specific fields, sourcetypes, and event codes
- Using aggregation commands like `stats`, `eventstats`, `bucket`, and `transaction`
- Extracting and transforming fields using `eval`, `rex`, and `replace`
- Building multi-step queries that progressively filter noise to surface high-fidelity signals

**TTP-Driven Detection**
- Detecting reconnaissance activity via native Windows binaries
- Identifying PsExec usage through registry modifications, file drops, and named pipes
- Detecting payload downloads via PowerShell and browser-based file creation
- Identifying execution from suspicious locations and misspelled legitimate binaries
- Detecting non-standard port communications and archive-based exfiltration

**Analytics-Driven Detection**
- Using statistical outlier detection to flag abnormal cmd.exe execution volume
- Detecting processes loading an unusually high number of DLLs in a short timeframe
- Using the `transaction` command to correlate repeated process execution on the same host
- Identifying abnormally long command lines as an indicator of obfuscation or payload delivery

**Real-World Incident Investigation**
- Tracing an attack chain across multiple hosts using Sysmon and Windows Security logs
- Identifying suspicious parent-child process relationships
- Pivoting from a suspicious IP across multiple sourcetypes to profile an attacker's staging server
- Detecting DCSync attacks using Event ID 4662 and GUID correlation
- Detecting LSASS credential dumping and shellcode via CallTrace UNKNOWN memory regions
- Building an iterative alert that progressively filters false positives

---

## Skills Developed

- Log analysis and threat hunting in Splunk across large multi-host datasets
- Efficient SPL query writing for speed, accuracy, and scalability
- TTP-based detection using Sysmon event IDs
- Statistical anomaly detection using `eventstats`, `stdev`, and `bucket`
- False positive identification and progressive alert tuning
- DCSync and LSASS credential dumping detection
- Shellcode detection via CallTrace analysis
- Alert engineering with real-world applicability

---

## Tools & Data Sources Used

| Tool / Source | Purpose |
|---|---|
| Splunk | Primary SIEM and investigation platform |
| SPL | Query language for searching, filtering, and aggregating log data |
| WinEventLog:Sysmon | Process creation, file creation, network connections, registry, pipes |
| WinEventLog:Security | Logon events, AD object access, privilege use |
| linux:syslog | Linux host identification and network activity |

---

*Completed as part of the Hack The Box Academy SOC Analyst learning path.*
