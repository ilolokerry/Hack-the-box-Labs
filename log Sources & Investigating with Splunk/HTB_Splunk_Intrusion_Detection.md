# HTB Academy — Intrusion Detection With Splunk (Real-World Scenario)

## Overview

This module scales up from single-machine log analysis to network-wide intrusion detection using Splunk as the SIEM. Working with over 500,000 events across multiple hosts and sourcetypes, the focus is on crafting efficient queries, identifying attacks, eliminating false positives, and building meaningful alerts.

**Platform:** Hack The Box Academy
**Tool:** Splunk
**Dataset:** 500,000+ events across 5 machines
**Data Sources:** `WinEventLog:Sysmon`, `WinEventLog:Security`, `linux:syslog`

---

## What I Did

### Explored the Dataset

Listed all available sourcetypes to understand the environment from scratch:

```spl
index="main" | stats count by sourcetype
```

Identified all Sysmon EventCodes present in the data:

```spl
index="main" sourcetype="WinEventLog:Sysmon" | stats count by EventCode
```

Found 20 distinct EventCodes. Reviewed each one to understand its detection value before building queries.

![sourcetype](https://github.com/ilolokerry/Hack-the-box-Labs/blob/c95a1cdd829db25c15ac8b54ac61db71d0b93695/log%20Sources%20%26%20Investigating%20with%20Splunk/media/source%20type.png)
---

### Learned Efficient Query Writing

Tested three approaches to understand the performance impact of query design:

```spl
index="main" uniwaldo.local
```
> Searches all fields across all sourcetypes. Fast for exact strings but returns everything.

```spl
index="main" *uniwaldo.local*
```
> Leading wildcard forces a full scan across all events — significantly slower even with the same number of results.

```spl
index="main" ComputerName="*uniwaldo.local"
```
> Targets a specific field — much faster, less resource-intensive, and filters out irrelevant data immediately.

The field-targeted query was significantly faster. This reinforced the importance of targeted queries in large environments — especially when converting hunts into scheduled alerts.

---

### Hunted for Malicious Parent-Child Process Relationships

Queried all parent-child process trees using Sysmon Event ID 1:

```spl
index="main" sourcetype="WinEventLog:Sysmon" EventCode=1 | stats count by ParentImage, Image
```
> Returns 5,427 results — too many to sift through manually. Narrowed down to high-risk child processes.
![parent](https://github.com/ilolokerry/Hack-the-box-Labs/blob/c95a1cdd829db25c15ac8b54ac61db71d0b93695/log%20Sources%20%26%20Investigating%20with%20Splunk/media/parent.png)

Narrowed to high-risk child processes:

```spl
index="main" sourcetype="WinEventLog:Sysmon" EventCode=1 (Image="*cmd.exe" OR Image="*powershell.exe") | stats count by ParentImage, Image
```
> cmd.exe and powershell.exe are commonly abused by attackers. Filtering for these as child processes immediately surfaces suspicious chains.
![cmd](https://github.com/ilolokerry/Hack-the-box-Labs/blob/c95a1cdd829db25c15ac8b54ac61db71d0b93695/log%20Sources%20%26%20Investigating%20with%20Splunk/media/cmd%20or%20poweeshell.png)

Drilled into the suspicious chain:

```spl
index="main" sourcetype="WinEventLog:Sysmon" EventCode=1 (Image="*cmd.exe" OR Image="*powershell.exe") ParentImage="C:\\Windows\\System32\\notepad.exe"
```
> notepad.exe has no legitimate reason to spawn powershell.exe. This is a strong indicator of process injection or a malicious file masquerading as a text file.

**Finding:** `notepad.exe` (with no arguments) triggered `powershell.exe` downloading a file from `10[.]0[.]0[.]229:8080`.

![notepad](https://github.com/ilolokerry/Hack-the-box-Labs/blob/9aec7af3c92d2b84d9007ca309ca9e4f30b13a14/log%20Sources%20%26%20Investigating%20with%20Splunk/media/nmotepad.png)
![notepad2](https://github.com/ilolokerry/Hack-the-box-Labs/blob/9aec7af3c92d2b84d9007ca309ca9e4f30b13a14/log%20Sources%20%26%20Investigating%20with%20Splunk/media/notepad2.png)
---

### Pivoted on Suspicious IP `10[.]0[.]0[.]229`

Queried all sourcetypes referencing the suspicious IP:

```spl
index="main" 10.0.0.229 | stats count by sourcetype
```
> Shows which log sources have seen this IP — helps decide where to investigate next.
![one](https://github.com/ilolokerry/Hack-the-box-Labs/blob/9aec7af3c92d2b84d9007ca309ca9e4f30b13a14/log%20Sources%20%26%20Investigating%20with%20Splunk/media/10%20one.png)
Checked Linux syslog for more context:

```spl
index="main" 10.0.0.229 sourcetype="linux:syslog"
```
> Linux syslog can reveal the hostname and interface associated with an IP, helping confirm whether this is a known or unknown host.
![two](https://github.com/ilolokerry/Hack-the-box-Labs/blob/492230473827a6d25ed22e296ebab128ddba811d/log%20Sources%20%26%20Investigating%20with%20Splunk/media/10%20two.png)

**Finding:** IP belongs to `waldo-virtual-machine` on interface `ens160` — a Linux host likely compromised and being used as a staging server for delivering tools.

Checked all commands being executed referencing this IP:

```spl
index="main" 10.0.0.229 sourcetype="WinEventLog:sysmon" | stats count by CommandLine
```
![three](https://github.com/ilolokerry/Hack-the-box-Labs/blob/492230473827a6d25ed22e296ebab128ddba811d/log%20Sources%20%26%20Investigating%20with%20Splunk/media/10%20three.png)
> Aggregating by CommandLine reveals the full picture of what was downloaded and executed from this host across the environment.

**Finding:** Multiple binaries with clearly malicious names being downloaded and executed via PowerShell and PsExec64.

Identified affected hosts:

```spl
index="main" 10.0.0.229 sourcetype="WinEventLog:sysmon" | stats count by CommandLine, host
```
> Adding host to the aggregation shows which machines were impacted and whether the same commands ran on multiple hosts.

![four](https://github.com/ilolokerry/Hack-the-box-Labs/blob/492230473827a6d25ed22e296ebab128ddba811d/log%20Sources%20%26%20Investigating%20with%20Splunk/media/10%20four.png)

**Finding:** Two hosts compromised — `DESKTOP-EGSS5IS` and `DESKTOP-UN7T4R8`. A DCSync PowerShell script was executed on the second host.

---

### Detected DCSync Attack

Validated the DCSync suspicion with a targeted query:

```spl
index="main" EventCode=4662 Access_Mask=0x100 Account_Name!=*$
```

> - `EventCode=4662` fires when an AD object is accessed — disabled by default and must be enabled on the DC
> - `Access_Mask=0x100` is the Control Access right specifically required for DCSync operations
> - `Account_Name!=*$` filters out legitimate machine account replication — DCSync should only be performed by machine accounts or SYSTEM, not regular users

![dsyncone](https://github.com/ilolokerry/Hack-the-box-Labs/blob/94a286767d79cf57e1e5985604e99ccd5a9bd31a/log%20Sources%20%26%20Investigating%20with%20Splunk/media/dcsynce%20one.png)
![dsync](https://github.com/ilolokerry/Hack-the-box-Labs/blob/94a286767d79cf57e1e5985604e99ccd5a9bd31a/log%20Sources%20%26%20Investigating%20with%20Splunk/media/dcsync.png)
![one](https://github.com/ilolokerry/Hack-the-box-Labs/blob/94a286767d79cf57e1e5985604e99ccd5a9bd31a/log%20Sources%20%26%20Investigating%20with%20Splunk/media/19.png)
![two](https://github.com/ilolokerry/Hack-the-box-Labs/blob/94a286767d79cf57e1e5985604e99ccd5a9bd31a/log%20Sources%20%26%20Investigating%20with%20Splunk/media/21.png)
![three](https://github.com/ilolokerry/Hack-the-box-Labs/blob/94a286767d79cf57e1e5985604e99ccd5a9bd31a/log%20Sources%20%26%20Investigating%20with%20Splunk/media/22.png)
**Finding:** User `waldo` on the `UNIWALDO` domain accessed AD objects with GUIDs matching `DS-Replication-Get-Changes-All` — confirming a successful DCSync attack and full domain credential dump. `krbtgt` rotation recommended in case a Golden Ticket was created.

---

### Detected LSASS Credential Dumping

Queried Sysmon Event ID 10 (ProcessAccess) to find processes opening handles to `lsass.exe`:

```spl
index="main" EventCode=10 lsass | stats count by SourceImage
```
> Sorting by count helps distinguish normal frequent processes from rare suspicious ones. Low-count entries are worth investigating first.
![lsaaone](https://github.com/ilolokerry/Hack-the-box-Labs/blob/94a286767d79cf57e1e5985604e99ccd5a9bd31a/log%20Sources%20%26%20Investigating%20with%20Splunk/media/lass%201.png)
Investigated the suspicious result:

```spl
index="main" EventCode=10 lsass SourceImage="C:\\Windows\\System32\\notepad.exe"
```
> notepad.exe has no legitimate reason to open a handle to lsass.exe. This is a textbook indicator of process injection being used for credential dumping.

**Finding:** CallTrace showed API calls originating from `UNKNOWN` memory regions — shellcode executing from unbacked memory not mapped to any file on disk.

<!-- Add screenshot here -->
![LSASS Access by Notepad](./screenshots/lsass_notepad.png)

---

### Built a Shellcode Detection Alert

Developed a multi-step Splunk alert to detect process access events where calls originate from UNKNOWN memory regions, progressively filtering known false positives.

**Step 1 — Identify which EventCodes have UNKNOWN CallTrace:**
```spl
index="main" CallTrace="*UNKNOWN*" | stats count by EventCode
```
> Confirms that only EventCode 10 (ProcessAccess) contains UNKNOWN entries — so the alert will specifically target process handle access events.

**Step 2 — Group by SourceImage:**
```spl
index="main" CallTrace="*UNKNOWN*" | stats count by SourceImage
```
> Shows which processes are making calls from unknown memory regions. Reveals 1,575 events — too many without filtering.

**Step 3 — Filter self-accessing processes:**
```spl
index="main" CallTrace="*UNKNOWN*" | where SourceImage!=TargetImage | stats count by SourceImage
```
> A process accessing itself is generally not a concern. Removing self-access reduces noise without affecting detection of cross-process shellcode.

**Step 4 — Exclude .NET JIT false positives:**
```spl
index="main" CallTrace="*UNKNOWN*" SourceImage!="*Microsoft.NET*" CallTrace!=*ni.dll* CallTrace!=*clr.dll* | where SourceImage!=TargetImage | stats count by SourceImage
```
> .NET is a Just-In-Time (JIT) compiler — it legitimately generates code in memory at runtime that does not map to disk. These are expected UNKNOWN entries and not malicious.

**Step 5 — Exclude WOW64 (Heaven's Gate mechanism):**
```spl
index="main" CallTrace="*UNKNOWN*" SourceImage!="*Microsoft.NET*" CallTrace!=*ni.dll* CallTrace!=*clr.dll* CallTrace!=*wow64* | where SourceImage!=TargetImage | stats count by SourceImage
```
> WOW64 is the Windows subsystem that allows 32-bit applications to run on 64-bit Windows. It often contains memory regions not backed by a file — these are largely benign and linked to the Heaven's Gate mechanism.

**Step 6 — Exclude Explorer.exe:**
```spl
index="main" CallTrace="*UNKNOWN*" SourceImage!="*Microsoft.NET*" CallTrace!=*ni.dll* CallTrace!=*clr.dll* CallTrace!=*wow64* SourceImage!="C:\\Windows\\Explorer.EXE" | where SourceImage!=TargetImage | stats count by SourceImage
```
> Explorer.exe performs a huge range of legitimate tasks and is extremely difficult to validate UNKNOWN entries for. Excluding it avoids a major source of false positives while keeping the alert high-fidelity.

**Final alert with full context:**
```spl
index="main" CallTrace="*UNKNOWN*" SourceImage!="*Microsoft.NET*" CallTrace!=*ni.dll* CallTrace!=*clr.dll* CallTrace!=*wow64* SourceImage!="C:\\Windows\\Explorer.EXE" | where SourceImage!=TargetImage | stats count by SourceImage, TargetImage, CallTrace
```
> Adding TargetImage and CallTrace to the output provides full context for each alert — showing exactly what was accessed and from where, making triage faster and more accurate.

<!-- Add screenshot here -->
![Final Alert Query Results](./screenshots/final_alert.png)

---

## Key Sysmon Event IDs Referenced

| Event ID | Description | Used For |
|---|---|---|
| 1 | Process Creation | Parent-child anomaly detection |
| 10 | ProcessAccess | LSASS dumping, shellcode detection |
| 4662 | AD Object Access | DCSync attack detection |

---

## What I Learned

- How to approach a large unknown dataset systematically — listing sourcetypes and EventCodes first before building queries
- Why targeted field-specific queries are significantly faster than wildcard searches and matter at scale
- How to identify suspicious parent-child process relationships using Sysmon Event ID 1
- How to pivot from a suspicious IP across multiple sourcetypes to profile an attacker's staging server
- How DCSync attacks are detected using Event ID 4662, Access Mask `0x100`, and GUID lookups against Microsoft documentation
- How shellcode executing from unbacked memory appears as `UNKNOWN` in Sysmon Event ID 10 CallTrace
- How to build a detection alert iteratively by layering exclusions to reduce false positives without sacrificing detection fidelity
- How to think critically about alert bypass — and what makes an alert robust vs easily circumvented

---

## Skills Developed

- Large-scale log analysis and threat hunting in Splunk
- Efficient SPL query writing for performance and accuracy
- False positive identification and progressive filtering
- DCSync attack detection
- LSASS credential dumping detection via ProcessAccess events
- Shellcode detection through CallTrace analysis
- Alert engineering with iterative false positive reduction

---

*Completed as part of the Hack The Box Academy SOC Analyst learning path.*
