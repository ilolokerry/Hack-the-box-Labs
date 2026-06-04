# HTB SOC Analyst Lab — Analysis of Insight Nexus Breach

## Scenario

Insight Nexus, a market research firm based in Singapore, was compromised by two threat actor groups simultaneously.

**Crimson Fox** (primary actor) gained initial access through default credentials (`admin/admin`) left unchanged on an internet-facing ManageEngine ADManager Plus instance. From there they established a C2 channel, performed Active Directory enumeration, created a privileged domain account, pivoted via RDP into a misconfigured workstation (DEV-021), and deployed spyware across the domain using a GPO-pushed MSI package. They also exfiltrated sensitive client data.

**Silent Jackal** (secondary actor) exploited an unpatched file upload vulnerability in a PHP-based client reporting portal, uploading a marker file (`checkme.txt`) to signal their presence. Their activity was limited to this initial access.

The incident went undetected for several days due to alert fatigue. It was first discovered when a SOC analyst noticed the `checkme.txt` file and began correlating related alerts in the SIEM.

---

## Environment & Important Assets

| Asset | Hostname / URL | Role |
|---|---|---|
| ManageEngine Portal | `manage.insightnexus.com` | Internet-facing AD management (HTTPS port 443) |
| PHP Client Portal | `portal.insightnexus.com` | Client reporting portal with file upload enabled |
| Domain Controller | `DC01.insight.local` | Active Directory domain controller |
| File Server | `FS01.insight.local` | Project file shares (`\\fs01\projects`) |
| Database Server | `DB01.insight.local` | Sensitive client databases |
| Developer Workstation | `DEV-021` | Misconfigured — publicly exposed RDP port |
| ManageEngine Host | `SRV-MANAGE01` | Internal host running ManageEngine |

**Security tooling in place:**
- Perimeter firewall with default logging (no threat intelligence integration)
- Basic IDS with a high false-positive rate
- Wazuh agents on most Windows hosts (partial coverage)
- Centralized SIEM ingesting Sysmon, Windows Security, web server, and firewall logs
- TheHive for case management with Cortex available for enrichment

<!-- Add network diagram image here -->
![Network Diagram](./network_diagram.png)

---

## Incident Response Summary

Once the SOC analyst correlated the `checkme.txt` alert with ManageEngine outbound traffic and foreign IP logins, the incident was escalated and a TheHive case was opened. The following key actions were taken:

- **Case triage:** All related alerts were linked in TheHive and roles were assigned. Priority set to Critical due to confirmed data exfiltration.
- **Network containment:** Outbound traffic to `103.112.60.117` was blocked at the perimeter and host-based firewalls. An IDS signature was added for the attacker IP.
- **Credential actions:** The ManageEngine admin account was disabled, high-privilege credentials were rotated, and active sessions were revoked. The ManageEngine console was restricted to internal access only.
- **Host isolation:** `SRV-MANAGE01`, `DEV-021`, and any hosts showing MSI installation evidence were isolated from the network for forensic analysis.
- **Forensic collection:** Volatile memory, process lists, registry hives, and disk images were collected from isolated hosts. Copies of `java-update.msi`, `diagnostics_data.zip`, and any web shell files were preserved.

---

## Investigation Questions & Answers

---

### Question 1 — Credential Dumping

**What is the full path of the parent process that executed a credential dumping tool? (Event ID 4688)**

**Answer:** `C:\Program Files\Mozilla Firefox\firefox.exe`

Mimikatz was executed on `SRV-MANAGE01` under the Administrator account. The parent process was Firefox, indicating the attacker downloaded and launched the tool directly from the browser.

**Log Evidence:**

```json
{
  "agent": { "name": "SRV-MANAGE01", "ip": "172.16.50.20" },
  "timestamp": "2025-10-09T03:10:19.102140Z",
  "rule": {
    "level": 10,
    "description": "Possible credential dumping detected",
    "id": "90001"
  },
  "data": {
    "win": {
      "system": { "eventID": "4688" },
      "eventdata": {
        "subjectUserName": "Administrator",
        "newProcessName": "C:\\Users\\Administrator\\Downloads\\mimikatz.exe",
        "parentProcessName": "C:\\Program Files\\Mozilla Firefox\\firefox.exe",
        "subjectDomainName": "INSIGHT"
      }
    }
  }
}
```

---

### Question 2 — Persistence on DB01

**What is the imagePath value for the persistence mechanism on DB01?**

**Answer:** `C:\Windows\PSEXESVC.exe`

A new service named `PSEXESVC` was installed on `DB01` (Event ID 7045). This is the service component of PsExec, a tool commonly abused by attackers for remote execution and lateral movement.

**Log Evidence:**

```json
{
  "agent": { "name": "DB01", "ip": "172.16.30.17" },
  "timestamp": "2025-10-09T04:28:42.102140Z",
  "rule": {
    "level": 8,
    "description": "New Windows service installed",
    "id": "90008"
  },
  "data": {
    "win": {
      "system": { "eventID": "7045" },
      "eventdata": {
        "serviceName": "PSEXESVC",
        "imagePath": "C:\\Windows\\PSEXESVC.exe",
        "user": "SYSTEM"
      }
    }
  }
}
```

---

### Question 3 — Exfiltration

**What is the external IP address that diagnostics_data.zip was uploaded to?**

**Answer:** `93.184.216.34`

The attacker used a binary named `updater.exe` running as `insight\svc_deployer` on `SRV-MANAGE01` to upload `diagnostics_data.zip` to an external IP over HTTPS port 443. The filename was chosen to resemble routine telemetry to avoid detection.

**Log Evidence:**

```json
{
  "agent": { "name": "SRV-MANAGE01", "ip": "172.16.50.20" },
  "timestamp": "2025-10-09T05:33:58.102140Z",
  "rule": {
    "level": 9,
    "description": "Large outbound HTTPS POST with filename diagnostics_data.zip",
    "id": "90004"
  },
  "data": {
    "win": {
      "system": { "eventID": "3" },
      "eventdata": {
        "image": "C:\\Users\\svc_deployer\\AppData\\Roaming\\updater.exe",
        "destinationIp": "93.184.216.34",
        "destinationPort": "443",
        "user": "insight\\svc_deployer",
        "details": "HTTP POST /upload diagnostics_data.zip"
      }
    }
  }
}
```

---

### Question 4 — File Share Access

**Which user tried to connect to the file share `\\fs01\projects`?**

**Answer:** `svc_admin`

A Sysmon network connection (Event ID 3) captured an SMB connection from `172.16.200.50` to `FS01` on port 445 targeting the `\\fs01\projects` share, made under the `svc_admin` account.

**Log Evidence:**

```json
{
  "agent": { "name": "DB01", "ip": "172.16.30.17" },
  "timestamp": "2025-10-08T08:58:37.102140Z",
  "rule": {
    "level": 8,
    "description": "Possible suspicious access to Windows admin shares",
    "id": "92105"
  },
  "data": {
    "win": {
      "system": { "eventID": "3" },
      "eventdata": {
        "image": "C:\\Windows\\System32\\svchost.exe",
        "sourceIp": "172.16.200.50",
        "destinationIp": "172.16.10.20",
        "destinationPort": "445",
        "user": "svc_admin",
        "details": "SMB connect to \\\\fs01\\projects"
      }
    }
  }
}
```

---

*Completed as part of the Hack The Box SOC Analyst learning path.*
