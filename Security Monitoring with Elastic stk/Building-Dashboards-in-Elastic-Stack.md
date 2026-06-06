# Building Dashboards in Elastic Stack

## Overview

This document covers the four SIEM dashboards I built in Kibana as part of the Security Monitoring & SIEM Fundamentals module. Each dashboard targets a specific detection use case based on Windows Event Logs.

---

## Dashboard 1 — Failed Logon Attempts (All Users)

**Detection Goal:** Identify users generating failed logon attempts across the environment.

**Event ID:** `4625` — An account failed to log on

**Filters applied:**
- `event.code: 4625`
- Excluded computer accounts: `NOT user.name: *$`
- Excluded noise accounts: `WIN-OK9BH1BCKSD`, `WIN-RMMGJA7T9TC`, `DESKTOP-DPOESND`
- Channel filter: `winlog.channel.keyword: Security`

**KQL Query:**
```kql
NOT user.name: *$ AND winlog.channel.keyword: Security
```

**Fields displayed:**

| Column | Field |
|---|---|
| Username | `user.name.keyword` |
| Event Logged By | `host.hostname.keyword` |
| Logon Type | `winlog.logon.type.keyword` |
| # of Logins | Count of records |

<!-- Add screenshot here -->
![Dashboard 1](./screenshots/dashboard1_failed_logons.png)

---

## Dashboard 2 — Failed Logon Attempts (Disabled Users)

**Detection Goal:** Identify failed login attempts targeting disabled accounts. A disabled account can never log in successfully — any attempt may indicate credential stuffing or an attacker using stale credentials.

**Event ID:** `4625` — An account failed to log on
**SubStatus:** `0xC0000072` — Account is disabled

**Filters applied:**
- `event.code: 4625`
- `winlog.event_data.SubStatus: 0xC0000072`

**Fields displayed:**

| Column | Field |
|---|---|
| Username | `user.name.keyword` |
| Event Logged By | `host.hostname.keyword` |
| # of Logins | Count of records |

<!-- Add screenshot here -->
![Dashboard 2](./screenshots/dashboard2_disabled_users.png)

---

## Dashboard 3 — Successful RDP Logon by Service Accounts

**Detection Goal:** Detect successful RDP logons using service accounts. Service accounts are not used for interactive RDP sessions in normal operations — any such logon is suspicious.

**Event ID:** `4624` — An account was successfully logged on
**Logon Type:** `RemoteInteractive` (RDP)

**Filters applied:**
- `event.code: 4624`
- `winlog.logon.type: RemoteInteractive`

**KQL Query:**
```kql
user.name: svc-*
```

**Fields displayed:**

| Column | Field |
|---|---|
| Username | `user.name.keyword` |
| Event Logged By | `host.hostname.keyword` |
| Source IP | `related.ip.keyword` |
| # of Logins | Count of records |

<!-- Add screenshot here -->
![Dashboard 3](./screenshots/dashboard3_svc_rdp.png)

---

## Dashboard 4 — Users Added or Removed from Local Administrators Group

**Detection Goal:** Monitor changes to the local Administrators group. Unauthorized additions are a common persistence and privilege escalation technique.

**Event IDs:**
- `4732` — A member was added to a security-enabled local group
- `4733` — A member was removed from a security-enabled local group

**Filters applied:**
- `event.code: 4732 or 4733`
- `group.name: administrators`
- Timeframe: March 5, 2023 to present

**Fields displayed:**

| Column | Field |
|---|---|
| Username | `user.name.keyword` |
| Member SID | `winlog.event_data.MemberSid.keyword` |
| Group Name | `group.name.keyword` |
| Action | `event.action.keyword` |
| Host | `host.name.keyword` |
| Count | Count of records |

<!-- Add screenshot here -->
![Dashboard 4](./screenshots/dashboard4_admin_group.png)

---

## Full SOC-Alerts Dashboard

<!-- Add full dashboard screenshot here -->
![Full Dashboard](./screenshots/full_dashboard.png)

---

## Key Notes

- Always use `.keyword` fields for aggregations in Elastic (e.g. `user.name.keyword` not `user.name`)
- `NOT user.name: *$` filters out computer accounts from logon visualizations
- SubStatus `0xC0000072` in Event ID 4625 specifically indicates a disabled account logon attempt
- Service account RDP logons are a high-fidelity detection signal and should never occur in normal operations
- Individual panel timeframes can be customized without affecting the rest of the dashboard

---

*Completed as part of the Hack The Box Academy SOC Analyst learning path.*
