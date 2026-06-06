# Security Monitoring & SIEM Fundamentals — HTB Academy

## Overview

This repository documents my completion of the Security Monitoring & SIEM Fundamentals module on Hack The Box Academy. The module provided a practical introduction to SIEM concepts, SOC operations, and hands-on experience building detection use cases and dashboards using the Elastic Stack.

---

## What I Learned

**SIEM & Elastic Stack**
- How SIEM solutions collect, normalize, and correlate security event data across an environment
- The architecture of the Elastic Stack (Elasticsearch, Logstash, Kibana) and how it is used in SOC environments
- How to query security data using KQL (Kibana Query Language)

**SOC Operations**
- The structure and function of a Security Operations Center
- How analysts triage and investigate alerts
- How dashboards and visualizations support real-time security monitoring

**MITRE ATT&CK in SOC Workflows**
- How the MITRE ATT&CK framework is applied to map detections to known adversary techniques
- Using ATT&CK to prioritize use cases and build detection coverage

**SIEM Use Case Development**
- Building detection logic around specific Windows Event IDs
- Filtering, refining, and tuning visualizations to reduce noise
- Developing use cases for common attack patterns including failed logons, disabled account abuse, service account misuse, and privilege escalation

---

## Practical Work

| File | Description |
|---|---|
| `Building-Dashboards-in-Elastic-Stack.md` | Step-by-step breakdown of 4 SIEM dashboards built in Elastic |

---

## Tools Used

- Elastic Stack (Kibana)
- KQL (Kibana Query Language)
- Windows Event Logs

![kibana](https://github.com/ilolokerry/Hack-the-box-Labs/blob/5d29a040435ef4c2be48ab71f79bec670b6db571/Security%20Monitoring%20with%20Elastic%20stk/images/elastic.png)
![beats](https://github.com/ilolokerry/Hack-the-box-Labs/blob/5d29a040435ef4c2be48ab71f79bec670b6db571/Security%20Monitoring%20with%20Elastic%20stk/images/beats1.png)
![discover](https://github.com/ilolokerry/Hack-the-box-Labs/blob/5d29a040435ef4c2be48ab71f79bec670b6db571/Security%20Monitoring%20with%20Elastic%20stk/images/discover.png)
---

*Completed as part of the Hack The Box Academy SOC Analyst learning path.*
