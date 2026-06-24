# YARA & Sigma for SOC Analysts — HTB Academy

## Module Description

This Hack The Box Academy module covers how to create YARA rules both manually and automatically, and apply them to hunt threats on disk, live processes, memory, and online databases. The module then shifts focus to Sigma rules — covering how to build Sigma rules, translate them into SIEM queries using `sigmac`, and hunt threats in both event logs and SIEM solutions. The entire module is hands-on, working against real-world malware and attacker techniques.

## Module Summary

The module opens by explaining why YARA and Sigma rules are essential tools for any SOC role. It breaks down YARA's rule anatomy and walks through building rules both manually and automatically, then applies those rules across multiple environments: scanning directories, live Windows processes, memory images, and online malware databases.

From there, the module pivots to Sigma — covering its rule structure, manual rule creation, and how to translate Sigma rules into SIEM-ready search queries using the `sigmac` utility. The end goal is being able to hunt for threats in both raw event logs and a full SIEM setup using Sigma detections.

## What's in This Repo

[`Developing-YARA-Rules.md`](./Developing-YARA-Rules.md)<br>
[`Hunting-Evil-with-YARA-Windows-and-Linux.md`](./Hunting-Evil-with-YARA-Windows-and-Linux.md) <br>
[`Developing-Sigma-Rules.md`](./Developing-Sigma-Rules.md) <br>
[`Hunting-Evil-with-Sigma-Chainsaw-Edition.md`](./Hunting-Evil-with-Sigma-Chainsaw-Edition.md) <br>
## Module Conclusion

Completing the YARA & Sigma for SOC Analysts module covered:

- The benefits of YARA and Sigma rules for enhanced SOC capabilities
- The structure and development process of YARA rules, both manual and automated
- Applying YARA rules across various environments: directories, live processes, memory dumps, and online malware repositories
- Sigma rule structure and manual rule creation
- Hands-on experience translating Sigma rules into SIEM queries using `sigmac`
- Hunting for threats in event logs and SIEM, leveraging Sigma rules
- Hands-on experience applying YARA and Sigma rules to detect real-world malware and attack techniques

## Tools Covered

- YARA
- Sigma / `sigmac`
- Chainsaw
- Zircolite (referenced)
- Sysmon event analysis
