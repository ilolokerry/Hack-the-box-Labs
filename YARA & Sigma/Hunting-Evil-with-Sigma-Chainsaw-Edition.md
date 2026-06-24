# Hunting Evil with Sigma (Chainsaw Edition)
 
## Objective
 
This section was about applying Sigma rules at speed, without a SIEM in the picture. The tool of choice was **Chainsaw** — a forensic artifact-hunting tool that can load Sigma rules natively and run them against one or many `.evtx` files at once. The idea: when you're racing the clock during an investigation and don't have log aggregation set up, Chainsaw + Sigma lets you scan a pile of Windows Event Logs fast and still get SIEM-quality detection logic out of it.
 
## Lab Setup
 
- Target system spawned via HTB Academy
- Chainsaw binary: `C:\Tools\chainsaw\chainsaw_x86_64-pc-windows-msvc.exe`
- Sigma rules referenced from `C:\Rules\sigma`
- Sample event logs in `C:\Events\YARASigma`
## Walkthrough
 
### Getting Familiar with Chainsaw
 
First step was just running the help menu to see what Chainsaw can do:
 
```powershell
PS C:\Tools\chainsaw> .\chainsaw_x86_64-pc-windows-msvc.exe -h
```
 
The commands that matter most for hunting:
 
| Command | Purpose |
|---|---|
| `hunt` | Run detection rules (Sigma or Chainsaw-native) against artifacts |
| `search` | Keyword search across forensic artifacts |
| `lint` | Validate that rules load correctly before using them |
| `dump` | Convert artifacts to a different format |
 
### Example 1 — Multiple Failed Logins From a Single Source
 
I ran the Sigma rule built in the previous section (`win_security_susp_failed_logons_single_source2.yml`) against `lab_events_2.evtx`, which contains a batch of failed NTLM logon attempts against a `NOUSER` account:
 
```powershell
PS C:\Tools\chainsaw> .\chainsaw_x86_64-pc-windows-msvc.exe hunt C:\Events\YARASigma\lab_events_2.evtx -s C:\Rules\sigma\win_security_susp_failed_logons_single_source2.yml --mapping .\mappings\sigma-event-logs-all.yml
```
 ![2](https://github.com/ilolokerry/Hack-the-box-Labs/blob/c7c698233e0dcb0f8e7567a9f9fd9270b663bf1c/YARA%20%26%20Sigma/media/sigma/hunting%20evil%20with%20sigma%20%2C%20chainsaw/1.png)
 
Chainsaw loaded the rule, scanned the file, and returned a clean detection table — it correctly flagged 5 failed NTLM logins against `NOUSER` from the same workstation (`FS01`). This confirmed the rule from the previous section actually fires correctly when run through a dedicated hunting tool, not just a manual PowerShell filter.
 
### Example 2 — Abnormal PowerShell Command-Line Length (Event ID 4688)
 
This example is about a classic attacker evasion pattern: PowerShell commands get abnormally long when attackers Base64-encode payloads, chain string concatenation, or stuff fragmented variables into a single line to dodge simple keyword detections. The rule used here flags any 4688 (process creation) event with a `CommandLine` of 1000+ characters, where the process is PowerShell, pwsh, or cmd:
 
```yaml
title: Unusually Long PowerShell CommandLine
id: d0d28567-4b9a-45e2-8bbc-fb1b66a1f7f6
status: test
description: Detects unusually long PowerShell command lines with a length of 1000 characters or more
tags:
  - attack.execution
  - attack.t1059.001
  - detection.threat_hunting
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    EventID: 4688
    NewProcessName|endswith:
      - '\powershell.exe'
      - '\pwsh.exe'
      - '\cmd.exe'
  selection_powershell:
    CommandLine|contains:
      - 'powershell.exe'
      - 'pwsh.exe'
  selection_length:
    CommandLine|re: '.{1000,}'
  condition: selection and selection_powershell and selection_length
falsepositives:
  - Unknown
level: low
```
 
**Rule logic, broken down:**
 
- `selection` — must be event 4688, and the new process must be PowerShell, pwsh, or cmd
- `selection_powershell` — the command line itself must reference a PowerShell executable (catches `cmd.exe` spawning PowerShell indirectly)
- `selection_length` — uses a regex (`.{1000,}`) to require 1000+ characters in the command line
- `condition` — all three sections must match together
I ran this against `lab_events_3.evtx`, which contains 4688 events from real abnormally-long PowerShell commands:
 
```powershell
PS C:\Tools\chainsaw> .\chainsaw_x86_64-pc-windows-msvc.exe hunt C:\Events\YARASigma\lab_events_3.evtx -s C:\Rules\sigma\proc_creation_win_powershell_abnormal_commandline_size.yml --mapping .\mappings\sigma-event-logs-all-new.yml
```
 
![2](https://github.com/ilolokerry/Hack-the-box-Labs/blob/c7c698233e0dcb0f8e7567a9f9fd9270b663bf1c/YARA%20%26%20Sigma/media/sigma/hunting%20evil%20with%20sigma%20%2C%20chainsaw/2.png)
![2.2](https://github.com/ilolokerry/Hack-the-box-Labs/blob/c7c698233e0dcb0f8e7567a9f9fd9270b663bf1c/YARA%20%26%20Sigma/media/sigma/hunting%20evil%20with%20sigma%20%2C%20chainsaw/2.2.png)
 
 detections found on 3 documents.All three flagged events contained heavily obfuscated PowerShell — Base64-encoded, GZip-compressed payloads being decoded and executed via `[scriptblock]::create(...)`, launched indirectly through `cmd.exe /b /c start /b /min powershell.exe`. Textbook fileless-malware staging behavior, and the rule (once properly mapped) caught all of it.
 
### Practical Exercise — Hunting Defender Exclusions
 
The section closed with a hands-on check: using the Sigma rule `posh_ps_win_defender_exclusions_added.yml` against `lab_events_5.evtx` to find a suspicious Windows Defender exclusion path that had been added — a common defense-evasion technique where malware adds its own staging directory to Defender's exclusion list so it can operate undetected. Running the hunt surfaced the excluded directory directly in the Sigma rule's match output.
 
![3](https://github.com/ilolokerry/Hack-the-box-Labs/blob/c7c698233e0dcb0f8e7567a9f9fd9270b663bf1c/YARA%20%26%20Sigma/media/sigma/hunting%20evil%20with%20sigma%20%2C%20chainsaw/3.png?)

## Key Takeaways
 - Chainsaw lets you run real Sigma rules against log files directly, no SIEM needed — great for fast checks.
- The same rule can work across different tools, which is why Sigma is built to be reusable, not tied to one system.
- Always test a rule against a real log file to confirm it works, instead of just trusting that the YAML looks correct.
Small details, like which field a rule checks or what counts as "suspicious," can decide whether an attack gets caught or missed.
## Conclusion
 
This section reinforced that Sigma rules are only half the story — the tool you run them through, and how that tool maps fields, determines whether your detection logic actually works in practice. Getting a rule to silently fail (0 detections) and having to debug *why* was a more valuable exercise than if everything had just worked first try — it's exactly the kind of troubleshooting I'd expect to run into doing real SIEM/EDR tuning work.
