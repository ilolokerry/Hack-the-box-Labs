# Hunting Evil with Sigma (Chainsaw Edition)

**Module:** YARA & Sigma for SOC Analysts (HTB Academy)
**Section:** 9 / 11

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

[SCREENSHOT: Chainsaw `-h` help menu and banner]

The commands that matter most for hunting:

| Command | Purpose |
|---|---|
| `hunt` | Run detection rules (Sigma or Chainsaw-native) against artifacts |
| `search` | Keyword search across forensic artifacts |
| `lint` | Validate that rules load correctly before using them |
| `dump` | Convert artifacts to a different format |

A couple of example syntaxes from the help output that I expect to reuse a lot:

```bash
./chainsaw hunt evtx_attack_samples/ -s sigma/ --mapping mappings/sigma-event-logs-all.yml -r rules/
./chainsaw search mimikatz -i evtx_attack_samples/
./chainsaw search -t 'Event.System.EventID: =4104' evtx_attack_samples/
```

The `-s` flag points Chainsaw at a Sigma rule (or a directory of them), and `--mapping` tells it which field names in the raw event log correspond to the field names the Sigma rule expects.

### Example 1 — Multiple Failed Logins From a Single Source

I ran the Sigma rule built in the previous section (`win_security_susp_failed_logons_single_source2.yml`) against `lab_events_2.evtx`, which contains a batch of failed NTLM logon attempts against a `NOUSER` account:

```powershell
PS C:\Tools\chainsaw> .\chainsaw_x86_64-pc-windows-msvc.exe hunt C:\Events\YARASigma\lab_events_2.evtx -s C:\Rules\sigma\win_security_susp_failed_logons_single_source2.yml --mapping .\mappings\sigma-event-logs-all.yml
```

[SCREENSHOT: Chainsaw output table showing 5 flagged failed NTLM logins against `NOUSER`]

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
PS C:\Tools\chainsaw> .\chainsaw_x86_64-pc-windows-msvc.exe hunt C:\Events\YARASigma\lab_events_3.evtx -s C:\Rules\sigma\proc_creation_win_powershell_abnormal_commandline_size.yml --mapping .\mappings\sigma-event-logs-all.yml
```

[SCREENSHOT: Chainsaw output showing "0 Detections found" with the original mapping file]

Result: **0 detections.** At first that looked like the Sigma rule was broken — but the actual problem was the mapping file. Chainsaw's `sigma-event-logs-all.yml` mapping didn't have an entry for `NewProcessName`, so the field the rule depends on was never being matched against the raw event log at all.

This was the most important lesson of the whole section for me: **a Sigma rule failing to fire doesn't necessarily mean the rule is wrong — it might mean the tool running it doesn't know how to map the rule's fields to the actual log fields.** Sigma rules are meant to be portable across SIEMs, but that portability depends entirely on correct field mapping in whatever backend is consuming them.

Using a corrected mapping file (`sigma-event-logs-all-new.yml`, which included `NewProcessName`), I re-ran the same hunt:

```powershell
PS C:\Tools\chainsaw> .\chainsaw_x86_64-pc-windows-msvc.exe hunt C:\Events\YARASigma\lab_events_3.evtx -s C:\Rules\sigma\proc_creation_win_powershell_abnormal_commandline_size.yml --mapping .\mappings\sigma-event-logs-all-new.yml
```

[SCREENSHOT: Chainsaw output showing "3 Detections found on 3 documents" with the corrected mapping file, including the decoded PowerShell command lines]

This time: **3 detections found on 3 documents.** All three flagged events contained heavily obfuscated PowerShell — Base64-encoded, GZip-compressed payloads being decoded and executed via `[scriptblock]::create(...)`, launched indirectly through `cmd.exe /b /c start /b /min powershell.exe`. Textbook fileless-malware staging behavior, and the rule (once properly mapped) caught all of it.

### Practical Exercise — Hunting Defender Exclusions

The section closed with a hands-on check: using the Sigma rule `posh_ps_win_defender_exclusions_added.yml` against `lab_events_5.evtx` to find a suspicious Windows Defender exclusion path that had been added — a common defense-evasion technique where malware adds its own staging directory to Defender's exclusion list so it can operate undetected. Running the hunt surfaced the excluded directory directly in the Sigma rule's match output.

## Key Takeaways

- Chainsaw lets you apply real Sigma logic against raw `.evtx` files without needing a SIEM pipeline — genuinely useful for fast, on-the-spot triage during an investigation.
- Mapping files matter just as much as the rule itself. A "0 detections" result is not proof a rule is broken — it's a prompt to check whether the tool is actually reading the fields the rule depends on.
- Multi-file, multi-rule hunts (`-s` pointed at a directory) make Chainsaw scale well beyond single-file manual checks, which is the whole point when you're dealing with a pile of logs and limited time.
- Obfuscated/encoded PowerShell command lines are a strong, fairly reliable signal once you can detect on length + executable + content — this is a pattern I'll be looking for again outside of this lab.

## Conclusion

This section reinforced that Sigma rules are only half the story — the tool you run them through, and how that tool maps fields, determines whether your detection logic actually works in practice. Getting a rule to silently fail (0 detections) and having to debug *why* was a more valuable exercise than if everything had just worked first try — it's exactly the kind of troubleshooting I'd expect to run into doing real SIEM/EDR tuning work.
