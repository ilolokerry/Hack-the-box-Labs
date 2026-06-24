# Hunting Evil with YARA (Windows & Linux Edition)

> Part of my **YARA & Sigma for SOC Analysts** (HTB Academy) learning path.
> This report documents what I did and learned while working through the "Hunting Evil with YARA" sections, applying YARA across disk, live processes, ETW data, and memory images.

## Objective

Learn how to operationalize YARA as a SOC analyst — not just write rules, but actually hunt with them across different artifact types:

- Files on disk
- Live/running processes
- ETW (Event Tracing for Windows) data
- Memory images (standalone and via Volatility)

## Environment

- Windows target (RDP) for the disk, process, and ETW sections
- Linux target (SSH) for the memory forensics section
- Tools used: `yara64.exe` / `yara`, HxD hex editor, SilkETW, Volatility 2.6.1, `hexdump`

---

## Part 1 — Hunting for Malicious Executables on Disk

**Sample analyzed:** `dharma_sample.exe` (Dharma ransomware)

I started by examining the sample in a hex editor (HxD) to confirm a previously identified PDB string:

```
C:\crysis\Release\PDB\payload.pdb
```

[SCREENSHOT: HxD hex view showing the `payload.pdb` and `sssssbsss` strings highlighted]
Scrolling further through the hex dump, I spotted a second, fairly unique-looking string: `sssssbsss`.

On Linux, the same bytes can be located without a GUI hex editor using `hexdump`:

```bash
hexdump dharma_sample.exe -C | grep crysis -n3
hexdump dharma_sample.exe -C | grep sssssbsss -n3
```

**Building the rule** — I converted both strings into raw hex byte patterns and combined them into a single rule requiring both to match:

```yara
rule ransomware_dharma {
    meta:
        author      = "kerry"
        version     = "1.0"
        description = "Simple rule to detect strings from Dharma ransomware"
        reference   = "https://www.virustotal.com/gui/file/bff6a1000a86f8edf3673d576786ec75b80bed0c458a8ca0bd52d12b74099071/behavior"
    strings:
        $string_pdb  = { 433A5C6372797369735C52656C656173655C5044425C7061796C6F61642E706462 }
        $string_ssss = { 73 73 73 73 73 62 73 73 73 }
    condition:
        all of them
}
```

**Running it against the sample directory:**

```powershell
yara64.exe -s C:\Rules\yara\dharma_ransomware.yar C:\Samples\YARASigma\ -r 2>null

PS C:\Users\htb-student> yara64.exe -s C:\Rules\yara\dharma_ransomware.yar C:\Samples\YARASigma\ -r 2>null
ransomware_dharma C:\Samples\YARASigma\\dharma_sample.exe
0xc814:$string_pdb: 43 3A 5C 63 72 79 73 69 73 5C 52 65 6C 65 61 73 65 5C 50 44 42 5C 70 61 79 6C 6F 61 64 2E 70 64 62
0x16c10:$string_ssss: 73 73 73 73 73 62 73 73 73
ransomware_dharma C:\Samples\YARASigma\\check_updates.exe
0xc814:$string_pdb: 43 3A 5C 63 72 79 73 69 73 5C 52 65 6C 65 61 73 65 5C 50 44 42 5C 70 61 79 6C 6F 61 64 2E 70 64 62
0x16c10:$string_ssss: 73 73 73 73 73 62 73 73 73
ransomware_dharma C:\Samples\YARASigma\\microsoft.com
0xc814:$string_pdb: 43 3A 5C 63 72 79 73 69 73 5C 52 65 6C 65 61 73 65 5C 50 44 42 5C 70 61 79 6C 6F 61 64 2E 70 64 62
0x16c10:$string_ssss: 73 73 73 73 73 62 73 73 73
ransomware_dharma C:\Samples\YARASigma\\KB5027505.exe
0xc814:$string_pdb: 43 3A 5C 63 72 79 73 69 73 5C 52 65 6C 65 61 73 65 5C 50 44 42 5C 70 61 79 6C 6F 61 64 2E 70 64 62
0x16c10:$string_ssss: 73 73 73 73 73 62 73 73 73
ransomware_dharma C:\Samples\YARASigma\\pdf_reader.exe
0xc814:$string_pdb: 43 3A 5C 63 72 79 73 69 73 5C 52 65 6C 65 61 73 65 5C 50 44 42 5C 70 61 79 6C 6F 61 64 2E 70 64 62
0x16c10:$string_ssss: 73 73 73 73 73 62 73 73 73
```

**Result:** The rule didn't just flag `dharma_sample.exe` — it also caught several disguised copies sitting in the same directory under innocuous-looking names: `check_updates.exe`, `microsoft.com`, `KB5027505.exe`, and `pdf_reader.exe`. This was a good reminder of why pattern-based detection beats trusting filenames — malware authors lean on legitimate-sounding names to blend in, and a string/byte-pattern rule cuts straight through that.

---

## Part 2 — Hunting for Evil Within Running Processes

Here the goal shifted from disk artifacts to memory-resident shellcode — specifically, detecting Metasploit's Meterpreter reverse TCP shellcode injected into a legitimate process.

**Detection rule** (sourced from the Cuckoo Sandbox community repo):

```yara
rule meterpreter_reverse_tcp_shellcode {
    meta:
        author      = "FDD @ Cuckoo sandbox"
        description = "Rule for metasploit's meterpreter reverse tcp raw shellcode"
    strings:
        $s1 = { fce8 8?00 0000 60 }   // shellcode prologue in metasploit
        $s2 = { 648b ??30 }           // mov edx, fs:[???+0x30]
        $s3 = { 4c77 2607 }           // kernel32 checksum
        $s4 = "ws2_"                  // ws2_32.dll
        $s5 = { 2980 6b00 }           // WSAStartUp checksum
        $s6 = { ea0f dfe0 }           // WSASocket checksum
        $s7 = { 99a5 7461 }           // connect checksum
    condition:
        5 of them
}
```

**Simulating the injection:** I ran `htb_sample_shell.exe`, which spawns `cmdkey.exe` as a child process and injects Meterpreter shellcode into it.

```powershell
PS C:\Samples\YARASigma> .\htb_sample_shell.exe
[+] Parent process with PID 6384 is created : ...htb_sample_shell.exe
[+] Child process with PID 7800 is created  : C:\Windows\System32\cmdkey.exe
[+] Shellcode is written at address 000002686B1C0000 in remote process cmdkey.exe
[+] Remote thread to execute the shellcode is started with thread ID 6308
```

[SCREENSHOT: console output of `htb_sample_shell.exe` showing the injection into `cmdkey.exe`]

**Scanning every running process** with a one-liner that pipes `Get-Process` into `yara64.exe`:

```powershell
Get-Process | ForEach-Object { "Scanning with Yara for meterpreter shellcode on PID "+$_.id; & "yara64.exe" "C:\Rules\yara\meterpreter_shellcode.yar" $_.id }
```

[SCREENSHOT: PowerShell output showing YARA matches on PID 6384 and PID 7800, plus the access-denied errors on protected PIDs]

**Result:** Both the parent (`htb_sample_shell.exe`, PID 6384) and the injected child (`cmdkey.exe`, PID 7800) lit up as matches. A few system PIDs returned `can not attach to process (try running as root)` errors — expected, since those need elevated/protected-process privileges.

Drilling into the flagged PID with `--print-strings` confirmed the shellcode components living inside `cmdkey.exe`'s memory — `ws2_32.dll` references, the kernel32 checksum, WSAStartup/WSASocket checksums, and the `connect` checksum, all exactly where the rule expected them.

**Takeaway:** this is a clean illustration of process injection detection — the rule doesn't care what the process is named, it cares what's actually sitting in its memory.

---

## Part 3 — Hunting for Evil Within ETW Data

ETW (Event Tracing for Windows) gives visibility into both user-mode and kernel-mode activity through a Provider → Session → Consumer pipeline. I used **SilkETW** to layer YARA scanning on top of live ETW events — useful because it lets you tag or filter events in near real time instead of only doing after-the-fact log review.

Some of the ETW providers I noted as high-value for blue-team work:

| Provider | Useful for |
|---|---|
| `Microsoft-Windows-Kernel-Process` | Process injection / hollowing |
| `Microsoft-Windows-Kernel-Network` | C2 traffic, unauthorized connections |
| `Microsoft-Windows-PowerShell` | Malicious script block execution |
| `Microsoft-Windows-Kernel-Registry` | Persistence via registry changes |
| `Microsoft-Windows-DNS-Client` | DNS tunneling / C2 over DNS |
| `Microsoft-Windows-CodeIntegrity` | Unsigned/malicious driver loads |

**Test rule** (`etw_powershell_hello.yar`) — flags PowerShell script blocks containing a simple combination of strings:

```yara
rule powershell_hello_world_yara {
    strings:
        $s0 = "Write-Host" ascii wide nocase
        $s1 = "Hello" ascii wide nocase
        $s2 = "from" ascii wide nocase
        $s3 = "PowerShell" ascii wide nocase
    condition:
        3 of ($s*)
}
```

**Collector command:**

```powershell
.\SilkETW.exe -t user -pn Microsoft-Windows-PowerShell -ot file -p ./etw_ps_logs.json -l verbose -y C:\Rules\yara -yo Matches
```

In a second terminal, I triggered the matching activity:

```powershell
Invoke-Command -ScriptBlock {Write-Host "Hello from PowerShell"}
```

[SCREENSHOT: SilkETW JSON output / console showing the YARA match against `powershell_hello_world_yara`]

**Result:** SilkETW captured the event and reported a YARA match against `powershell_hello_world_yara` in real time. This is a small example, but the pattern generalizes well — swap the rule for something targeting AMSI bypass strings, obfuscated `IEX` chains, or known offensive-tooling cmdlets, and you've got a lightweight real-time PowerShell abuse detector.

---

## Part 4 — Hunting for Evil Within Memory Images

The scenario here is the realistic SOC case: you don't always get hands-on access to a suspected host, but you might get handed a memory capture. The workflow is:

1. Create/obtain YARA rules
2. (Optionally) compile them with `yarac` for performance and to obfuscate rule content
3. Capture memory (e.g., via DumpIt, FTK Imager, LiME)
4. Scan the image with YARA

**Scenario:** `compromised_system.raw` — a memory snapshot from a host hit by **WannaCry**.

**Direct YARA scan:**

```bash
yara /home/htb-student/Rules/yara/wannacry_artifacts_memory.yar \
     /home/htb-student/MemoryDumps/compromised_system.raw --print-strings
```

[SCREENSHOT: terminal output of the YARA scan showing WannaCry string hits in the memory image]

This surfaced dozens of hits for known WannaCry artifacts scattered throughout memory: `tasksche.exe`, `mssecsvc.exe`, `diskpart.exe`, and the infamous kill-switch domain `www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com`.

**Pivoting to Volatility's `yarascan` plugin** for a more forensics-framework-native approach:

*Single-pattern scan* (quick, no rule file needed):

```bash
vol.py -f compromised_system.raw yarascan -U "www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com"
```

*Full rule-file scan* using a proper multi-string rule:

```yara
rule Ransomware_WannaCry {
    meta:
        author      = "Madhukar Raina"
        version     = "1.1"
        description = "Simple rule to detect strings from WannaCry ransomware"
        reference   = "https://www.virustotal.com/gui/file/ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa/behavior"
    strings:
        $wannacry_payload_str1 = "tasksche.exe" fullword ascii
        $wannacry_payload_str2 = "www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com" ascii
        $wannacry_payload_str3 = "mssecsvc.exe" fullword ascii
        $wannacry_payload_str4 = "diskpart.exe" fullword ascii
        $wannacry_payload_str5 = "lhdfrgui.exe" fullword ascii
    condition:
        3 of them
}
```

```bash
vol.py -f compromised_system.raw yarascan -y /home/htb-student/Rules/yara/wannacry_artifacts_memory.yar
```

[SCREENSHOT: Volatility `yarascan` output showing matches attributed to `svchost.exe`, PID 1576]

**Result:** Volatility consistently attributed every match to **`svchost.exe`, PID 1576** — pinpointing exactly which process in memory was carrying the WannaCry indicators, which is far more actionable for an analyst than a flat "found somewhere in this 4GB image" result.

**Key distinction I picked up:** `-U` is for a single ad-hoc pattern straight on the command line; `-y` is for a proper rule file when you've got multiple/complex rules to apply.

---

## Key Takeaways

- YARA is genuinely environment-agnostic — the same rule logic applies whether you're scanning files, live process memory, ETW event streams, or a full memory capture.
- Filenames lie; byte patterns and strings don't. The Dharma samples disguised as `microsoft.com` and `KB5027505.exe` drove that home.
- Combining YARA with ETW (via SilkETW) turns it into a near-real-time detection layer, not just a static/forensic tool.
- Memory forensics + YARA (directly or through Volatility's `yarascan`) lets you attribute IOCs to a specific process, which is critical for scoping an incident.

## References

- [Cuckoo Sandbox community YARA rules](https://github.com/cuckoosandbox/community/blob/master/data/yara/shellcode/metasploit.yar)
- [SilkETW (FuzzySec)](https://github.com/fireeye/SilkETW)
- Microsoft ETW documentation
- HTB Academy — *YARA & Sigma for SOC Analysts*
