# Developing YARA Rules

> Part of my **YARA & Sigma for SOC Analysts** (HTB Academy) learning path.
> This report documents what I did and learned while working through manual and automated YARA rule development, going from raw string analysis to production-style rules used to detect real malware families (UPX-packed binaries, Dharma ransomware, APT17's ZoxPNG RAT, and Turla's Neuron malware).

## Objective

Move beyond just *using* YARA rules to actually *building* them — both by hand and with automated tooling — using proper malware analysis methodology:

- String/byte analysis (`strings`, hex inspection)
- Automated rule generation with **yarGen**
- Manual rule crafting using threat intel reports, imphash, and PE/`.NET` reversing

## Environment

- Linux target (SSH)
- Tools used: `strings`, `yarGen`, `yara`, `monodis`, `imphash_calc.py`, dnSpy (referenced)

---

## Part 1 — A Simple Manual Rule: Detecting UPX-Packed Executables

**Sample:** `svchost.exe`

Started with the most basic analysis step — running `strings` on the sample:

```bash
strings svchost.exe
```

[SCREENSHOT: terminal output of `strings svchost.exe` highlighting the UPX0/UPX1/UPX2/UPX! markers]

The output immediately gave it away: `UPX0`, `UPX1`, `UPX2`, and `UPX!` markers — clear signs the binary is packed with the **UPX (Ultimate Packer for eXecutables)** packer.

**Rule:**

```yara
rule UPX_packed_executable
{
    meta:
        description = "Detects UPX-packed executables"
    strings:
        $string_1 = "UPX0"
        $string_2 = "UPX1"
        $string_3 = "UPX2"
    condition:
        all of them
}
```

**Lesson:** this isn't a malware-specific rule — it just flags *packing*, which is itself a useful triage signal. Packing is heavily used by both legitimate software and malware trying to evade static analysis, so a rule like this is best used as a first-pass filter to prioritize samples for deeper review, not as a standalone malicious/benign verdict.

---

## Part 2 — Automated Rule Generation with yarGen

**Sample:** `dharma_sample.exe`

Manual `strings` analysis again surfaced the earlier-identified PDB path:

```
C:\crysis\Release\PDB\payload.pdb
```

Rather than hand-pick every interesting string, I used **yarGen** — a tool that automatically generates YARA rules by diffing a sample's strings against a large "goodware" string/opcode database, filtering out anything common to legitimate software.

**Setup:**

```bash
pip install -r requirements.txt
python yarGen.py --update      # downloads ~913MB of goodware string/opcode DBs
```

**Generating the rule** against the sample placed in a temp folder:

```bash
python3 yarGen.py -m /home/htb-student/temp -o htb_sample.yar
```

[SCREENSHOT: terminal output of yarGen processing the sample and writing the generated rule]

yarGen loaded its goodware databases (millions of known-benign strings/imphashes/exports), processed the sample, and produced a single rule:

```yara
rule dharma_sample {
    meta:
        description = "temp - file dharma_sample.exe"
        author      = "yarGen Rule Generator"
        reference   = "https://github.com/Neo23x0/yarGen"
        date        = "2023-08-24"
        hash1       = "bff6a1000a86f8edf3673d576786ec75b80bed0c458a8ca0bd52d12b74099071"
    strings:
        $x1  = "C:\\crysis\\Release\\PDB\\payload.pdb" fullword ascii
        $s2  = "sssssbs" fullword ascii
        $s3  = "sssssbsss" fullword ascii
        $s4  = "RSDS%~m" fullword ascii
        // ... additional low-frequency/obfuscated-looking strings
    condition:
        uint16(0) == 0x5a4d and filesize < 300KB and
        1 of ($x*) and 4 of them
}
```

**Validation** against the sample repository:

```bash
yara htb_sample.yar /home/htb-student/Samples/YARASigma
```

[SCREENSHOT: terminal output showing the generated rule matching `dharma_sample.exe` and its disguised copies]

**Result:** matched `dharma_sample.exe` plus the same four disguised copies seen earlier (`pdf_reader.exe`, `microsoft.com`, `check_updates.exe`, `KB5027505.exe`) — confirming the auto-generated rule was just as effective as the manually-crafted one from the previous report, with far less manual string-picking effort.

**Takeaway:** yarGen is a strong starting point for rule creation, especially at scale, but the tool itself flags that rules should be **post-processed** — reviewed and tightened by a human before being trusted in production, since automated string selection can still include red herrings.

---

## Part 3 — Manual Rule Development, Example 1: ZoxPNG RAT (APT17)

**Sample:** `legit.exe` (deliberately misleading filename)

This time I built a rule from scratch using multiple intelligence sources, not just raw strings:

1. **String analysis** — `strings legit.exe` revealed network/HTTP indicators (`InternetOpenA`, `HttpSendRequestA`, a suspicious hardcoded Google-image-search-style URL used for C2 disguise, `Cookie: SESSIONID=%s`, staged `Step 1`–`Step 11` markers, and a specific spoofed User-Agent string).
2. **Public threat intel** — a write-up from Intezer on this ZoxPNG variant.
3. **Common sample size** — cross-referencing related hashes from the report showed none of the known related samples exceeded ~200KB.
4. **Imphash** — calculated with a helper script:

```bash
python3 imphash_calc.py /home/htb-student/Samples/YARASigma/legit.exe
# 414bbd566b700ea021cfae3ad8f4d9b9
```

[SCREENSHOT: terminal output of the imphash calculation script]

**Resulting rule** (`apt_apt17_mal_sep17_2.yar`, originally by Florian Roth):

```yara
import "pe"

rule APT17_Malware_Oct17_Gen {
    meta:
        description = "Detects APT17 malware"
        author      = "Florian Roth (Nextron Systems)"
        reference   = "https://goo.gl/puVc9q"
        date        = "2017-10-03"
    strings:
        $x1 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NETCLR 2.0.50727)" fullword ascii
        $x2 = "http://%s/imgres?q=A380&hl=en-US&sa=X&biw=1440&bih=809&tbm=isus&tbnid=aLW4-J8Q1lmYBM" ascii
        $s1 = "hWritePipe2 Error:%d" fullword ascii
        $s2 = "Not Support This Function!" fullword ascii
        $s3 = "Cookie: SESSIONID=%s" fullword ascii
        $s4 = "http://0.0.0.0/1" fullword ascii
        $s5 = "Content-Type: image/x-png" fullword ascii
        $s6 = "Accept-Language: en-US" fullword ascii
        $s7 = "IISCMD Error:%d" fullword ascii
        $s8 = "[IISEND=0x%08X][Recv:] 0x%08X %s" fullword ascii
    condition:
        ( uint16(0) == 0x5a4d and filesize < 200KB and (
            pe.imphash() == "414bbd566b700ea021cfae3ad8f4d9b9" or
            1 of ($x*) or
            6 of them
        ) )
}
```

**What stood out to me:**
- The `import "pe"` module lets the rule reach into PE-specific metadata (imphash) instead of relying purely on strings — this makes the rule resilient even if strings get changed across variants, as long as the import table (and therefore imphash) stays similar.
- The condition logic gives **three independent paths to a match**: a strong imphash match alone, a single highly-unique `$x*` string alone, or a broader 6-of-everything match. This layered condition design balances precision (imphash/unique strings) with recall (catching variants where one indicator changed).

---

## Part 4 — Manual Rule Development, Example 2: Neuron (Turla)

**Sample:** `Microsoft.Exchange.Service.exe` (again, a deliberately legitimate-sounding name)

Since the NCSC UK report on this malware confirmed both the Neuron client and service are **.NET** binaries, plain `strings` output wouldn't show much beyond surface-level text. Instead, I used `monodis` to decompile the assembly's IL code:

```bash
monodis --output=code Microsoft.Exchange.Service.exe
cat code
```

[SCREENSHOT: terminal output of the decompiled IL code showing `Utils.Storage::ExecCMD` and related class/method names]

This surfaced .NET class and method names directly from the IL — things like `Utils.Storage::ExecCMD`, `Utils.Crypt::EncryptScript`, and `Storage::KillOldThread` — effectively reverse-engineering the malware's internal structure without needing a full debugger session (though the report notes a tool like **dnSpy** would give a richer view for deeper analysis).

**Resulting rule** (`neuron_1.yar`, by NCSC UK):

```yara
rule neuron_functions_classes_and_vars {
    meta:
        description = "Rule for detection of Neuron based on .NET functions and class names"
        author      = "NCSC UK"
        reference   = "https://www.ncsc.gov.uk/file/2691/download?token=RzXWTuAB"
        reference2  = "https://www.ncsc.gov.uk/alerts/turla-group-malware"
    strings:
        $class1 = "StorageUtils" ascii
        $class2 = "WebServer" ascii
        $class3 = "StorageFile" ascii
        $class4 = "StorageScript" ascii
        $class5 = "ServerConfig" ascii
        $class6 = "CommandScript" ascii
        $class7 = "MSExchangeService" ascii
        $class8 = "W3WPDIAG" ascii
        $func1  = "AddConfigAsString" ascii
        $func2  = "DelConfigAsString" ascii
        $func3  = "GetConfigAsString" ascii
        $func4  = "EncryptScript" ascii
        $func5  = "ExecCMD" ascii
        $func6  = "KillOldThread" ascii
        $func7  = "FindSPath" ascii
        $dotnetMagic = "BSJB" ascii
    condition:
        (uint16(0) == 0x5A4D and uint16(uint32(0x3c)) == 0x4550) and $dotnetMagic and 6 of them
}
```

**Breaking down the condition logic:**
- `uint16(0) == 0x5A4D` confirms the `MZ` PE magic bytes at the start of the file.
- `uint16(uint32(0x3c)) == 0x4550` follows the pointer at offset `0x3c` (the standard location of the PE header offset) and checks for the `PE` signature there — a more rigorous PE-format validity check than the MZ check alone.
- `$dotnetMagic == "BSJB"` confirms the file is specifically a **.NET assembly** (this signature lives in the CLI header).
- `6 of them` requires six of the fifteen class/function name strings — giving tolerance for partial obfuscation or renaming while still requiring strong cumulative evidence.

---

## Closing Exercise — Adapting an Existing Rule

The module closed with a practical exercise: take the `apt_apt17_mal_sep17_1.yar` rule (built around a placeholder `X.dll`) and adapt it to correctly fingerprint a *different* sample, `DirectX.dll`, by identifying the correct legitimate-looking DLL name the malware impersonates.

**Answer identified:** `TSMSISrv.dll`

This drove home a recurring theme across this whole module: threat actors lean heavily on **typosquatting/impersonation of legitimate system or vendor DLL names** (`DirectX.dll` mimicking a real Windows component) to blend into a system's process and file listings, and a well-built YARA rule needs to account for that exact naming trick rather than just generic "looks suspicious" heuristics.

---

## Key Takeaways

- Manual rule-building starts with the basics — `strings`, hex inspection — but gets much stronger when combined with external threat intel, imphash, and (for .NET) IL-level reversing via `monodis`/dnSpy.
- **yarGen** is a genuinely useful accelerator for rule creation, but generated rules are a starting point, not a finished product — they need human review before being trusted in a production detection pipeline.
- Strong rules layer multiple signal types (PE imphash + unique strings + format checks) so a single changed string in a malware variant doesn't blow the detection.
- Malware authors consistently disguise files using legitimate-sounding names (`legit.exe`, `Microsoft.Exchange.Service.exe`, `DirectX.dll`) — which is exactly why byte/string/structure-based detection (YARA) matters more than filename-based triage.

## References

- [yarGen (Florian Roth / Neo23x0)](https://github.com/Neo23x0/yarGen)
- [Intezer — ZoxPNG / APT17 analysis](https://www.intezer.com/)
- [NCSC UK — Turla Group Malware Advisory](https://www.ncsc.gov.uk/alerts/turla-group-malware)
- HTB Academy — *YARA & Sigma for SOC Analysts*
