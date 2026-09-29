# revil-ransomware-analysis
DFIR investigation of a simulated REvil/Sodinokibi ransomware incident using Redline, Hybrid Analysis, and VirusTotal  includes filesystem triage, IOC extraction, and MITRE ATT&amp;CK mapping.
# REvil Ransomware DFIR Investigation (LetsDefend Challenge)

## Overview

This writeup documents my investigation of a simulated REvil (Sodinokibi) ransomware
incident, based on the "REvil Ransomware" DFIR challenge from LetsDefend. The scenario
provides a memory/triage image (`.mans` file) collected from a compromised Windows host,
along with a dropped ransom note. The goal was to identify the initial infection vector,
the ransomware binary, its behavior, and relevant MITRE ATT&CK mappings.
**Tools used:**
- [Redline](https://fireeye.market/apps/211364et) (FireEye/Mandiant) — for parsing the
  `.mans` triage collection
- [Hybrid Analysis](https://www.hybrid-analysis.com/) — for dynamic sandbox behavior /
  process tree analysis
- [VirusTotal](https://www.virustotal.com/) — for hash reputation and MITRE ATT&CK
  behavior mapping

**Files provided:**
- `AnalysisSession1.mans` — Redline collection from the compromised host
- Ransom note dropped on the filesystem
- A supporting PNG artifact
## Q1: What is the Operating System on which the Redline image was collected?

Opening the `.mans` file in Redline and navigating to **System Information**, the
"Operating System Information" panel identifies the host as:

**Windows 7 Professional, 7601, Service Pack 1 (64-bit)**
Machine name: `WIN-CH23QIC2OMH`
<img width="377" height="357" alt="Screenshot 2026-09-24 141813" src="https://github.com/user-attachments/assets/26393459-47c5-4d1a-932f-32b54379bf95" />

---
## Q2: What is the logged-in user while the Redline image was being collected?

Under **User Information** in Redline, the active user profile is:

**SecurityNinja**
<img width="343" height="80" alt="Screenshot 2026-09-28 213940" src="https://github.com/user-attachments/assets/c7e2df9a-f914-4397-9f9e-510c4dbee4a0" />

---
## Q3: What is the location of the ransomware on the filesystem?

Drilling into the SecurityNinja profile under **File System → Downloads**, three files
stand out: the legitimate `7z1900-x64.exe` installer, the ransom note
`993ixjlb-readme.txt`, and a suspiciously named executable that doesn't match typical
software naming conventions:

**`C:\Users\SecurityNinja\Downloads\bad day.exe`**

The file properties show `bad day.exe` (136 KB) was created at `2021-07-31 20:06:09Z` —
just seconds after the ransom note `993ixjlb-readme.txt` was created at `20:06:04Z`.
This timestamp correlation is consistent with the malware dropping its ransom note
immediately upon execution.
<img width="504" height="391" alt="Screenshot 2026-09-24 142218" src="https://github.com/user-attachments/assets/cb9fe79d-3fd3-472f-9151-6368c8b2db04" />

---
## Q4: What is the MD5 hash of the ransomware?

Opening the file's "Full Detailed Information" view in Redline, the **File Hashes**
section lists:

**MD5: `94d087166651c0020a9e6cc2fdacdc0c`**

This hash was cross-referenced against Hybrid Analysis / VirusTotal to confirm
malicious classification.
<img width="513" height="392" alt="Screenshot 2026-09-24 142708" src="https://github.com/user-attachments/assets/9d680ba0-eda6-41f2-a010-e4ba738f600a" />

---
## Q5: What is the extension used on encrypted files?

The ransom note dropped on the system (`993ixjlb-readme.txt`) states directly:
*"all files on your system has extension 993ixjlb."* This is also visible on encrypted
files themselves in Redline's File System view (e.g. `Wildlife.wmv.993ixjlb`).

**Extension: `.993ixjlb`**
<img width="142" height="11" alt="Screenshot 2026-09-28 215107" src="https://github.com/user-attachments/assets/f0ded044-ec97-48a4-b639-a5518a1f816f" />

---
## Q6: What is the onion (Tor) website for paying the ransom?

From the ransom note's payment instructions section:

**`http://aplebzu47wgazapdqks6vrcv6zcnjppkbxbr6wketf56nf6aq2nmyoyd.onion/4FE49B3286F992CB`**
<img width="830" height="110" alt="Screenshot 2026-09-28 215618" src="https://github.com/user-attachments/assets/3a67cfe6-b405-4338-a446-c711527a5dfb" />

---

## Q7: What is the secondary (clearnet) website for paying the ransom?

Provided in the same note as a fallback if Tor is inaccessible:

**`http://decoder.re/4FE49B3286F992CB`**
<img width="952" height="107" alt="Screenshot 2026-09-28 215957" src="https://github.com/user-attachments/assets/d8a950c9-3a49-47ba-8caf-9a62e83443b3" />

---
## Q8: What child command-line process is executed after the ransomware runs?

Since Redline doesn't capture live sandbox execution, I took the ransomware's hash and
searched it on Hybrid Analysis to review its recorded process tree. The parent process
spawns a `netsh.exe` child process running:

**`netsh advfirewall firewall set rule group="Network Discovery" new enable=Yes`**

This enables the "Network Discovery" firewall rule group — a known REvil/Sodinokibi
behavior that allows the malware to scan the local network for additional hosts and
shares to reach for lateral movement/encryption. 
<img width="502" height="124" alt="Screenshot 2026-09-24 145200" src="https://github.com/user-attachments/assets/ada75231-a47b-4f6e-bbbb-5fcf534f61f9" />

---
## Q9: What is the MITRE ATT&CK technique ID for this ransomware's impact stage?

Searching the file's SHA-256 hash on VirusTotal and reviewing the **Behavior** tab's
MITRE ATT&CK mapping, two techniques appear under the **Impact (TA0040)** tactic:
"Service Stop" (T1489) and "Data Encrypted for Impact" (T1486). Since the sample's core
behavior is file encryption for ransom. The relevant technique is:

**T1486 — Data Encrypted for Impact**
<img width="211" height="187" alt="Screenshot 2026-09-28 180550" src="https://github.com/user-attachments/assets/35578eb0-9640-417d-a78c-84bc464e0660" />

---
