# Threat Detection Lab — Project Plan
 
A two-VM home SOC for detection engineering practice, tuned for a 16 GB RAM host. The goal is a tight, well-documented project that demonstrates end-to-end skill: telemetry collection, SIEM operation, detection authoring, adversary emulation, and incident investigation — without sinking weeks into infrastructure.
 
**Scope discipline matters more than scope size.** Resist the urge to add more VMs mid-build. Finish this lab, then decide if you want a Lab 2.
 
---
 
## 1. Setup & Install
 
### 1.1 Resource Plan (16 GB Host)
 
You are running two VMs on a host that also needs to function. Budget RAM up front or Elastic will eat you alive.
 
| Component        | RAM Allocation | Notes                                                       |
| ---------------- | -------------- | ----------------------------------------------------------- |
| Host OS          | ~4 GB          | Close Chrome tabs, Slack, etc. while running the lab        |
| Windows 11 VM    | 5–6 GB         | 4 GB is the floor; Win10 is a lighter alternative if needed |
| Ubuntu SIEM VM   | 5–6 GB         | Elasticsearch JVM heap will be capped explicitly            |
| Buffer           | ~1 GB          | Don't allocate every byte                                   |
 
Hard rule: when the lab is running, treat the host like a single-purpose machine. Do schoolwork elsewhere.
 
### 1.2 Host Software
 
- **Hypervisor:** VMware Workstation (what this lab runs on).
- **Network:** Create an "Internal Network" or "Host-Only Network" so the two VMs can talk to each other. The Ubuntu VM also needs a NAT adapter so it can reach the internet during setup.
### 1.3 VM 1 — Windows 11 Endpoint
 
**OS install:**
- Download Windows 11 ISO from Microsoft.
- If TPM/Secure Boot give you grief in VMware, either enable the appropriate VM options or fall back to Windows 10 — it will not weaken the project.
- Allocate 5–6 GB RAM, 2 vCPUs, 60 GB dynamic disk.
**Install on the Windows VM:**
- **Sysmon** with the [SwiftOnSecurity sysmon-config](https://github.com/SwiftOnSecurity/sysmon-config) — do not run Sysmon with default config, it logs almost nothing useful.
- **Elastic Agent** (enrolled to your Fleet server — you'll do this after the SIEM is up).
- **PowerShell logging** — enable via Group Policy or registry:
  - Module Logging
  - Script Block Logging (this is the big one — captures decoded PowerShell)
  - Transcription (optional but nice)
- **Windows Security auditing** — enable advanced audit policies for:
  - Logon/Logoff (success + failure)
  - Account Management
  - Process Creation (with command line — this requires a separate policy toggle, easy to miss)
  - Object Access if you want file auditing
**Do not enroll the Elastic Agent yet.** Get Windows installed and snapshot it. Then build the SIEM. Then come back and enroll.
 
### 1.4 VM 2 — Ubuntu SIEM
 
**OS install:**
- Ubuntu Server 22.04 LTS (lighter than desktop — you don't need a GUI on this box).
- Allocate 5–6 GB RAM, 2 vCPUs, 80 GB disk.
- Give it a static IP on the internal network so the Windows agent has a stable target.
**Install the Elastic stack** (single-node setup — no clustering, no extras):
- Elasticsearch
- Kibana
- Fleet Server (you'll add this through Kibana after the basics are up)
**Critical: cap the Elasticsearch JVM heap.** Out of the box, Elastic can balloon and OOM-kill itself on a small VM. Create `/etc/elasticsearch/jvm.options.d/heap.options` with:
 
```
-Xms2g
-Xmx2g
```
 
Do this *before* you start Elasticsearch for the first time. Tune up later if you have headroom; tuning down after a crash is more painful.
 
**Order of operations on Ubuntu:**
1. Install Elasticsearch, set heap, start it, confirm it's healthy on port 9200.
2. Install Kibana, configure it to point at Elasticsearch, start it, confirm UI loads.
3. In Kibana, set up Fleet — this will guide you to install Fleet Server on the same host.
4. Back to the Windows VM: install Elastic Agent and enroll it into Fleet using the enrollment token Kibana gives you.
5. Add the **Windows integration**, **System integration**, and crucially a **custom log integration for Sysmon** (or use the Sysmon integration if available in your version).
### 1.5 Verify Ingestion Before Doing Anything Else
 
This is where most home labs silently fail. Do not skip.
 
- Log into the Windows VM, run a few commands, fail a login deliberately.
- Open Kibana Discover, filter on your Windows host, confirm you see:
  - Sysmon events (Event IDs 1, 3, 11, etc.)
  - PowerShell script block logs (Event ID 4104)
  - Security events (4624 success logon, 4625 failed logon, 4720 user created)
- If anything is missing, fix it now. Detections built on incomplete telemetry are worthless.
**Snapshot both VMs.** Label the snapshot "clean-ingestion-verified". You will want this.
 
---
 
## 2. Process — What To Do After Setup
 
This is the actual project work. Each phase produces a deliverable for the repo.
 
### Phase A — Baseline Dashboard
 
Before generating malicious activity, build a Kibana dashboard showing normal activity:
- Logon events over time (success vs failure)
- Top processes spawned
- PowerShell activity rate
- Network connections from Sysmon Event ID 3
The point isn't a pretty dashboard. It's that you'll see what "normal" looks like, so when you run atomics you can visually confirm the anomaly stands out. Save and export the dashboard JSON — it goes in the repo.
 
### Phase B — Adversary Emulation with Atomic Red Team
 
[Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) is a library of small scripted tests, each mapped to a MITRE ATT&CK technique. This replaces manually fumbling around trying to look suspicious.
 
**Install on the Windows VM:**
- Install the Invoke-AtomicRedTeam PowerShell module.
- Pull the atomics repository.
**Plan your atomics.** Pick 5–7 techniques that match the activity types you originally listed:
 
| ATT&CK ID  | Technique                        | Maps To Your Original List       |
| ---------- | -------------------------------- | -------------------------------- |
| T1059.001  | PowerShell                       | Suspicious PowerShell            |
| T1027      | Obfuscated/Encoded Commands      | Encoded command execution        |
| T1136.001  | Create Local Account             | New local user creation          |
| T1098      | Account Manipulation             | Admin group modification         |
| T1110.001  | Brute Force: Password Guessing   | Failed logins                    |
| T1105      | Ingress Tool Transfer            | File download test               |
| T1021.001  | Remote Services: RDP             | RDP/login events                 |
 
For each one: read the atomic's YAML, understand what it does, run it, then go look in Kibana for the resulting telemetry. **Take a screenshot or note the event details for each.** Those notes become your investigation writeups.
 
### Phase B.5 — ATT&CK Coverage Heatmap (Python)
 
Zero blockers, so start this as soon as you've settled on your 5–7 planned techniques — no need to wait until atomics are actually run.
 
- Maintain a small YAML/JSON list of your planned/completed techniques (technique ID, tactic, status).
- Write a script that reads this list and generates a MITRE ATT&CK Navigator layer JSON.
- Update it incrementally as detections are added. It becomes a good README screenshot and a living coverage map.
### Phase C — Write Detections as Sigma Rules
 
[Sigma](https://github.com/SigmaHQ/sigma) is the portable, vendor-neutral detection format. Writing in Sigma and then converting to Elastic's query language (EQL or KQL) is dramatically better signaling on a resume than writing Elastic-only queries — it shows you understand detection as a discipline, not as a product.
 
Write **5 detections, one per tactic**. Each maps to an atomic already planned in Phase B, so no extra emulation work is needed.
 
| # | Tactic               | ATT&CK    | Detection                                                         | Key telemetry          |
| --- | -------------------- | --------- | ----------------------------------------------------------------- | ---------------------- |
| 1 | Execution            | T1059.001 | PowerShell download cradle (IEX with Net.WebClient / Invoke-WebRequest) | 4104 script block |
| 2 | Defense Evasion      | T1027     | PowerShell launched with `-EncodedCommand`                        | Sysmon 1 command line  |
| 3 | Persistence          | T1136.001 | New local user created                                            | 4720                   |
| 4 | Privilege Escalation | T1098     | User added to local Administrators                                | 4732                   |
| 5 | Credential Access    | T1110.001 | Burst of failed logons against one account                        | 4625                   |
 
Detection 5 needs a count over a time window. If the Sigma-to-EQL conversion can't express it, build it as a Kibana threshold rule and note that in the rule's README.
 
For each detection:
1. Write the rule in Sigma YAML — give it a clear title, description, ATT&CK mapping, log source, detection logic, false positive notes, and severity.
2. Convert to Elastic EQL or KQL using `sigma-cli` (or do it by hand for the small ones).
3. Create the detection rule in Kibana's Security app using the converted query.
4. Re-run the corresponding atomic and confirm the rule fires.
5. Tune if needed (e.g., the rule fires on legitimate admin activity — note this in the false positives section).
### Phase C.5 — Python Tooling: Validation Harness & Sigma Pipeline
 
Build these starting with your **first** detection, not after all 5 are done — testing-as-you-go reads as an engineering workflow; automating retroactively reads as an afterthought.
 
**Detection validation harness** (highest resume value of all the Python work):
- Use the `elasticsearch-py` client to query for the expected event after running an atomic.
- Use Kibana's Detection Engine API to confirm the corresponding rule fired an alert.
- Script asserts pass/fail and logs the result — this is detection-as-code regression testing, the same pattern real detection engineering teams run in CI/CD.
- The harness does not launch atomics. Run the atomic on the Windows VM, then run the harness for that technique. Keeping it read-only avoids remote-execution setup.
- Once all 5 detections exist, screenshot a full run with every detection passing. It goes at the top of the README.
**Sigma → EQL pipeline** (optional, same timeframe):
- Use `pySigma` (the library behind `sigma-cli`) to script the Sigma-to-EQL conversion instead of hand-converting each rule.
- Optionally auto-deploy the converted query to Kibana via its API.
- Small script, but demonstrates you understand Sigma as a pipeline rather than a manual chore.
### Phase D — Investigations
 
Pick 2–3 of your fired detections and write proper investigation reports. Each one should walk through:
- **Trigger:** What detection fired, when, on what host.
- **Initial indicators:** The raw event(s) that triggered it.
- **Pivot:** What you queried next — parent process, user account, network connections around the event, other activity from the same source.
- **Timeline:** A chronological reconstruction of what happened.
- **Verdict:** True positive (it was the atomic you ran), false positive (something else triggered it), or inconclusive.
- **Recommendations:** What would you tell a real org to do? Block the technique, harden a policy, tune the detection, etc.
This is the most resume-valuable section of the entire project. Detection engineering jobs and SOC analyst roles both rely on this kind of structured thinking, and almost no student-tier portfolio shows it well.
 
### Phase D.5 — Python Tooling: Enrichment/Pivot Helper
 
Build this when you start investigation #1 — that's when you'll actually feel the manual pivoting pain it's meant to solve, rather than building it speculatively.
 
- Script takes an alert ID, pulls the raw triggering event(s) via the Elasticsearch API.
- Pulls related events in a time window (same host, user, or process tree) to automate the "pivot" step of your investigation writeups.
- Not a full SOAR — just a query helper that saves manual re-querying in Kibana Discover.
### Phase E — Document Lessons Learned
 
One short document. What broke during the build, what you'd do differently, what surprised you. Hiring managers read this.
 
Include a troubleshooting table (symptom, root cause, fix) for every build issue, starting with the ones already hit: the x509 certificate failure during Fleet enrollment, PowerShell execution policy blocks, and Atomic Red Team path errors. Log each one the day it happens, while the details are fresh.
 
---
 
## 3. GitHub Repo — Structure & When to Commit
 
### 3.1 Why This Matters
 
The repo *is* the deliverable. An interviewer is not spinning up your VMs. They are clicking through your README on their phone between meetings. Optimize for that.
 
### 3.2 Repo Structure
 
```
threat-detection-lab/
├── README.md                          # Front door: what, why, architecture, screenshots
├── docs/
│   ├── architecture.md                # Network diagram + component explanation
│   ├── setup/
│   │   ├── 01-vm-and-network.md
│   │   ├── 02-ubuntu-elastic.md
│   │   ├── 03-windows-sysmon.md
│   │   ├── 04-fleet-enrollment.md
│   │   └── 05-ingestion-verification.md
│   └── lessons-learned.md             # What broke, what you'd change, troubleshooting table
├── detections/
│   ├── README.md                      # Index table: ID, title, ATT&CK, severity
│   ├── T1027-encoded-powershell/
│   │   ├── README.md                  # Description, logic, false positives, screenshots
│   │   ├── rule.sigma.yml
│   │   └── rule.eql.txt
│   ├── T1136.001-local-account-creation/
│   │   └── ...
│   └── (one folder per detection)
├── investigations/
│   ├── README.md                      # Index of investigations
│   ├── 001-encoded-powershell-execution/
│   │   ├── investigation.md
│   │   └── screenshots/
│   └── (one folder per investigation)
├── dashboards/
│   ├── README.md                      # What each dashboard shows
│   ├── screenshots/
│   └── exports/                       # Kibana NDJSON exports
├── atomics/
│   └── execution-plan.md              # Which atomics, run order, expected telemetry
├── scripts/
│   ├── README.md                      # What each script does, how to run it
│   ├── coverage.yml                   # Technique list: ID, tactic, status
│   ├── attack_heatmap.py              # Builds MITRE Navigator layer from coverage.yml
│   ├── validate_detections.py         # After an atomic: checks ES for telemetry, Kibana for the alert
│   ├── sigma_to_eql.py                # pySigma-based conversion (+ optional Kibana deploy)
│   └── investigate.py                 # Pulls alert + related events for pivoting
└── .gitignore
```
 
### 3.3 README.md — The Most Important File
 
Structure it so someone can understand the project in 60 seconds:
1. **One-paragraph summary.** What it is, what it demonstrates.
2. **Architecture diagram.** Hand-drawn is fine; clarity beats polish.
3. **Tech stack.** Bulleted: Elastic Stack, Fleet, Sysmon, Atomic Red Team, Sigma, Python (elasticsearch-py, pySigma).
4. **Highlights.** "5 detections written in Sigma covering 5 ATT&CK tactics, validated via Atomic Red Team and a Python harness. 3 full investigations."
5. **Detections table.** Same as `detections/README.md` — duplicate it on the front page.
6. **Screenshots.** Harness run with every detection passing, ATT&CK Navigator layer, baseline dashboard, a fired detection, an investigation excerpt.
7. **Links** to deeper docs.
### 3.4 When to Commit
 
Don't save commits for "when it's done." The commit history is itself evidence of incremental engineering work, and a repo created in a single commit two days before an interview looks exactly like what it is.
 
Commit at these checkpoints:
 
| Checkpoint                                  | What to Commit                                       |
| ------------------------------------------- | ---------------------------------------------------- |
| Day 1, before any install                   | README skeleton, architecture diagram, empty folders |
| After Ubuntu + Elastic running              | `docs/setup/01-` and `02-`                           |
| After Windows agent enrolled                | `docs/setup/03-` and `04-`                           |
| After ingestion verified                    | `docs/setup/05-`, baseline dashboard export          |
| After Atomic Red Team installed and planned | `atomics/execution-plan.md`                          |
| After ATT&CK heatmap script works           | `scripts/attack_heatmap.py`, `coverage.yml`, layer JSON |
| After each detection written and validated  | That detection's folder (Sigma + EQL + README)       |
| After validation harness runs against detection #1 | `scripts/validate_detections.py`              |
| After Sigma→EQL pipeline script works       | `scripts/sigma_to_eql.py`                             |
| After each investigation                    | That investigation's folder                          |
| After enrichment/pivot helper used in an investigation | `scripts/investigate.py`                  |
| Final pass                                  | `lessons-learned.md`, polish README, add screenshots |
 
Use real commit messages: `Add T1136.001 detection: local account creation via net user`, not `update`.
 
### 3.5 What Not to Commit
 
- Elastic enrollment tokens, API keys, internal IPs that reveal anything sensitive about your host network.
- Massive log exports or VM disk files.
- Anything that wasn't actually used — empty folders, half-written rules. A small, complete repo beats a sprawling, half-finished one.
Add a `.gitignore` early to keep these out by default.
 
---
 
## 4. Suggested Timeline
 
You do not have to hit these exactly, but if you blow past them by 2× it's a signal you're scope-creeping.
 
- **Week 1:** VM setup, Elastic stack running, Windows agent enrolled, ingestion verified. Commit setup docs.
- **Week 2:** Atomic Red Team installed, baseline dashboard built, all planned atomics executed, telemetry confirmed for each.
- **Week 3:** Write the 5 Sigma detections, convert to EQL, validate each with the harness after re-running its atomic.
- **Week 4:** Write 2–3 investigations, polish README, take screenshots, write lessons learned.
Total: about one month at student pace. If you stall at any single step for more than a few days, ask for help rather than grinding — that pattern repeats badly in industry, better to break it now.
 
---
 
## 5. What Success Looks Like
 
When you can hand this to an interviewer and they see:
- A clear architecture they can grok in 30 seconds
- Detections written in an industry-standard format with ATT&CK mappings
- Real investigations that show analytical thinking, not just tool screenshots
- A commit history showing weeks of incremental work
…you have a resume project that meaningfully differentiates you from candidates whose "security project" is a TryHackMe completion certificate. That's the bar.
 
