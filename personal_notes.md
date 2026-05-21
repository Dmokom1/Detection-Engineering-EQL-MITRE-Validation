# Build Notes
# Detection Engineering: EQL Sequence Rule and MITRE ATT&CK Validation

This file provides supporting build context for the main README. It documents the lab sequence, telemetry setup, validation points, evidence interpretation, and screenshot mapping.

The README explains the full project story. These notes focus on the build details behind the project without repeating the entire write-up.

---

## Purpose of This File

This project was built to practice detection engineering in Elastic using Sysmon, Windows audit policy, simulated endpoint activity, and an EQL sequence rule.

These build notes focus on:

- Telemetry setup
- Audit policy configuration
- Kali network setup
- Attack simulation sequence
- EQL rule logic
- Alert validation
- MITRE ATT&CK coverage review
- Screenshot-supported evidence

---

## Lab Environment

| Component | Details |
|---|---|
| Hypervisor | VMware Workstation Player 17 |
| Target Host | Windows Server 2022 Domain Controller |
| Domain | `cs.local` |
| DC IP Address | `192.168.9.142` |
| Kali VMNet IP | `192.168.9.136` |
| Kali eth1 Static IP | `10.0.0.5` |
| SIEM | Elastic Security / Kibana |
| Endpoint Telemetry | Sysmon with SwiftOnSecurity `sysmonconfig-export.xml` |
| Windows Logging | Advanced Audit Policy and command-line process logging |
| Detection Language | Elastic EQL |

---

## Corrected Lab Sequence

The final lab workflow followed this order:

1. Prepared Sysmon and the SwiftOnSecurity configuration.
2. Installed Sysmon on the Domain Controller.
3. Enabled audit policy subcategory enforcement.
4. Enabled command-line logging for process creation events.
5. Enabled Advanced Audit Policy for process creation.
6. Reviewed Kali network interfaces.
7. Assigned a static IP to Kali `eth1`.
8. Verified process command-line telemetry in Elastic.
9. Ran `whoami` on the Domain Controller.
10. Created `C:\Users\Public\payload.exe`.
11. Attempted PowerShell remote script retrieval with `DownloadString`.
12. Added a registry Run key for persistence simulation.
13. Reviewed attack-related telemetry in Elastic.
14. Built and enabled the EQL sequence rule.
15. Re-ran the attack sequence for validation.
16. Confirmed alert generation in Elastic.
17. Reviewed MITRE ATT&CK coverage mapping.

---

## Important Commands and Artifacts

| Item | Value |
|---|---|
| Sysmon install command | `sysmon64.exe -accepteula -i sysmonconfig-export.xml` |
| Kali static IP command | `ip addr add 10.0.0.5/24 dev eth1` |
| Kali interface enable command | `ip link set eth1 up` |
| Telemetry verification marker | `Phase0_CommandLine_Verification_Test` |
| Discovery command | `whoami` |
| Staged file path | `C:\Users\Public\payload.exe` |
| PowerShell pattern tested | `IEX (New-Object Net.WebClient).DownloadString(...)` |
| Registry persistence path | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` |
| EQL correlation field | `host.name` |
| EQL maxspan | `1h` |

---

## Phase 0: Sysmon and Audit Policy Setup

Sysmon was installed with the SwiftOnSecurity configuration file. Windows audit policy settings were also updated to improve process visibility and command-line logging.

The telemetry setup included:

- Sysmon installation
- Audit policy subcategory enforcement
- Command-line logging for process creation
- Advanced Audit Policy process creation auditing

### Screenshot Evidence

| Screenshot | What It Supports |
|---|---|
| `screenshots/01_Sysmon_Binary_And_Config_Ready.png` | Sysmon binary and configuration file ready |
| `screenshots/02_Sysmon_Installation_Complete.png` | Sysmon installed successfully |
| `screenshots/03_Force_Audit_Policy_Subcategory_Enabled.png` | Audit policy subcategory enforcement enabled |
| `screenshots/04_Include_Command_Line_In_Process_Creation_Enabled.png` | Command-line logging enabled |
| `screenshots/05_Advanced_Audit_Process_Creation_Enabled.png` | Advanced Audit Process Creation enabled |

### Observation

This phase mattered because the EQL rule depended on reliable endpoint telemetry. Without Sysmon and process command-line visibility, the later rule development would have been weaker or incomplete.

---

## Phase 1: Kali Network Setup

Kali Linux was configured with a stable lab IP address to keep testing predictable.

The static IP assigned to `eth1` was:

`10.0.0.5/24`

The Kali VMNet IP shown in the lab was:

`192.168.9.136`

### Screenshot Evidence

| Screenshot | What It Supports |
|---|---|
| `screenshots/06_Kali_Network_Interfaces_List.png` | Kali network interfaces before static IP assignment |
| `screenshots/07_Kali_Static_IP_Assigned.png` | Kali `eth1` configured with `10.0.0.5/24` |

### Observation

This helped keep the test environment stable when generating and reviewing activity from the lab machines.

---

## Phase 2: Telemetry Validation

Before building the EQL rule, process command-line telemetry was verified in Elastic.

The validation marker used was:

`Phase0_CommandLine_Verification_Test`

### Screenshot Evidence

| Screenshot | What It Supports |
|---|---|
| `screenshots/08_Elastic_Command_Line_Verification_Success.png` | Elastic showing populated `process.command_line` |

### Observation

This was one of the most important gates in the project.

The screenshot confirmed that process command-line data was visible in Elastic. This validated that telemetry was working before detection logic was written.

---

## Phase 3: Attack Simulation

The lab activity was designed to create endpoint telemetry for detection testing.

The simulated sequence included:

1. `whoami` execution
2. File creation at `C:\Users\Public\payload.exe`
3. PowerShell remote script retrieval attempt
4. Registry Run key persistence simulation

### Screenshot Evidence

| Screenshot | What It Supports |
|---|---|
| `screenshots/09_Phase1_Whoami_Execution.png` | `whoami` executed as `cs\administrator` |
| `screenshots/10_Phase1_Attack_Chain_Telemetry.png` | File staging and suspicious DNS lookup attempt |
| `screenshots/11_Phase1_PowerShell_Execution.png` | PowerShell `DownloadString` attempt with connection failure |
| `screenshots/12_Phase1_Persistence_Establishment.png` | Registry Run key persistence simulation |

### Observation

The PowerShell download attempt failed because the remote server was unreachable. This still created useful command-line telemetry, but it should not be described as a successful payload download.

The registry Run key was successfully added, but it was not included in the final EQL sequence rule.

---

## Phase 4: Elastic Telemetry Review

Elastic was used to confirm that attack-related activity was visible after the simulation.

### Screenshot Evidence

| Screenshot | What It Supports |
|---|---|
| `screenshots/13_Elastic_Attack_Telemetry_Verification.png` | Elastic review of attack-related process telemetry |

### Observation

This confirmed that Elastic contained searchable telemetry from the simulated activity.

The important point was not that every action triggered a detection. The important point was that the telemetry existed and could support rule development and investigation.

---

## Phase 5: EQL Rule Development

The final EQL rule was scoped to a two-stage sequence:

1. `whoami.exe` execution
2. File creation at `C:\Users\Public\payload.exe`

Both events had to occur on the same host.

```eql
sequence by host.name with maxspan=1h
  [process where process.name : "whoami.exe"]
  [file where file.path : "C:\\Users\\Public\\payload.exe"]
```

### Screenshot Evidence

| Screenshot | What It Supports |
|---|---|
| `screenshots/14_Multi_Stage_Rule_Activation.png` | EQL sequence rule enabled in Elastic |

### Observation

The rule was intentionally narrow and lab-focused.

`whoami.exe` alone can be noisy. File creation alone can also be common. The value of the rule came from correlating both actions on the same host within a time window.

The rule did not include PowerShell, DNS lookup, or registry persistence. Those were supporting telemetry, not part of the final alert logic.

---

## Phase 6: Rule Validation and Alert Generation

After enabling the rule, the attack sequence was re-run to confirm that the EQL rule generated an alert.

### Screenshot Evidence

| Screenshot | What It Supports |
|---|---|
| `screenshots/15_Full_Attack_Chain_Reexecution.png` | Attack sequence re-executed for validation |
| `screenshots/16_EQL_Sequence_Alert_Generation.png` | EQL alert generated successfully |

### Observation

Elastic generated an alert named:

`Multi-Stage Adversary Execution Chain`

This validated that the two-stage EQL sequence rule worked in the lab environment.

---

## Phase 7: MITRE ATT&CK Coverage Review

The Security Onion coverage view was used to review mapped ATT&CK detection coverage.

### Screenshot Evidence

| Screenshot | What It Supports |
|---|---|
| `screenshots/17_MITRE_ATT&CK_Detection_Coverage.png` | MITRE ATT&CK coverage overview |

### Observation

This screenshot showed mapped rule coverage across ATT&CK techniques.

It should be interpreted as a coverage overview, not proof that the custom EQL rule covered every highlighted technique.

---

## Evidence Interpretation Notes

These notes keep the project explanation accurate:

- The EQL rule detected a two-stage sequence, not the full four-stage simulation.
- The PowerShell `DownloadString` command was attempted, but the remote server connection failed.
- The registry Run key was created, but it was not part of the final EQL rule.
- The MITRE ATT&CK screenshot shows mapped coverage, not full detection validation for this custom rule.
- `whoami.exe` alone can be noisy in real environments.
- The value of the rule came from sequence correlation using `host.name`.

---

## Key Lessons Learned

1. Telemetry validation should happen before detection rule writing.
2. Command-line visibility makes process telemetry much more useful.
3. EQL sequence rules are useful for correlating related events over time.
4. `host.name` prevents unrelated events from different hosts from satisfying the same sequence.
5. A failed PowerShell download can still produce useful telemetry.
6. Registry persistence can be reviewed as supporting telemetry even if it is not part of the final rule.
7. MITRE coverage views are useful for understanding visibility and gaps, but they should not be overstated.

---

## Improvements for a Future Version

Future improvements could include:

- A separate EQL rule for suspicious PowerShell command-line patterns
- A separate rule for registry Run key persistence
- More complete Sysmon Event ID references for each event type
- Testing against benign administrator activity to reduce false positives
- Testing across multiple hosts
- More detailed alert screenshots showing event fields
- A timeline mapping each simulated action to the matching Elastic evidence

---

## Screenshot Map

| Screenshot | What It Supports |
|---|---|
| `screenshots/01_Sysmon_Binary_And_Config_Ready.png` | Sysmon binary and configuration file ready |
| `screenshots/02_Sysmon_Installation_Complete.png` | Sysmon installed successfully |
| `screenshots/03_Force_Audit_Policy_Subcategory_Enabled.png` | Audit policy subcategory enforcement enabled |
| `screenshots/04_Include_Command_Line_In_Process_Creation_Enabled.png` | Command-line logging enabled for process creation |
| `screenshots/05_Advanced_Audit_Process_Creation_Enabled.png` | Advanced Audit Process Creation enabled |
| `screenshots/06_Kali_Network_Interfaces_List.png` | Kali network interfaces before static IP assignment |
| `screenshots/07_Kali_Static_IP_Assigned.png` | Kali `eth1` configured with `10.0.0.5/24` |
| `screenshots/08_Elastic_Command_Line_Verification_Success.png` | Elastic showing populated `process.command_line` |
| `screenshots/09_Phase1_Whoami_Execution.png` | `whoami` executed as `cs\administrator` |
| `screenshots/10_Phase1_Attack_Chain_Telemetry.png` | File staging and suspicious DNS lookup attempt |
| `screenshots/11_Phase1_PowerShell_Execution.png` | PowerShell `DownloadString` attempt with connection failure |
| `screenshots/12_Phase1_Persistence_Establishment.png` | Registry Run key persistence simulation |
| `screenshots/13_Elastic_Attack_Telemetry_Verification.png` | Elastic review of attack-related process telemetry |
| `screenshots/14_Multi_Stage_Rule_Activation.png` | EQL sequence rule enabled in Elastic |
| `screenshots/15_Full_Attack_Chain_Reexecution.png` | Attack sequence re-executed for validation |
| `screenshots/16_EQL_Sequence_Alert_Generation.png` | EQL alert generated successfully |
| `screenshots/17_MITRE_ATT&CK_Detection_Coverage.png` | MITRE ATT&CK coverage overview |