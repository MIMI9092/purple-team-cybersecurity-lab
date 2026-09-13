# 05A - Local Privilege Escalation

## Status

**Completed and live-validated. Splunk correlation validation is pending.**

## Objective

Add one controlled, deterministic privilege-escalation step after Windows and
Active Directory discovery. The scenario demonstrates a transition from the
compromised but non-administrative domain account `LAB\svc_web` to
`NT AUTHORITY\SYSTEM` without introducing a second large exploit chain.

## Placement in the Attack Chain

```text
DMZ compromise and SOCKS pivot
  -> WinRM access as LAB\svc_web
  -> Windows / AD discovery
  -> writable lab service script
  -> service executes the script as LocalSystem
  -> SYSTEM proof artifact
  -> user-level persistence and C2 simulation
```

This step fits after discovery because the attacker must first identify the
endpoint, account context, service configuration and writable file. It fits
before PB05 because the demonstration should establish privilege escalation as
its own attack stage rather than incorrectly claiming that the user-level Run
key was privileged persistence.

Local SYSTEM on `WIN10-CLIENT01` does not imply Domain Admin or privileged
access to `AD-DC01`. After proving this local boundary crossing, later
Kerberoasting and authorization tests can continue under their original domain
identities. PB05 also remains an intentionally user-level persistence use case;
the project should not relabel it as SYSTEM persistence.

## Controlled Vulnerability

The lab fixture creates:

| Item | Value |
|---|---|
| Service | `PFA-Lab-Updater` |
| Service identity | `LocalSystem` |
| Protected wrapper | `C:\Program Files\PFA-Lab\PFA-Lab-Updater.exe` |
| Writable service script | `C:\ProgramData\PFA-Lab\PrivilegeEscalation\PFA-Lab-Updater.ps1` |
| Delegated writer | `LAB\svc_web` / `S-1-5-21-722403993-16450863-2166090910-1106` |
| Proof artifact | `C:\ProgramData\PFA-Lab\PrivilegeEscalation\system-proof.json` |
| Proof event | Application `9101`, source `PFA-Lab-PrivilegeEscalation` |
| Marker | `PFA_SERVICE_PRIVESC_01` |

The service executable remains administrator-controlled. Only the script it
loads is intentionally writable, and the account receives service query/start
rights without service reconfiguration or deletion rights.

## Evidence Story

The proof is not merely a file containing a username. The replay records both
sides of the transition:

```text
LAB\svc_web
  -> records its SID, baseline hash, ACL and write timestamp
  -> modifies the exact lab service script
  -> starts only PFA-Lab-Updater
  -> protected wrapper launches PowerShell as LocalSystem
  -> PowerShell records SID S-1-5-18, PID, parent PID and source hash
  -> structured proof and Application event 9101 are verified
```

The resulting Windows telemetry is expected to include:

- Security `4663`: the exact script written by `LAB\svc_web`;
- Security `4688`: service wrapper to PowerShell with SYSTEM subject context;
- PowerShell Operational `4104`: the `PFA_SERVICE_PRIVESC_01` payload;
- System `7036`: the named service state transition;
- Application `9101`: a supplemental SYSTEM proof marker. Its write result is
  captured inside the proof JSON, while failure of the attacker session to read
  the Application log does not invalidate the native Security/PowerShell chain.

Splunk and Shuffle remain off during the attack-only replay. The endpoint keeps
the events locally so the Universal Forwarder can send them after monitoring is
started for detection validation. Existing PB05 collection covers Security and
PowerShell; `System` and `Application` must also be confirmed. The toolkit
contains `windows\privilege-escalation-inputs.conf.example` as a merge-only
sample for those two channels.

## Safety Boundaries

- Hard-coded to the documented lab addresses, host, account SID, service, file
  and proof path.
- The fixture is installed only from an elevated local session on
  `WIN10-CLIENT01`; the replay cannot create a privileged service.
- The proof creates no user, group membership, credential, shell, persistence,
  firewall rule or network listener.
- A stale proof, changed baseline, unexpected service path, running service or
  identity mismatch causes a fail-closed result.
- Repetition requires the explicit elevated reset script.

## Automation

Toolkit:

```text
10 - Automation\Purple-Team-Attack-Replay
```

One-time endpoint fixture installation:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Install-PfaLabPrivilegeEscalation.ps1
```

Attack-only replay from the Windows controller:

```powershell
.\Invoke-PurpleTeamReplay.ps1 -Scenario WIN10-ServicePrivilegeEscalation -Mode DryRun
.\Invoke-PurpleTeamReplay.ps1 -Scenario WIN10-ServicePrivilegeEscalation -Mode Live -ConfirmLive
```

Reset on the endpoint before another replay:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Reset-PfaLabPrivilegeEscalation.ps1
```

## Live Validation

The controlled replay completed successfully on 9 September 2026.

| Field | Verified result |
|---|---|
| Run ID | `PTR-20260909T162419Z-355a0dc0` |
| Writer | `LAB\svc_web` (`S-1-5-21-722403993-16450863-2166090910-1106`) |
| Executor | `NT AUTHORITY\SYSTEM` (`S-1-5-18`) |
| Boundary | `SVC_WEB_TO_SYSTEM_PROVED` |
| Script before SHA-256 | `8E6D74767EC00DE1A619A8AB2BBDFCCBD08CAFA87B968E5A0D3AC6BAEDECF235` |
| Script after SHA-256 | `DF4F2BC01689B1C5A83141BDD9D8086A9DA380EF72A67F5504978552C85EDDE0` |
| SYSTEM process / parent PID | `6420` / `3672` |
| Application event write | `WRITTEN` |
| Service state after proof | `Stopped` |
| Monitoring / response | Not started |

The attacker session could not read the Application event back
(`application_event_observed_by_attacker=false`), but the SYSTEM payload
reported a successful write with no write error. This does not weaken the
identity proof: the structured artifact independently records SYSTEM SID
`S-1-5-18`, process lineage, timestamps, source hash and the exact file change.
The Enterprise Developer license is now active, so the later Splunk test can
proceed. It must confirm Application `9101` alongside Security
`4663`/`4688`, PowerShell `4104` and System `7036`.

Saved evidence:

```text
10 - Automation\Purple-Team-Attack-Replay\evidence\PTR-20260909T162419Z-355a0dc0
```

## ATT&CK Mapping

- Primary: `T1574.010`, Services File Permissions Weakness
- Secondary: `T1569.002`, Service Execution
- Secondary: `T1059.001`, PowerShell

The scenario is not labeled `T1068` because it does not exploit a kernel or
software vulnerability. It demonstrates an intentionally weak service-file
permission boundary. `T1543.003` describes the elevated administrative setup of
the lab fixture, not the attacker phase: `LAB\svc_web` does not create,
reconfigure, or replace the service executable.
