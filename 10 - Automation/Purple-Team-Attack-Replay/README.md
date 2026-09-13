# Purple Team Attack Replay Toolkit

## Purpose

This toolkit will replay the project's validated attack scenarios inside the
authorized laboratory. It is an orchestration layer, not an autonomous attack
platform. The Windows host coordinates VMware and Kali; attacker activity is
performed from Kali and reaches internal systems through the same controlled
pivots used during manual validation. This toolkit is attack-only: it does not
start Splunk or Shuffle and does not run detection, approval, containment, or
response verification.

The implemented foundation provides:

- a lab-only address allowlist;
- VMware inventory and configuration checks;
- `DryRun`, `Status`, `Preflight`, VM-only `Prepare`, and read-only
  `FootholdPreflight` and `AttackPathPreflight` modes;
- an explicit PB05 persistence-and-C2 execution plan;
- a fail-closed `Live` PB05 replay built from the original Kali history and the
  preserved endpoint script;
- a separate, deterministic Windows service privilege-escalation replay that
  preserves the `LAB\svc_web` file-writer and `NT AUTHORITY\SYSTEM` executor as
  distinct evidence;
- a locked `Cleanup` mode until exact cleanup checks are implemented.

## Execution Model

```text
Windows host controller
        |
        v
Kali attacker VM
        |
        v
DMZ foothold and SOCKS pivot (127.0.0.1:1080)
        |
        v
pypsrp Microsoft.PowerShell session to WIN10-CLIENT01
        |
        v
PB05 persistence and Chisel callback artifacts
        |
        v
Attack-chain evidence handoff (replay stops here)
```

The privilege-escalation scenario follows the same network path but stops at a
different boundary:

```text
LAB\svc_web PSRP session
        |
        v
modifies one delegated lab service script
        |
        v
PFA-Lab-Updater service starts as LocalSystem
        |
        v
SYSTEM PowerShell writes a structured proof and Application event 9101
```

Direct management access to Windows is reserved for health checks and final
cleanup. It is not the primary attack path.

## Initial Setup

1. Copy `config/lab.example.psd1` to `config/lab.local.psd1`.
2. Fill in the missing Kali VMX path and confirm the local VMware paths.
3. Do not place passwords, API keys, hashes, or session tokens in the file.
4. Keep `EnableLiveExecution = $false` until dry-run and preflight output have
   been reviewed.

## Current Commands

Run from Windows PowerShell:

```powershell
Set-Location 'C:\Users\DELL\Documents\CBI Internship\10 - Automation\Purple-Team-Attack-Replay'

.\Invoke-PurpleTeamReplay.ps1 -Scenario PB05-PersistenceC2 -Mode DryRun
.\Invoke-PurpleTeamReplay.ps1 -Scenario PB05-PersistenceC2 -Mode Status
.\Invoke-PurpleTeamReplay.ps1 -Scenario PB05-PersistenceC2 -Mode Preflight
.\Invoke-PurpleTeamReplay.ps1 -Scenario PB05-PersistenceC2 -Mode Prepare
.\Invoke-PurpleTeamReplay.ps1 -Scenario PB05-PersistenceC2 -Mode ArtifactDiscovery
.\Invoke-PurpleTeamReplay.ps1 -Scenario PB05-PersistenceC2 -Mode FootholdPreflight
.\Invoke-PurpleTeamReplay.ps1 -Scenario PB05-PersistenceC2 -Mode AttackPathPreflight
.\Invoke-PurpleTeamReplay.ps1 -Scenario PB05-PersistenceC2 -Mode Live -ConfirmLive
```

## Windows Service Privilege-Escalation Scenario

This scenario is intentionally separate from PB05. It models a services-file-
permissions weakness using one lab-owned service and one delegated script. It
does not add `svc_web` to Administrators, exploit a kernel vulnerability, create
a new privileged account, or open another shell.

First copy these two files to `WIN10-CLIENT01` and run the installer once from
an elevated Windows PowerShell session:

```text
windows\Install-PfaLabPrivilegeEscalation.ps1
windows\Reset-PfaLabPrivilegeEscalation.ps1
```

On the Windows endpoint:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Install-PfaLabPrivilegeEscalation.ps1
```

The installer creates the protected service wrapper under `Program Files`, an
on-demand `LocalSystem` service named `PFA-Lab-Updater`, and one writable script
under `C:\ProgramData\PFA-Lab\PrivilegeEscalation`. Only the exact documented
SID receives script `Modify` and service query/start rights. The installer also
enables process creation, command-line, PowerShell script-block and exact-file
write auditing. It prints `InstalledReady` only after checking the service,
hash, ACL and audit rule (`FixtureStatus = INSTALLED_READY`).

Security and PowerShell collection were already documented for PB05. Before
the later Splunk validation, confirm that the Universal Forwarder also collects
`System` and `Application`. A merge-only example is provided at
`windows\privilege-escalation-inputs.conf.example`; do not create duplicate
stanzas if those channels already exist.

Then run from the Windows controller:

```powershell
.\Invoke-PurpleTeamReplay.ps1 -Scenario WIN10-ServicePrivilegeEscalation -Mode DryRun
.\Invoke-PurpleTeamReplay.ps1 -Scenario WIN10-ServicePrivilegeEscalation -Mode Status
.\Invoke-PurpleTeamReplay.ps1 -Scenario WIN10-ServicePrivilegeEscalation -Mode Prepare
.\Invoke-PurpleTeamReplay.ps1 -Scenario WIN10-ServicePrivilegeEscalation -Mode FootholdPreflight
.\Invoke-PurpleTeamReplay.ps1 -Scenario WIN10-ServicePrivilegeEscalation -Mode AttackPathPreflight
.\Invoke-PurpleTeamReplay.ps1 -Scenario WIN10-ServicePrivilegeEscalation -Mode Live -ConfirmLive
```

`Live` records the baseline hash and ACL, writes a hash-verified harmless proof
payload as `LAB\svc_web`, starts only `PFA-Lab-Updater`, and requires a fresh
proof containing SID `S-1-5-18`. The SYSTEM payload records whether its
supplemental Application event `9101` write succeeded; inability of the
unprivileged attacker session to query that log does not invalidate the SYSTEM
proof. Splunk and Shuffle remain off so their startup and response activity
cannot contaminate the attack replay; Windows event logs can be forwarded
afterward once the required input channels are enabled.

Before repeating the scenario, run this locally in an elevated PowerShell on
`WIN10-CLIENT01`:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Reset-PfaLabPrivilegeEscalation.ps1
```

The reset stops only the named lab service, restores its baseline script, and
removes only the proof artifact. Audit settings remain enabled because they may
also support the rest of the project.

### First Live Validation

Run `PTR-20260909T162419Z-355a0dc0` completed with exit code `0` and verified
the boundary `SVC_WEB_TO_SYSTEM_PROVED`. The saved state distinguishes
`LAB\svc_web` (file writer) from `NT AUTHORITY\SYSTEM` (service-launched
executor), including both SIDs, before/after script hashes, timestamps and
process lineage. The Application `9101` write reported `WRITTEN`; the
unprivileged attacker session could not read the event back. Splunk and Shuffle
were stopped, so central telemetry validation remains a separate later step.

Open the GNS3 desktop application and the required lab project first; GNS3
manages its own GNS3 VM. `Prepare` does not start or control that VM. It starts
only OPNsense, the standalone DMZ-DVWA VM, Kali, AD-DC01, and WIN10-CLIENT01
when they are currently stopped. Splunk and Shuffle are explicit exclusions:
`Status`, `Preflight`, and `Prepare` fail closed if either monitoring VM is
running. The runner reports this condition but never shuts those VMs down
automatically.

`Prepare` does not launch Chisel, open a WinRM session, or create persistence.

`AttackPathPreflight` connects to Kali over SSH and checks the exact PB05 path:

```text
Kali 127.0.0.1:1080 -> DMZ Chisel pivot -> WIN10-CLIENT01:5985
```

It uses a temporary Proxychains configuration and performs only a TCP
connection check. If SOCKS port `1080` is absent, it fails closed without
touching Windows.

`FootholdPreflight` checks the earlier stage without exploiting DVWA. It verifies
the external DVWA entry point at `192.168.111.128:8080`, listener availability
on Kali TCP `443`, and the local Chisel candidates that could be transferred to
the older DVWA container.

`ArtifactDiscovery` reads only four fixed Kali sources: Bash history, Zsh
history, and the two original reverse-shell/pivot session recordings. It
returns only lines related to Chisel, Proxychains, Evil-WinRM, transfers,
listeners, and PB05. It redacts password flags, cookies, authorization values,
Kerberos material, and long hexadecimal secrets; commands likely to contain
credential material are omitted completely before anything leaves Kali. The
console output is not copied into the local evidence log automatically.

`Live` requires `EnableLiveExecution = $true` in the ignored local configuration
and the explicit `-ConfirmLive` switch. It stages a hash-verified temporary
helper on Kali, asks interactively for the Kali SSH, Kali sudo, DVWA admin, and
`LAB\svc_web` credentials, and does not write those credentials to configuration
or evidence files. It reproduces this path:

```text
Kali pypsrp -> temporary loopback relay -> DMZ SOCKS 1080 -> WIN10-CLIENT01
```

The loopback relay is created only for the live run. The isolated pypsrp client
at `/home/kali/.local/share/pb05-replay/venv` uses NTLM with WSMan message
encryption and explicitly opens the `Microsoft.PowerShell` configuration, while
the relay still sends every connection through the compromised DMZ host. The
Windows password is read from a private file descriptor and is not placed in a
command line, environment, history, evidence output, or a temporary file. The
preserved endpoint Chisel binary must already exist with the documented SHA-256
hash; the payload fails closed before changing persistence if that prerequisite
is absent or different.

After successful payload verification, the PSRP runspace is disconnected rather
than closed. This keeps the callback process alive for the endpoint's configured
two-hour WinRM idle window. The HKCU Run value is the durable persistence
mechanism; the disconnected runspace only preserves the live callback long
enough for controlled detection and response validation.

The endpoint payload recreates the preserved `PFA-Lab-Tunnel` script semantics,
sets the exact HKCU Run value, starts the callback to Kali, verifies reverse
SOCKS `1082`, and stops at the attack-chain boundary. `Cleanup` remains locked.

## Safety Controls

- Every configured address must match the hard-coded project allowlist.
- Splunk and Shuffle must be stopped before attack-only preparation or replay.
- The runner never starts or stops Splunk or Shuffle.
- Live mode requires both a local configuration opt-in and an explicit command
  switch.
- No reusable secret is stored or written to the evidence directory.
- Every run receives a unique run ID.
- Live replay stops at the attack-chain evidence boundary.
- The privilege-escalation fixture uses a protected wrapper; only its exact lab
  script is writable by the documented `svc_web` SID.
- The proof payload records identity and process metadata only. It creates no
  administrator, shell, credential, persistence or network listener.
- Cleanup is a separate explicit mode and targets only the named PB05 process
  and Run value.
- Password spraying remains excluded from the initial implementation.

## Remaining Implementation Order

1. Validate privilege-escalation telemetry ingestion and correlation now that
   the Enterprise Developer license is active.
2. Extend replay coverage to PB04 identity activity when required.
3. Add PB03 web-exploitation, reverse-shell, reconnaissance and pivot scenarios
   when required.
4. Build a combined safe demonstration mode and evidence report generation.
