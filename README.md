# Purple Team Cybersecurity Lab

Obsidian knowledge base documenting a segmented cybersecurity laboratory built
for an internship project at CBI.

## Project Scope

- Segmented network architecture using VMware, GNS3, OPNsense, and Cisco routing
- External reconnaissance and controlled DVWA exploitation
- DMZ command execution and pivoting into an internal Windows network
- Active Directory discovery and Kerberoasting
- Centralized telemetry and detection engineering with Splunk
- Network monitoring with OPNsense and Suricata
- Workflow automation with Shuffle SOAR
- Detection-gap analysis and defensive improvement planning

## Current Defensive Status

- Phase 1 reconnaissance detections: completed and live-validated.
- Phase 2 web-exploitation detections: completed and live-validated.
- Phase 3 pivot/internal-access detections: completed and live-validated.
- OPS01 telemetry health: completed and live-validated.
- Saved-alert audit: 21 enabled production alerts and Application-shared.
  Standard searches are staggered across the five-minute cycle; D13, D15, and
  D18 use independently staggered 15-minute schedules after validation.
- Event 4771 failure auditing and the D03 manual detection search are validated.
  A historical screenshot records D03 enabled; re-audit its current scheduled
  state and preserve trigger evidence before the final report.
- SOAR playbooks PB02 and PB03 are functionally complete for the current lab
  scope. PB01 is retained as historical experimentation.
- PB04 Active Directory credential-access and account-abuse response is
  complete: IRP2 monitoring and IRP3 analyst-approved temporary account
  disable were live-validated with AD/Splunk verification, fail-closed outage
  behavior, final audit, cleanup, and manual account recovery.
- PB05 endpoint persistence/C2 response is complete for CRP1 through CRP4,
  including native analyst approval and independently verified containment.
- The controlled Windows service-file privilege-escalation replay is complete
  and proves `LAB\svc_web` to `NT AUTHORITY\SYSTEM`; central Splunk correlation
  remains pending.
- The Enterprise Developer license is active with a 10 GB/day quota through
  6 March 2027. The 12-panel full executive dashboard is restored and
  live-validated against historical indexed data.

## Start Here

Open the repository as an Obsidian vault, then begin with:

`00 - Dashboard/Project Dashboard.md`

## Documentation Conventions

- Use Mermaid for architecture, attack-chain, data-flow, and response diagrams.
- Keep commands, paths, addresses, account names, and captured output in normal code blocks.
- Redact credentials, tokens, hashes, and other reusable secrets before committing evidence.

## Structure

| Folder | Purpose |
| --- | --- |
| `00 - Dashboard` | Project navigation and attack-chain overview |
| `01 - Infrastructure` | Architecture, assets, addressing, routing, and monitoring |
| `02 - Attack Chain` | Phase-by-phase offensive activity and observations |
| `03 - Detection Engineering` | Data sources, searches, and coverage |
| `04 - SOAR Playbooks` | Splunk and Shuffle integration |
| `05 - Detection Gaps` | Confirmed visibility and detection weaknesses |
| `06 - Defensive Improvements` | Prioritized hardening backlog |
| `07 - Evidence Index` | Screenshot and evidence catalog |
| `08 - Meetings and Progress` | Project status and decisions |
| `09 - Report Material` | Report planning |
| `10 - Automation` | Sanitized attack-replay tooling, safety checks, and example configuration |

## Safety

This repository documents activity performed only inside an authorized,
isolated laboratory. Passwords, session cookies, API keys, Kerberos ticket
files, password hashes, and other reusable secrets are intentionally excluded.
