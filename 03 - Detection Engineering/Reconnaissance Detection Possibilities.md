---
title: Reconnaissance Detection Possibilities
project: Purple Team Cybersecurity Lab
updated: 2026-08-12
status: Design Baseline
---

# Reconnaissance Detection Possibilities

## Purpose

Define observable reconnaissance behaviors before selecting alerts or building
SOAR playbooks. External reconnaissance and internal post-compromise discovery
are treated as separate SOC use cases because their risk, telemetry, false
positives, escalation paths, and response options are different.

## Offensive Actions Mapped from the Lab

### External reconnaissance

- Kali `192.168.111.144` scanned the OPNsense WAN address
  `192.168.111.128`.
- Nmap found the published DVWA service on TCP `8080` and identified filtered
  ports.
- Nmap service scripts and WhatWeb fingerprinted Apache, Debian, PHP, DVWA,
  redirects, and cookies.
- Gobuster enumerated application content such as `/config/`, `/docs/`,
  `/external/`, `/phpinfo.php`, `/robots.txt`, and `/setup.php`.

### Internal service discovery

- After the DVWA compromise, the DMZ host `10.10.60.10` was used as a Chisel
  pivot.
- Probes targeted internal services including Kerberos `88`, LDAP `389`, SMB
  `445`, and WinRM `5985`.
- Existing D10 covers grouped DMZ-originated TCP SYN discovery behavior.

## Use-Case Segmentation

| Use case | Security question | Proposed playbook |
|---|---|---|
| External reconnaissance | Is an external source actively mapping or fingerprinting the published attack surface? | `PB-RECON-01 - External Reconnaissance Triage` |
| Internal discovery | Is a DMZ or workstation asset unexpectedly discovering internal services or hosts? | `PB-RECON-02 - Internal Service Discovery Triage` |

The first implementation target is `PB-RECON-01`. PB-RECON-02 will later use
D10 and will have a higher escalation priority because internal discovery can
indicate an established foothold.

## External Reconnaissance Detection Possibilities

| Candidate | Behavior | Telemetry | Strength | Main false positives | Decision |
|---|---|---|---|---|---|
| R1 | IDS signature for Nmap user agent or scan behavior | Suricata alerts in `index=opnsense` | High fidelity when present, low development cost | Approved scanners and security testing | Retain as supporting signal, not the only analytic |
| R2 | One source probes many WAN ports in a short window | OPNsense `filterlog` | Behavioral and tool-independent | Monitoring systems, vulnerability scanners, retransmissions | Strong primary candidate after threshold validation |
| R3 | Suspicious fingerprinting user agents such as Nmap or WhatWeb | DVWA Docker access logs | Directly maps to offensive activity | Authorized testing; trivial user-agent spoofing | Useful supporting alert or enrichment |
| R4 | High request rate across many distinct application paths | DVWA Docker access logs | Detects directory/content enumeration without relying on a tool name | Crawlers, monitoring, legitimate QA | Strong primary candidate after application baseline |
| R5 | Burst of `403` and `404` responses across distinct URIs | DVWA Docker access logs | Useful evidence of forced browsing | Broken links, crawlers, application testing | Combine with R4 rather than alert alone |
| R6 | Correlation of network scan plus web fingerprinting or content enumeration from the same source | OPNsense/Suricata plus DVWA logs | Highest-confidence external recon case | Approved penetration tests | Preferred high-confidence correlation once individual fields are validated |

## Internal Discovery Detection Possibilities

| Candidate | Behavior | Telemetry | Strength | Main false positives | Decision |
|---|---|---|---|---|---|
| IR1 | DMZ source reaches multiple internal service ports | OPNsense `filterlog` | Already validated as D10 | Administrative monitoring and approved scanners | Reuse D10 for PB-RECON-02 |
| IR2 | One source reaches multiple internal hosts | OPNsense `filterlog` | Detects horizontal discovery | Inventory systems and management servers | Add after a multi-host replay and baseline |
| IR3 | Unexpected access to AD discovery ports `53/88/389/445` | OPNsense `filterlog` | Strong when the source zone should not query AD | Approved application dependencies | Enrichment or higher-confidence condition |
| IR4 | Network discovery followed by remote management or authentication | OPNsense plus Windows Security | Strong evidence of progression | Authorized administration | Escalate to lateral-movement playbook rather than keep as recon only |

## Recommended External Recon Detection Model

Use a tiered model instead of generating an incident for every request:

1. Preserve IDS signatures and suspicious user agents as evidence.
2. Use behavioral thresholds for port scanning and content enumeration.
3. Generate the highest-confidence alert when network and web reconnaissance
   occur from the same source in a bounded time window.
4. Suppress duplicates by source and target while retaining counts and
   timestamps for the analyst.

## Required Analyst Context

PB-RECON-01 must present:

- Source IP and source classification.
- Target WAN address, published service, and affected application.
- First and last observed timestamps.
- Ports probed and firewall actions.
- Request count, distinct URI count, and response-code distribution.
- User agents and matching Suricata signatures.
- Whether the source is an approved scanner or purple-team asset.
- Whether exploitation attempts followed the reconnaissance.

## Analyst Decisions

| Decision | Meaning | Next action |
|---|---|---|
| Authorized scanning | Known vulnerability scan or approved exercise | Document owner, scope, and close or suppress for the approved window |
| Benign automation | Search engine, monitoring, or expected crawler | Document evidence and close; consider allowlist after validation |
| Suspicious reconnaissance | Unapproved mapping or enumeration without exploitation evidence | Escalate to SOC investigation and increase monitoring |
| Reconnaissance followed by exploitation | Related SQL injection, command execution, callback, or authentication activity | Escalate as an incident to the relevant exploitation playbook |
| Insufficient telemetry | Required logs or entity context missing | Escalate telemetry issue; do not claim malicious activity |

## Escalation Baseline

| Situation | Priority | Owner | Target response |
|---|---:|---|---|
| Signature or threshold match only | Medium | Tier 1 SOC analyst | Review within 30 minutes |
| Network scan plus web enumeration | High | Tier 1/2 SOC analyst | Review within 15 minutes |
| Recon followed by exploitation evidence | High or Critical | Incident lead and application owner | Immediate escalation |
| Approved scanner not allowlisted | Informational process issue | Detection engineer or asset owner | Tune after ownership validation |
| Telemetry unavailable or stale | Operational | SIEM/platform owner | Restore visibility before closure |

## Response Philosophy

PB-RECON-01 begins as an investigation and escalation playbook. It must not
automatically block an external source based only on reconnaissance. A future
temporary block may be offered with analyst approval when confidence is high,
the source is not allowlisted, exploitation evidence exists, and rollback is
available.

## Next Validation Work

1. Inspect the existing Phase 1 saved searches `D01`, `P1-R02`, `P1-R03`,
   `P1-R04`, and `P1-C01` and record their exact intent and output fields.
2. Test each candidate over All Time to confirm which historical offensive
   actions it represents.
3. Select the minimum alert set needed by PB-RECON-01.
4. Define a stable alert schema before creating the Shuffle workflow.
