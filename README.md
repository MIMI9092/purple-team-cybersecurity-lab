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

## Safety

This repository documents activity performed only inside an authorized,
isolated laboratory. Passwords, session cookies, API keys, Kerberos ticket
files, password hashes, and other reusable secrets are intentionally excluded.
