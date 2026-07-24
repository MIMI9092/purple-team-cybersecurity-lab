# CBI Cybersecurity Internship Lab

## Project

**Title:** Offensive and Defensive Cybersecurity Lab  
**Student:** Mariam Ibni  
**Company:** CBI  
**Supervisor:** Yassine Medouar

## Current Objective

Build and evaluate a segmented purple-team laboratory that combines:

- External attack simulation
- DMZ exploitation
- Internal network pivoting
- Active Directory attacks
- Centralized monitoring with Splunk
- Network detection with OPNsense and Suricata
- Automated response with Shuffle SOAR

## Navigation

### Infrastructure

- [[Network Architecture]]
- [[Assets and Addressing]]
- [[Firewall and Routing]]
- [[Security Monitoring Architecture]]

### Attack Chain

- [[Attack Chain Overview]]
- [[01 - External Reconnaissance]]
- [[02 - DVWA Web Exploitation]]
- [[03 - DMZ Reverse Shell]]
- [[04 - DMZ to Windows Pivot]]
- [[05 - Active Directory Discovery]]
- [[06 - Kerberoasting]]
- [[07 - Offline Password Recovery]]
- [[08 - Valid Account Validation]]
- [[09 - Authorization Assessment]]

### Defensive Work

- [[Detection Coverage Matrix]]
- [[Splunk Data Sources and Searches]]
- [[Detection Gap Register]]
- [[Defensive Improvement Backlog]]
- [[Splunk and Shuffle Integration]]

### Documentation

- [[Evidence Index]]
- [[Project Progress]]
- [[Report Outline]]

## Current Status

| Phase | Status |
|---|---|
| Infrastructure deployment | Completed |
| External reconnaissance | Completed |
| DVWA SQL injection | Completed |
| DMZ command execution | Completed |
| Reverse shell | Completed |
| Pivot through DVWA | Completed |
| Windows 10 access | Completed |
| Active Directory discovery | Completed |
| Kerberoasting | Completed |
| Offline password recovery | Completed |
| Valid-account validation | Completed |
| Authorization assessment | Next |
| Lateral movement | Planned |
| Persistence simulation | Planned |
| C2 simulation | Planned |
| Defensive improvements | Planned |
| Detection rules and playbooks | Planned |

## Current Attack Position

The lab has progressed from an external Kali host to a validated Active Directory service-account credential:

`Kali -> OPNsense NAT -> DVWA -> Windows 10 -> AD-DC01`

The next activity is to determine what the recovered `svc_sql` account is authorized to access without assuming that valid authentication provides administrative privileges.

## Safety Notes

- This vault documents an isolated and authorized laboratory.
- Do not store passwords, session cookies, API keys, or active tokens here.
- Use `[REDACTED]` when a secret appears in evidence.
- Take VM snapshots before changes that affect authentication, routing, or security controls.
