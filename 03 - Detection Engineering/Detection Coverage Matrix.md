# Detection Coverage Matrix

| Activity | Primary telemetry | Confirmed? | Gap / Next action |
|---|---|---:|---|
| Nmap scan | Suricata, OPNsense, Splunk | Yes | Build correlation by source and destination |
| WhatWeb fingerprinting | DVWA access logs | Yes | Create user-agent detection |
| Gobuster enumeration | DVWA access logs | Yes | Detect URI volume and 403/404 bursts |
| SQLmap SQL injection | DVWA Docker logs | Yes | D02, D04, and D05 created and live-validated |
| SQL injection IDS signature | Suricata | Partial | Web-log detections compensate; review enabled ET WEB rules |
| Command injection | DVWA access logs | Partial | D06 validated; POST body remains absent from access logs |
| Reverse shell | DVWA plus OPNsense logs | Yes | D07 and Critical D08 correlation live-validated; add endpoint process telemetry |
| Correlated web compromise | DVWA plus OPNsense logs | Yes | D08 correlated command POST and callback to the same peer within five minutes |
| Chisel tunnel from DMZ | OPNsense filterlog + Suricata EVE flow | Yes | D09 live-validated against a genuine long-lived WebSocket Chisel flow |
| Internal service discovery from DMZ | OPNsense filterlog | Yes | D10 live-validated across four internal service ports |
| Allowed DMZ-to-SMB or WinRM | OPNsense filterlog | Yes | D11 live-validated; temporary exposure remains a hardening issue |
| WinRM lateral access | OPNsense + Windows Security | Yes | D12 live-validated by correlating the network connection and type-3 logon |
| Full web-compromise-to-internal chain | DVWA + OPNsense + Windows Security | Yes | Critical D13 live-validated across four stages |
| AD discovery | Windows Security and PowerShell logs | Partial | Network discovery is covered by D10; command-specific AD discovery analytics remain optional |
| Writable service script privilege escalation | Security 4663 + 4688, PowerShell 4104, SCM 7036, Application 9101 | Partial | `LAB\svc_web` to SYSTEM attack replay live-validated in `PTR-20260909T162419Z-355a0dc0`; Splunk ingestion and correlation validation pending |
| Kerberoasting | AD Event 4769 | Yes | D14 live-validated for RC4 user-managed SPN requests |
| Offline cracking | Kali only | No central log | Preserve operator evidence |
| Valid account after Kerberoasting | AD Events 4769 and 4768 | Yes | Critical D15 live-validated within a 48-hour correlation window |
| SMB authorization assessment | Windows Security plus operator evidence | Partial | Add 5140/5145 collection and correlation |
| Run-key persistence | Event 4688 and PowerShell 4104 | Yes | D17 live-validated; direct registry-change telemetry remains an enrichment gap |
| Chisel execution | Event 4688 + Suricata EVE flow | Yes | Critical D18 endpoint/network correlation live-validated |
| Password spray success | AD Event 4768 | Yes | Baseline normal TGT volume |
| Password spray failure | AD Event 4771 | Yes | Two `0x18` failures from `10.10.30.20` were ingested and returned by D03; re-audit the current scheduled-alert state and preserve trigger evidence |
| Splunk ingestion outage | Forwarder/internal logs + index freshness | Yes | OPS01 live-validated for source silence and ingestion delay |

## Detection Program Status

The primary Phase 1, Phase 2, and Phase 3 detection objectives are complete and
live-validated. The remaining priority is not to create more alerts for every
raw event; it is to improve data quality, baselining, field normalization,
scheduler performance, and response workflow quality.

Open coverage work:

1. Re-audit D03's current enabled/scheduled state and preserve a triggered-alert
   or scheduler-history result; its Event 4771 telemetry and manual search are
   already validated.
2. Add direct registry-change telemetry to enrich D17.
3. Establish approved DMZ egress and management-path allowlists.
4. Baseline D13, D15, and D18 runtime because their correlation windows are
   intentionally larger than the other production searches.
5. Add SOAR enrichment and analyst-approved reversible containment only for
   the highest-confidence alerts.
