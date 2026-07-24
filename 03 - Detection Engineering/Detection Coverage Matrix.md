# Detection Coverage Matrix

| Activity | Primary telemetry | Confirmed? | Gap / Next action |
|---|---|---:|---|
| Nmap scan | Suricata, OPNsense, Splunk | Yes | Build correlation by source and destination |
| WhatWeb fingerprinting | DVWA access logs | Yes | Create user-agent detection |
| Gobuster enumeration | DVWA access logs | Yes | Detect URI volume and 403/404 bursts |
| SQLmap SQL injection | DVWA Docker logs | Yes | Create SQLmap and SQL-pattern alerts |
| SQL injection IDS signature | Suricata | Partial | Review enabled ET WEB rules |
| Command injection | DVWA access logs | Partial | POST body absent from access log |
| Reverse shell | OPNsense connection logs | Partial | Add endpoint process telemetry |
| Chisel tunnel | Firewall flow logs | Partial | Detect long-lived periodic TCP 443 |
| WinRM lateral access | Windows events | Partial | Confirm 4624 and PowerShell collection |
| AD discovery | Windows logs | Partial | Enable and validate process creation |
| Kerberoasting | AD Event 4769 | Yes | Build RC4 service-ticket correlation |
| Offline cracking | Kali only | No central log | Preserve operator evidence |
| Valid account TGT | AD Event 4768 | Yes | Correlate with prior 4769 |
| Splunk ingestion outage | Forwarder/internal logs | Yes | Add forwarder health alert |

## Priority Detections

1. Kerberoasting: Event 4769 with RC4 and unusual service access.
2. Chained identity use: `svc_web` ticket request followed by `svc_sql` authentication.
3. DMZ-to-internal WinRM.
4. Long-lived Chisel-like TCP 443 sessions.
5. SQLmap user-agent and injection patterns.
6. Splunk forwarder connection and ingestion-health failures.
