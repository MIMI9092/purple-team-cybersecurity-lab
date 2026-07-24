# Project Progress

## Infrastructure Completed

- OPNsense firewall and Suricata
- Cisco routing and internal VLANs
- Dedicated DMZ
- Active Directory domain
- Domain-joined Windows 10 client
- DVWA Docker server
- Splunk SIEM
- Universal Forwarders
- OPNsense remote syslog
- Shuffle SOAR
- Splunk-to-Shuffle webhook and API enrichment

## Offensive Work Completed

- External service scanning
- Web-server fingerprinting
- Directory and file discovery
- SQL injection with SQLmap
- DVWA database enumeration
- Controlled password-hash recovery
- Command injection
- Reverse shell in the DVWA container
- Chisel pivot through the DMZ
- WinRM access to Windows 10
- Second Chisel pivot through Windows 10
- Active Directory discovery
- Kerberoasting
- Offline service-account password recovery
- Successful service-account TGT validation

## Defensive Evidence Confirmed

- Suricata Nmap alert
- OPNsense firewall traffic
- DVWA Docker access logs
- AD Event 4769
- AD Event 4768
- Splunk delayed-ingestion behavior
- Shuffle workflow execution

## Current Next Step

Perform [[09 - Authorization Assessment]] for `svc_sql` before introducing any further controlled misconfiguration.

## Questions for Supervisor

- Is the attack chain scope approved through persistence and C2 simulation?
- Should the project include a controlled password spray?
- Is adding Sysmon acceptable for endpoint visibility?
- Which containment actions may Shuffle automate?
- Should temporary firewall blocking require manual approval?
