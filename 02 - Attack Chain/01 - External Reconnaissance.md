# 01 - External Reconnaissance

## Objective

Identify externally reachable services and fingerprint the application exposed through OPNsense.

## Source and Target

- Source: Kali `192.168.111.144`
- Target: OPNsense WAN `192.168.111.128`
- Published service: TCP `8080`
- Internal destination: DVWA `10.10.60.10:80`

## Actions

### Nmap Port Scan

Nmap identified TCP `8080` as the only relevant exposed web service in the tested range.

The scan established:

- The target was online.
- TCP `8080` was reachable.
- Other tested ports were filtered.

### Service Fingerprinting

Nmap service scripts and WhatWeb identified:

- Apache `2.4.25`
- Debian Linux
- PHP application behavior
- Redirect to `login.php`
- DVWA page title
- `PHPSESSID` and `security` cookies

### Content Enumeration

Gobuster discovered paths including:

- `/config/`
- `/docs/`
- `/external/`
- `/login.php`
- `/php.ini`
- `/phpinfo.php`
- `/robots.txt`
- `/setup.php`

HTTP `200` means the resource was returned. HTTP `301/302` means redirection. HTTP `403` confirms that a resource exists but access is denied.

## Why It Worked

OPNsense destination NAT intentionally exposed the DVWA web application on the WAN interface. Application and server headers disclosed useful implementation details.

## Defensive Evidence

- OPNsense firewall logs recorded Kali-to-WAN connections.
- Suricata detected Nmap behavior.
- Splunk received the Suricata alert and firewall traffic.
- DVWA Docker logs recorded HTTP requests and user agents.

## Key Detection

Suricata generated:

```text
ET SCAN Possible Nmap User-Agent Observed
SID 2024364
```

## Detection Gaps

- Basic HTTP requests to sensitive files did not always generate Suricata alerts.
- Web-server access logs were more useful than IDS signatures for some enumeration activity.
- Directory enumeration requires behavioral correlation, not only individual signatures.

## MITRE / CKC

- MITRE `T1046`: Network Service Scanning
- MITRE `T1595`: Active Scanning
- CKC: Reconnaissance
