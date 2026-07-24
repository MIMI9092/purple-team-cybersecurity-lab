# Assets and Addressing

| Asset | Role | Address | Zone |
|---|---|---:|---|
| Kali | External attacker | `192.168.111.144` | External |
| OPNsense WAN | Firewall external interface | `192.168.111.128` | External |
| OPNsense transit | Firewall-to-router link | `10.10.70.1/30` | Transit |
| Cisco R1 Fa0/0 | Router-to-firewall link | `10.10.70.2/30` | Transit |
| Cisco R1 VLAN 30 | Internal gateway | `10.10.30.1/24` | Internal |
| Cisco R1 VLAN 50 | SOC gateway | `10.10.50.1/24` | SOC |
| OPNsense DMZ | DMZ gateway | `10.10.60.1/24` | DMZ |
| AD-DC01 | Domain controller and DNS | `10.10.30.10` | Internal |
| WIN10-CLIENT01 | Domain-joined endpoint | `10.10.30.20` | Internal |
| Splunk | SIEM and log receiver | `10.10.50.10` | SOC |
| Shuffle | SOAR | `10.10.50.30` | SOC |
| DVWA host | Ubuntu/Docker web server | `10.10.60.10` | DMZ |

## Core Ports

| Port | Service | Use |
|---:|---|---|
| `80/TCP` | HTTP | DVWA inside the DMZ |
| `8080/TCP` | NAT exposure | External access to DVWA through OPNsense |
| `443/TCP` | HTTPS / controlled tunnel | OPNsense management or temporary Chisel listener |
| `5985/TCP` | WinRM | Controlled Windows remote management |
| `88/TCP` | Kerberos | Active Directory authentication |
| `389/TCP` | LDAP | Active Directory directory queries |
| `445/TCP` | SMB | Windows shares and domain services |
| `9997/TCP` | Splunk receiving | Universal Forwarder data |
| `5514/UDP` | Syslog | OPNsense and Suricata logs |
| `8000/TCP` | Splunk Web | Splunk user interface |
| `8089/TCP` | Splunk management API | Shuffle-to-Splunk API queries |
| `3001/TCP` | Shuffle frontend/webhook | Shuffle interface and webhook |

## Domain

| Property | Value |
|---|---|
| Domain | `lab.local` |
| NetBIOS name | `LAB` |
| Domain controller | `AD-DC01.lab.local` |
| Windows client | `WIN10-CLIENT01` |

## Accounts Used in the Scenario

| Account | Role |
|---|---|
| `www-data` | Compromised Apache process inside DVWA |
| `LAB\svc_web` | Controlled remote-management account used on Windows 10 |
| `LAB\svc_sql` | Controlled SPN-bearing service account used for Kerberoasting |
| `LAB\alice` | Normal domain user used for client testing |

Passwords are intentionally not documented in this vault.
