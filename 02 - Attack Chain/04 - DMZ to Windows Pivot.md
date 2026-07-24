# 04 - DMZ to Windows Pivot

## Objective

Use the compromised DMZ application as a network pivot and access an internal Windows endpoint through an intentionally permitted management path.

## First Chisel Tunnel

Kali ran a Chisel server in reverse mode on TCP `443`. The DVWA container downloaded a statically linked Chisel binary and connected back to Kali.

The static build was required because the original Kali binary required newer GLIBC versions than the old Debian-based DVWA container provided.

The reverse tunnel created:

```text
Kali SOCKS listener: 127.0.0.1:1080
```

## Proxychains

Proxychains redirected supported Kali TCP tools into the SOCKS proxy.

```text
Kali tool -> 127.0.0.1:1080 -> Chisel -> DVWA -> internal target
```

This allowed Kali to test internal services without having a direct route to the internal VLAN.

## WinRM Access

The lab temporarily allowed:

```text
10.10.60.10 -> 10.10.30.20:5985/TCP
```

Windows 10 had:

- WinRM enabled
- TCP `5985` listening
- A firewall rule scoped to the DVWA source address
- `LAB\svc_web` in `Remote Management Users`

Evil-WinRM authenticated through the SOCKS tunnel and opened a PowerShell session as:

```text
LAB\svc_web
```

## Second Chisel Tunnel

A Windows Chisel client was uploaded to Windows 10 and connected back to Kali. It created:

```text
Kali SOCKS listener: 127.0.0.1:1081
```

The second tunnel used Windows 10 as the pivot point:

```text
Kali -> Windows 10 -> AD-DC01
```

It successfully reached AD ports:

- Kerberos `88/TCP`
- LDAP `389/TCP`
- SMB `445/TCP`

## Why Two SOCKS Proxies Existed

- Port `1080` represented the network view from DVWA.
- Port `1081` represented the deeper network view from Windows 10.

## Intentional Weaknesses

- DMZ-to-Windows WinRM was allowed.
- A domain service credential was readable by the compromised web process.
- Windows permitted remote management by that account.
- Outbound Chisel traffic on TCP 443 was allowed.

## MITRE / CKC

- MITRE `T1572`: Protocol Tunneling
- MITRE `T1021.006`: Windows Remote Management
- MITRE `T1078`: Valid Accounts
- CKC: Command and Control / Actions on Objectives
