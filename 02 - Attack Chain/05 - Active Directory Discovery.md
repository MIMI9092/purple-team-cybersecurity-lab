# 05 - Active Directory Discovery

## Objective

Understand the compromised Windows endpoint, its domain membership, available identity, and reachable Active Directory services.

## Identity and Host Discovery

From the Evil-WinRM session:

- Current identity: `LAB\svc_web`
- Endpoint: `WIN10-CLIENT01`
- Endpoint address: `10.10.30.20`
- Domain: `lab.local`
- Domain controller: `AD-DC01.lab.local`
- Domain controller address: `10.10.30.10`

## Important Tools

### `whoami`

Shows the current Windows security principal.

### `whoami /groups`

Shows group SIDs and token membership. It confirmed that `svc_web` was a normal user with remote-management access, not a domain administrator.

### `nltest /dsgetdc:lab.local`

Asked Windows to locate a domain controller. It returned the DC, address, site, and services such as LDAP, KDC, DNS, and global catalog.

### `klist`

Displayed Kerberos tickets in the current logon session. It proved that the session had Kerberos context and had contacted the domain controller.

## Access-Denied Results

Some commands such as broad domain user/group enumeration returned System Error 5, Access Denied.

This was valuable because it demonstrated:

```text
Authentication != Authorization
```

The account could log in and locate the domain but did not automatically receive administrative directory permissions.

## Network Validation

Through the Windows SOCKS pivot, Kali confirmed:

- TCP `88` open on AD-DC01
- TCP `389` open on AD-DC01
- TCP `445` open on AD-DC01

## MITRE

- `T1087.002`: Domain Account Discovery
- `T1018`: Remote System Discovery
- `T1482`: Domain Trust Discovery
- `T1049`: System Network Connections Discovery
