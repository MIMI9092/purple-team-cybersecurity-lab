# 06 - Kerberoasting

## Objective

Request a Kerberos service ticket for an SPN-bearing service account and recover ticket material for controlled offline password analysis.

## Lab Preparation

The controlled account `svc_sql` was created with MSSQL-style SPNs:

```text
MSSQLSvc/WIN10-CLIENT01:1433
MSSQLSvc/WIN10-CLIENT01.lab.local:1433
```

An SPN associates a service identity with a domain account. The lab SPNs represented a legacy SQL service account.

## Attack Mechanism

Through the Windows 10 SOCKS proxy, Impacket `GetUserSPNs` authenticated as `svc_web`.

The tool:

1. Queried Active Directory for accounts with SPNs.
2. Identified `svc_sql`.
3. Asked the KDC for a service ticket for the SQL SPN.
4. Saved the encrypted ticket material in a crackable format.

The resulting evidence was stored at:

```text
~/pfa-evidence/phase4-ad/svc_sql-kerberoast.hash
```

## Why Kerberoasting Works

Any authenticated domain user can normally request service tickets. A portion of the ticket is protected using key material derived from the service account password.

The attacker can test password candidates offline without sending each guess to the domain controller.

## Event 4769

AD-DC01 generated Security Event `4769`:

| Field | Meaning |
|---|---|
| Account | `svc_web@LAB.LOCAL` requested the ticket |
| Service | `svc_sql` |
| Client | `10.10.30.20` |
| Result | `0x0`, successful |
| Encryption | `0x17`, RC4-HMAC |

`0x17` corresponds to RC4 and the `$krb5tgs$23$` hash format.

## Defensive Meaning

A single Event 4769 is normal. Suspicion increases when:

- A user requests many service tickets quickly.
- RC4 is used where AES should be expected.
- A workstation requests unusual service tickets.
- The requester does not normally access the service.
- Ticket requests occur soon after web compromise or remote management.

## MITRE

- `T1558.003`: Kerberoasting
