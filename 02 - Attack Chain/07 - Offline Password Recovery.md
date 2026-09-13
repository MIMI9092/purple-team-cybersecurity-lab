# 07 - Offline Password Recovery

## Objective

Demonstrate how a weak service-account password can be recovered from Kerberos ticket material without generating repeated domain authentication failures.

## Hash Format

The Kerberoast evidence used:

```text
<KERBEROS_TICKET_MATERIAL_REDACTED>
```

This indicated:

- Kerberos TGS material
- Encryption type 23
- RC4-HMAC
- Hashcat mode `13100`
- John format `krb5tgs`

## Hashcat Attempt

Hashcat could not run because the Kali VM had no compatible OpenCL, CUDA, HIP, or CPU OpenCL runtime.

This was a tooling limitation, not an invalid hash.

## John Attempt

John successfully loaded the Kerberos hash. The `rockyou.txt` wordlist completed without recovering the password.

This proved that:

- The hash was valid.
- The service-account password was not in that generic wordlist.
- A larger wordlist does not guarantee success.

## Controlled Candidate Validation

A small candidate file containing the known controlled lab candidate was tested. John recovered the service-account password and reported:

```text
1 password hash cracked, 0 left
```

The password is intentionally not recorded in this vault.

## Why This Was Offline

John compared locally generated candidate keys against the saved ticket data. It did not submit each password candidate to Active Directory.

Therefore:

- No lockout was triggered.
- No series of failed-logon events was generated.
- The activity occurred on Kali rather than the domain controller.

## Defensive Lesson

Controls include:

- Long, random service-account passwords
- Group Managed Service Accounts
- AES-only Kerberos where possible
- Removal of unnecessary SPNs
- Monitoring Event 4769 patterns
- Restricting service-account privileges

## MITRE

- `T1110.002`: Password Cracking
- Supports `T1558.003`: Kerberoasting
