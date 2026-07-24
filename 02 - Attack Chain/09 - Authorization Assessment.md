# 09 - Authorization Assessment

## Status

**Next phase. Not yet completed.**

## Objective

Determine what the recovered `svc_sql` identity is permitted to access after successful authentication.

## Questions to Answer

- Which AD groups contain `svc_sql`?
- Can it query normal LDAP information?
- Can it read `SYSVOL` and `NETLOGON`?
- Can it enumerate SMB shares?
- Can it access administrative shares such as `C$` or `ADMIN$`?
- Can it use WinRM or RDP?
- Does it have local privileges on any endpoint?
- Are denied operations logged?

## Expected Outcome

The preferred result is:

- Authentication succeeds.
- Normal domain resources may be readable.
- Administrative access is denied.

This would demonstrate that service-account password compromise is serious while also proving that least privilege limits impact.

## Evidence to Collect

- Successful Kerberos authentication
- Group-membership output
- Accessible share list
- Access-denied output
- Windows Events 4624, 4768, 4769, 5140, and 5145 where applicable
- Splunk correlation showing the same identity across phases

## Decision Point

Only after this assessment should the lab introduce a documented privilege misconfiguration for controlled lateral movement. Do not silently add the account to an administrative group.
