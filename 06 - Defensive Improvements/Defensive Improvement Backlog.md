# Defensive Improvement Backlog

## High Priority

- Remove temporary DMZ-to-Windows WinRM access.
- Remove temporary broad TCP 443 tunnel rules.
- Replace predictable service-account passwords.
- Replace `svc_sql` with a gMSA where applicable.
- Remove unnecessary or artificial SPNs after testing.
- Ensure service accounts are not local administrators.
- Build Splunk detections for Events 4768 and 4769.
- Alert on Universal Forwarder silence and receiver outages.

## Network

- Apply least-privilege rules between every zone.
- Permit DMZ-to-SOC only for necessary log forwarding.
- Deny DMZ-to-AD by default.
- Log denied DMZ-to-internal connections.
- Document temporary test rules with expiry dates.
- Review Suricata interface selection and HOME_NET.

## Endpoint

- Enable process creation auditing with command lines.
- Evaluate Sysmon for process, network, service, and scheduled-task telemetry.
- Restrict WinRM to management hosts.
- Remove unnecessary users from `Remote Management Users`.
- Monitor new binaries in user-writable directories.

## Active Directory

- Prefer AES Kerberos.
- Disable RC4 where compatibility permits.
- Use long random service-account passwords.
- Use gMSAs.
- Monitor SPN changes.
- Audit privileged and service-account group membership.
- Review delegation settings.

## SIEM

- Normalize OPNsense, Suricata, Linux, Docker, and Windows fields.
- Build dashboards for zone-to-zone traffic and authentication.
- Create correlation searches across web, network, and identity telemetry.
- Add health monitoring for ingestion latency and missing hosts.

## SOAR

- Enrich alerts before acting.
- Require analyst approval before containment.
- Make containment temporary and reversible.
- Store an audit trail of each action.
- Test error paths and unavailable-service behavior.
