# Defensive Improvement Backlog

## High Priority

- Remove temporary DMZ-to-Windows WinRM access.
- Remove temporary broad TCP 443 tunnel rules.
- Replace predictable service-account passwords.
- Replace `svc_sql` with a gMSA where applicable.
- Remove unnecessary or artificial SPNs after testing.
- Ensure service accounts are not local administrators.
- Build Splunk detections for Events 4768 and 4769: **completed as D14 and D15**.
- Enable Kerberos Authentication Service failure auditing and validate Event
  4771: **completed; two controlled failures reached Splunk and D03 returned
  them. Current scheduled-alert/trigger state still requires a final audit.**
- Define a safe account-lockout policy before further password-spray testing.
- Detect one source requesting authentication for multiple accounts.
- Detect HKCU Run persistence followed by PowerShell and Chisel execution:
  **completed as D17 and D18**.
- Alert on Universal Forwarder silence and receiver outages:
  **completed as OPS01**.

## Network

- Apply least-privilege rules between every zone.
- Permit DMZ-to-SOC only for necessary log forwarding.
- Deny DMZ-to-AD by default.
- Log denied DMZ-to-internal connections.
- Document temporary test rules with expiry dates.
- Review Suricata interface selection and HOME_NET.

## Endpoint

- Process creation auditing with command lines: **completed and validated**.
- PowerShell Script Block Logging and forwarder input: **completed and validated**.
- Evaluate Sysmon for process, network, service, and scheduled-task telemetry.
- Add registry-change telemetry for HKCU Run keys.
- Restrict WinRM to management hosts.
- Remove unnecessary users from `Remote Management Users`.
- Monitor new binaries in user-writable directories.
- After central evidence validation, run the elevated reset for the lab-owned
  `PFA-Lab-Updater` fixture and confirm its vulnerable script baseline is
  restored.

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
- Create correlation searches across web, network, and identity telemetry:
  **completed for the attack chain as D08, D09, D12, D13, D15, and D18**.
- Correlate 4104, 4688, and OPNsense/Suricata TCP 443 events for Chisel-like
  activity: **completed as D17 and D18**.
- Correlate 4768/4771 by client address and distinct account count.
- Add health monitoring for ingestion latency and missing hosts:
  **completed as OPS01**.
- Baseline and optimize scheduler runtime for D13, D15, and D18:
  **completed with clean post-change validation**.
- Reconsider summary indexing or accelerated data models only if future
  correlation volume causes scheduler lag.
- Correlate the `LAB\svc_web` `4663` script write with service/SYSTEM
  `4688`, PowerShell `4104`, System `7036` and Application `9101`: **attack
  generation validated; Splunk field and correlation validation pending**.
- Preserve the full Enterprise Dashboard Studio definition and retain the
  license-restricted JSON only as historical fallback.

## SOAR

- Enrich alerts before acting.
- Require analyst approval before containment.
- Make containment temporary and reversible.
- Store an audit trail of each action.
- Test error paths and unavailable-service behavior.
