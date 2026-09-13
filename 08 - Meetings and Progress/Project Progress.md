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
- Least-privilege authorization assessment
- SMB share discovery with `NETLOGON` allowed and `C$` denied
- WinRM authorization-boundary validation
- Process Creation and PowerShell telemetry enablement
- HKCU Run-key persistence simulation
- Chisel C2 tunnel recreation through Windows 10
- Initial controlled password spray

## Defensive Evidence Confirmed

- Suricata Nmap alert
- OPNsense firewall traffic
- DVWA Docker access logs
- AD Event 4769
- AD Event 4768
- WinRM Operational Event 192
- Process Creation Event 4688 with command lines
- PowerShell Script Block Event 4104
- OPNsense Chisel TCP 443 flow
- Successful password-spray Event 4768 for Alice
- Splunk delayed-ingestion behavior
- Shuffle workflow execution

## Defensive Detection Engineering Completed

- Phase 1 reconnaissance detections validated: D01, P1-R02, P1-R03, P1-R04,
  and P1-C01.
- Phase 2 Web Exploitation detections validated: D02, D04, D05, D06, D07,
  and D08.
- D08 correlated an authenticated command-endpoint POST with a real DMZ TCP
  callback to the same external peer four seconds later.
- The final Phase 2 validation repeated the original curl-based command
  injection and reverse-shell workflow and produced HTTP 200 web evidence.
- Phase 3 DMZ Pivot and Internal Access detections D09, D10, D11, D12, D13,
  D14, D15, D17, and D18 were created and live-validated.
- D09 and D18 use the Suricata EVE flow telemetry improvement to detect genuine
  long-lived Chisel WebSocket behavior from both the network and endpoint.
- D13 correlates the full transition from public DVWA command execution to
  callback, DMZ-to-internal management traffic, and successful Windows access.
- D14 and D15 cover Kerberoasting and subsequent valid-account use without
  storing Kerberos ticket material or recovered secrets.
- OPS01 monitors Universal Forwarder identity/receiver health, OPNsense source
  freshness, and ingestion delay; it was live-validated by controlled source
  silence.
- A full saved-alert audit was completed. All 21 enabled production alerts are
  Application-shared. The remaining five-minute searches are staggered across
  minute offsets 0-4, while D13, D15, and D18 use independently staggered
  15-minute schedules.
- D15 scheduler optimization passed at a 15-minute cadence with 0 skipped and
  0 failed post-change runs.
- D13 scheduler optimization passed at minutes 5, 20, 35, and 50 with 2
  successful runs, 0 skipped, 0 failed, 5.273-second average runtime, and
  6.850-second maximum runtime.
- D18 scheduler optimization passed at minutes 10, 25, 40, and 55 with 2
  successful runs, 0 skipped, 0 failed, 0.685-second average runtime, and
  1.013-second maximum runtime.
- Event 4771 failure telemetry was proven after enabling Success and Failure
  auditing. D03 returned the two controlled service-account failures. A
  historical screenshot shows D03 enabled; its current scheduler/trigger state
  still needs a final audit.
- The obsolete OPS01 clone and Shuffle test alert are retained disabled.

## SOAR Engineering Progress

- PB01 is retained as historical experimentation after supervisor feedback;
  it is no longer the project's main response architecture.
- PB02 reconnaissance response is functionally complete for the current lab.
  Scoped source containment was validated, while automatic rollback policy is
  intentionally deferred.
- PB03 public-facing web-exploitation response validated CP2 and CP3. The final
  CP3 run verified source blocking, callback blocking, scoped DMZ egress
  restriction, final audit, and notification. Automatic rollback remains
  deferred.
- Reusable helpers now include NTF01 for analyst/final notification, FW01 for
  safe OPNsense alias containment and PF-state handling, and FW02 for
  post-containment firewall evidence verification.
- `PB04 - Active Directory Credential Access and Account Abuse` is complete
  for the current D14/D15 identity scope.
- PB04 normalizes D14 and D15, enriches authorization, asset, Kerberos, logon,
  process, PowerShell, and WinRM evidence, assesses I1-I4, calculates risk,
  selects IRP0-IRP4, persists versioned cases, and validates analyst decisions.
- The IRP2 monitoring route completed without AD interaction and closed with a
  final audit.
- The IRP3 route live-validated an analyst-approved temporary disable of
  `svc_sql`, independent AD-state retrieval, a valid Splunk post-response
  window with no new authentication evidence, `VERIFIED/SUCCESS` assessment,
  audit-before-cleanup ordering, and manual account recovery.
- PB04 failed closed when AD was unreachable and when Splunk management TCP
  8089 was unavailable; neither failure reached the disable action.
- Automated service-account credential rotation and existing-session/ticket
  termination remain intentionally deferred. No credentials are stored in the
  vault.
- `PB05 - Endpoint Persistence and C2 Investigation and Containment` is
  complete for D17 and D18.
- PB05 correlates persistence, process, and network evidence; assesses P1-P4;
  selects CRP0-CRP4; and persists versioned endpoint/user campaign cases.
- CRP1 fail-closed escalation, CRP2 endpoint containment, CRP3 layered C2
  containment, and CRP4 repeated-C2 containment were live-validated.
- The custom restricted endpoint app verified the exact Chisel process before
  stopping it and verified the exact `PFA-Lab-Tunnel` Run value before removal.
  The binary and persistence script were preserved as evidence.
- CRP3/CRP4 verified scoped OPNsense alias blocking and targeted PF-state
  termination. Automated host isolation and binary deletion remain deferred.
- The native Shuffle User Input route now emails a frontend approval link,
  records authenticated click metadata, builds the exact approved decision,
  and launches the layered-response workflow without analyst `curl` input.
- The accepted final result was `LAYERED_CONTAINMENT_VERIFIED` with overall
  containment and endpoint verification both `VERIFIED`.

## Local Privilege-Escalation Milestone — 9 September 2026

- Installed and validated the isolated `PFA-Lab-Updater` LocalSystem fixture on
  `WIN10-CLIENT01`.
- Live run `PTR-20260909T162419Z-355a0dc0` proved the transition from
  `LAB\svc_web` to `NT AUTHORITY\SYSTEM` with separate writer and executor
  evidence.
- Captured the file ACL, before/after SHA-256 values, write/start/proof
  timestamps, SYSTEM PID and parent PID, service state and Application-event
  write status.
- The run stopped successfully at `SVC_WEB_TO_SYSTEM_PROVED`; Splunk, Shuffle
  and response actions remained off by design.
- The modified script and SYSTEM proof remain on the endpoint for later Splunk
  collection. Elevated reset is deferred until central validation is complete.

## Splunk License and Dashboard Milestone — 10 September 2026

- Installed the Splunk Developer Personal License and changed the active group
  from the expired Enterprise Trial group to Enterprise.
- Validated a 10 GB/day quota with expiration on 6 March 2027.
- Restored the full 12-panel `Purple Team Executive Overview` Dashboard Studio
  source.
- With `All time` selected, observed 799,276 indexed events, 10 active data
  sources, 25 enabled project detections and 2,692 historical detection hits.
- Confirmed that the earlier zero-valued panels under `Last 24 hours` reflected
  inactive sources/time range rather than a license or dashboard fault.
- Decided to prepare the report/presentation baseline before optional Shuffle
  ticketing and workflow refinements. Later additions can be incorporated as
  report revisions.

## Current Next Step

Prepare the first complete report/presentation baseline from the current
validated project. Preserve the local privilege-escalation proof, then validate
its Windows telemetry in Splunk before running the elevated endpoint reset.
Capture and index the final PB04/PB05 screenshots, export the accepted Shuffle
workflows and custom PB05 app, and treat ticketing or further Shuffle changes as
optional later revisions.
Confirm `svc_sql` remains enabled after controlled PB04 testing and reset PB05
lab artefacts only when the evidence set is complete. Rotate the Brevo API
credential exposed during troubleshooting. PB01 redesign is not the current
priority. AS-REP Roasting remains deferred until its detection is validated.
DG-08's source-telemetry gap is mitigated; re-audit D03's current enabled state
and preserve a scheduled-trigger or scheduler-history result before the report
freeze.

## Questions for Supervisor

- Is the completed attack chain scope sufficient before defensive engineering?
- What account-lockout policy should be demonstrated in the lab?
- Is adding Sysmon acceptable for endpoint visibility?
- Which containment actions may Shuffle automate?
- Should temporary firewall blocking require manual approval?
