# Detection Gap Register

## DG-01: SQL Injection Not Reliably Alerted by IDS

**Observed:** DVWA logs clearly contained SQLmap and SQL injection, but the expected Suricata search returned no matching alert.

**Impact:** The application attack was visible only in web logs.

**Improvement:** Review ET WEB rules, interface coverage, HOME_NET, and create Splunk detection from web access logs.

**Status:** Partially mitigated. D02, D04, and D05 were created and
live-validated from DVWA access logs. Reliable Suricata SQLi alerting remains
an open network-signature gap.

## DG-02: Reverse-Shell Command Content Missing

**Observed:** Firewall logs showed the TCP connection, and DVWA logs showed the POST endpoint, but the command body was not recorded.

**Impact:** Network telemetry could not explain why the connection occurred.

**Improvement:** Add process telemetry, auditd, container runtime monitoring, or application-level request logging in the isolated lab.

**Status:** Partially mitigated. D06 detects the command-endpoint POST, D07
detects unexpected DMZ egress, and D08 correlates the same external peer across
both sources. The actual POST command remains unavailable in current telemetry.

## DG-03: Encrypted Chisel Tunnel Contents

**Observed:** Chisel communication was visible as TCP 443 but its proxied content was not visible.

**Impact:** IDS could identify flow behavior but not the tunneled commands.

**Improvement:** Detect long duration, unusual endpoints, periodicity, process
creation, and destination reputation. D09 now correlates firewall and Suricata
flow behavior, while D18 correlates endpoint execution with the long-lived
network flow.

**Status:** Substantially mitigated. The encrypted contents remain unavailable
by design, but D09 and D18 were live-validated against genuine Chisel sessions.

## DG-04: Missing Endpoint Process Telemetry

**Observed:** AD and Windows event logs were collected, but detailed process creation and command-line evidence was initially limited.

**Impact:** Discovery commands and Chisel execution were difficult to correlate.

**Improvement:** Process Creation auditing with command lines and PowerShell
Script Block Logging were enabled and validated. Sysmon remains optional for
registry, file, and richer network telemetry.

**Status:** Mitigated for process and PowerShell visibility. D17 and D18 were
live-validated; direct registry-change and file-creation telemetry remain
optional enrichments.

## DG-05: Splunk Forwarder Transport Outage

**Observed:** Splunk `ens33` was down. Forwarders queued events and the SIEM temporarily appeared empty.

**Impact:** Detection and investigation were delayed.

**Improvement:** Alert on receiver availability, forwarder silence, queue growth, and ingestion latency.

**Status:** Mitigated by the enabled `OPS01 - Telemetry Source Silence or
Ingestion Delay` alert. An obsolete earlier OPS01 clone is retained disabled
for reference and must not be enabled concurrently.

## DG-06: Timezone and Event-Time Confusion

**Observed:** Windows and Splunk timestamps required expanded time windows.

**Impact:** Correct events initially appeared absent.

**Improvement:** Standardize NTP and timezone handling and document event time versus index time.

## DG-07: DMZ-to-Internal Management Exposure

**Observed:** DVWA could reach WinRM on Windows 10 after a temporary rule was added.

**Impact:** Web compromise could become internal lateral movement.

**Improvement:** Remove the rule, enforce jump-host administration, and alert on any DMZ-to-management port connection.

**Status:** Detection mitigated by D11 and D12. Network hardening remains open.

## DG-08: Kerberos Authentication Failures Initially Not Audited

**Observed:** A controlled password spray produced a valid Alice TGT and failed
pre-authentication for `svc_web` and `svc_sql`. Splunk received the successful
Event 4768 records, but no Event 4771 failures. The domain controller audit
subcategory `Kerberos Authentication Service` was configured for success only.

**Impact:** Password spraying could be undercounted because failed Kerberos
authentication attempts are the core signal.

**Improvement implemented:** Success and failure auditing was enabled for the
`Kerberos Authentication Service` subcategory. The two failed lab attempts were
repeated once each. Splunk returned two Event `4771` records for `svc_web` and
`svc_sql` from IPv4-mapped address `::ffff:10.10.30.20`, failure code `0x18`
and pre-authentication type `2`. The normalized D03 search returned both.

**Status:** Telemetry gap mitigated and detection logic validated. Evidence
`P07_04`, `P07_05`, `D03_01` and `D03_02` proves audit-policy correction,
Splunk ingestion, manual detection results and a historically enabled D03
configuration. Re-audit D03's current enabled state and preserve one scheduled
trigger or scheduler-history result before declaring the operational alert
validation complete.

## DG-09: Approved DMZ Egress Baseline Missing

**Observed:** D07 successfully detected the reverse-shell callback by treating
connections from the DMZ to destinations outside trusted lab zones as
unexpected. The lab does not yet maintain an approved external-destination
allowlist.

**Impact:** Legitimate package repositories, update services, proxies, or other
approved external services could create false positives in a production
deployment.

**Improvement:** Create an asset-owned DMZ egress allowlist, include destination
owner and expiration fields, and alert when a DMZ asset connects to a new or
unapproved peer.

**Status:** Open improvement; current lab rule remains validated.

## DG-10: Web-to-Network Correlation Depends on Comparable Peer Addresses

**Observed:** D08 successfully correlated a command-endpoint POST with a DMZ
callback because the web source address matched the firewall destination
address. The rule required a maximum delay of five minutes.

**Impact:** Reverse proxies, carrier NAT, multi-stage redirects, delayed
callbacks, or missing firewall telemetry may prevent the two signals from
sharing a comparable peer address.

**Improvement:** Add proxy-aware client IP handling, asset enrichment, longer
risk-based correlation windows, and endpoint process telemetry.

**Status:** Open improvement; D08 is validated for the current architecture.

## DG-11: Expensive Correlation Search Windows

**Observed:** D13, D15, and D18 correlate several telemetry sources and use
longer histories than the five-minute scheduler interval. D15 intentionally
looks back 48 hours.

**Impact:** Repeated broad searches can increase scheduler lag and skipped
search risk on a single-node lab Splunk deployment.

**Improvement:** Scheduler telemetry was baselined for D13, D15, and D18. The
three searches were moved to independently staggered 15-minute schedules and
then observed through multiple post-change executions.

**Status:** Mitigated for the current lab load. Post-change validation recorded
zero skipped runs, zero failed runs, and maximum runtimes below 60 seconds for
all three searches. Continue monitoring scheduler telemetry and reconsider
summary indexing only if search volume or runtime increases.

## DG-12: Duplicate and Test Alert Objects

**Observed:** Splunk contains an obsolete OPS01 clone and a Shuffle test alert.

**Impact:** Accidental re-enablement could create duplicate operational alerts
or send non-production events to SOAR.

**Improvement:** Both objects are disabled. The old OPS01 is retained at
Mariam's request for rollback/reference; the enabled production clone has the
shorter title. Keep both disabled objects clearly documented.

**Status:** Controlled administrative debt; no active duplicate alerting.

## DG-13: Privilege-Escalation Correlation Not Yet Validated Centrally

**Observed:** The controlled service-file replay successfully proved
`LAB\svc_web` modifying the lab script followed by execution as
`NT AUTHORITY\SYSTEM`. Splunk and Shuffle were intentionally off during the
attack-only run, so the endpoint proof exists but its five expected Windows
event categories have not yet been correlated centrally.

**Impact:** The project can claim the privilege-escalation attack result, but
must not yet claim a validated Splunk detection for that transition.

**Improvement:** Preserve the current endpoint state, confirm Universal
Forwarder collection for Security, PowerShell Operational, System and
Application, verify Events `4663`, `4688`, `4104`, `7036` and `9101`, normalize
their fields and test the ordered writer-to-SYSTEM correlation.

**Status:** Open. Enterprise Developer licensing and the full dashboard are
working; only this telemetry/correlation validation remains.
