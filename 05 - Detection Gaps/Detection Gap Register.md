# Detection Gap Register

## DG-01: SQL Injection Not Reliably Alerted by IDS

**Observed:** DVWA logs clearly contained SQLmap and SQL injection, but the expected Suricata search returned no matching alert.

**Impact:** The application attack was visible only in web logs.

**Improvement:** Review ET WEB rules, interface coverage, HOME_NET, and create Splunk detection from web access logs.

## DG-02: Reverse-Shell Command Content Missing

**Observed:** Firewall logs showed the TCP connection, and DVWA logs showed the POST endpoint, but the command body was not recorded.

**Impact:** Network telemetry could not explain why the connection occurred.

**Improvement:** Add process telemetry, auditd, container runtime monitoring, or application-level request logging in the isolated lab.

## DG-03: Encrypted Chisel Tunnel Contents

**Observed:** Chisel communication was visible as TCP 443 but its proxied content was not visible.

**Impact:** IDS could identify flow behavior but not the tunneled commands.

**Improvement:** Detect long duration, unusual endpoints, periodicity, process creation, and destination reputation.

## DG-04: Missing Endpoint Process Telemetry

**Observed:** AD and Windows event logs were collected, but detailed process creation and command-line evidence was limited.

**Impact:** Discovery commands and Chisel execution were difficult to correlate.

**Improvement:** Enable process creation auditing and evaluate Sysmon with a controlled configuration.

## DG-05: Splunk Forwarder Transport Outage

**Observed:** Splunk `ens33` was down. Forwarders queued events and the SIEM temporarily appeared empty.

**Impact:** Detection and investigation were delayed.

**Improvement:** Alert on receiver availability, forwarder silence, queue growth, and ingestion latency.

## DG-06: Timezone and Event-Time Confusion

**Observed:** Windows and Splunk timestamps required expanded time windows.

**Impact:** Correct events initially appeared absent.

**Improvement:** Standardize NTP and timezone handling and document event time versus index time.

## DG-07: DMZ-to-Internal Management Exposure

**Observed:** DVWA could reach WinRM on Windows 10 after a temporary rule was added.

**Impact:** Web compromise could become internal lateral movement.

**Improvement:** Remove the rule, enforce jump-host administration, and alert on any DMZ-to-management port connection.
