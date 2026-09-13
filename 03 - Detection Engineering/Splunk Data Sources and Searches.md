# Splunk Data Sources and Searches

Validated Phase 2 production SPL, alert settings, evidence, and detection gaps
are documented in [[Phase 2 Web Exploitation Detections]].

## Platform and Dashboard Status

The Enterprise Developer license is active with a 10 GB/day quota through
6 March 2027. The full 12-panel executive Dashboard Studio view is restored and
its indexed-event and `tstats` searches were validated against historical data.
See [[Splunk License and Executive Dashboard]].

## OPNsense and Suricata

```spl
index=opnsense
```

Search for Kali activity:

```spl
index=opnsense "192.168.111.144"
```

Search for Suricata events:

```spl
index=opnsense ("suricata[" OR "\"event_type\":\"alert\"")
```

## DVWA Docker Logs

```spl
index=linux host="dmz-dvwa" sourcetype="docker:json"
```

SQLmap activity:

```spl
index=linux host="dmz-dvwa" sourcetype="docker:json"
("sqlmap" OR "UNION" OR "vulnerabilities/sqli")
```

Command-injection endpoint:

```spl
index=linux host="dmz-dvwa" sourcetype="docker:json"
"/vulnerabilities/exec/"
```

Unexpected DMZ egress and reverse-shell correlation use OPNsense `filterlog`
events from `index=opnsense source=udp:5514` and dynamically classify trusted
lab zones. The production rules do not hardcode the attacker IP or callback
port.

## Kerberoasting

```spl
index=* host="AD-DC01" EventCode=4769
"svc_sql"
```

Fields of interest:

- Requesting account
- Service name
- Client address
- Ticket encryption type
- Result code

## Valid Account Authentication

```spl
index=* host="AD-DC01"
(EventCode=4768 OR "Kerberos authentication ticket")
"svc_sql"
```

The Windows forwarders currently store these events in `index=main`. Use
`index=*` during troubleshooting, then narrow a validated detection to
`index=main`.

## Authorization Assessment

```spl
index=main earliest=-30m
(host="AD-DC01" OR host="WIN10-CLIENT01")
"svc_sql"
(EventCode=4624 OR EventCode=4625 OR source="WinEventLog:Microsoft-Windows-WinRM/Operational")
```

## Persistence and Chisel

```spl
index=main host="WIN10-CLIENT01" earliest=-30m
(EventCode=4688 OR EventCode=4104)
("PFA_PERSISTENCE_C2_01" OR "pfa-tunnel.ps1" OR "chisel.exe")
| table _time EventCode source Process_Command_Line ScriptBlockText
```

The corresponding network connection is visible in OPNsense:

```spl
index=opnsense earliest=-30m
"10.10.30.20" "192.168.111.144" "443"
```

## Controlled Password Spray

```spl
index=main host="AD-DC01" earliest=-30m
(EventCode=4771 OR EventCode=4768)
("alice" OR "svc_web" OR "svc_sql")
| table _time EventCode Account_Name Client_Address Failure_Code Ticket_Encryption_Type
```

- `4768` shows TGT requests, including successful authentication.
- `4771` shows Kerberos pre-authentication failures.
- The initial test produced successful `4768` events for Alice.
- Failed `svc_web` and `svc_sql` attempts did not produce `4771` because the
  Kerberos Authentication Service subcategory audited success only.
- The audit subcategory was subsequently changed to `Success and Failure`.
- The controlled rerun produced two Splunk Event `4771` records for `svc_web`
  and `svc_sql`, from `::ffff:10.10.30.20`, with failure code `0x18` and
  pre-authentication type `2`.
- D03's normalized manual search returned both records. Historical evidence
  shows the scheduled alert enabled, but its current state and a triggered-alert
  or scheduler-history result still require a final audit.

## Writable Service Script Privilege Escalation

The endpoint attack replay is live-validated and deliberately keeps the file
writer and privileged executor separate. The central correlation remains
pending. Validate field names against the forwarded Windows XML before
converting this into a scheduled detection.

```spl
index=main host="WIN10-CLIENT01" earliest=-30m
(
  (EventCode=4663 ObjectName="*\\PFA-Lab-Updater.ps1" SubjectUserName="svc_web")
  OR
  (EventCode=4688 NewProcessName="*\\powershell.exe" ProcessCommandLine="*PFA-Lab-Updater.ps1*" SubjectUserSid="S-1-5-18")
  OR
  (EventCode=4104 ScriptBlockText="*PFA_SERVICE_PRIVESC_01*")
  OR
  (source="WinEventLog:Application" EventCode=9101 SourceName="PFA-Lab-PrivilegeEscalation")
)
| eval Stage=case(
    EventCode=4663,"svc_web modified service script",
    EventCode=4688,"SYSTEM PowerShell started",
    EventCode=4104,"proof payload executed",
    EventCode=9101,"SYSTEM proof recorded")
| table _time Stage SubjectUserName SubjectUserSid ObjectName ParentProcessName NewProcessName ProcessCommandLine Message
| sort 0 _time
```

The final analytic should require the ordered transition within a short window:

```text
LAB\svc_web file write -> PFA-Lab-Updater start -> SYSTEM PowerShell -> proof event 9101
```

The attack generation is **live-validated** in run
`PTR-20260909T162419Z-355a0dc0`. Splunk coverage remains **partial** until the
preserved events are ingested, the actual field extraction is confirmed and
the ordered correlation is tested. Do not use the successful SYSTEM proof to
claim that the SIEM detection itself has already been validated.

## Time and Ingestion Issues

During timezone or delayed-ingestion troubleshooting:

```spl
index=* host="AD-DC01" _index_earliest=-15m latest=+12h
```

`_index_earliest` filters by ingestion time rather than only the original event timestamp.

## Forwarder Health

Use Splunk internal logs to investigate:

- Blocked TCP input
- Forwarder ingestion latency
- Output queues
- Receiver connection failures
- File-monitor lag

The SIEM VM network interface and TCP `9997` receiver must be checked before assuming an endpoint stopped logging.
