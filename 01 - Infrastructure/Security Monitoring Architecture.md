# Security Monitoring Architecture

## Splunk SIEM

Splunk Enterprise runs at `10.10.50.10`.

Important interfaces:

- Web interface: TCP `8000`
- Management API: TCP `8089`
- Universal Forwarder receiver: TCP `9997`
- OPNsense syslog input: UDP `5514`

## Collected Sources

| Source | Method | Index / Sourcetype |
|---|---|---|
| OPNsense firewall | Remote syslog | `opnsense`, `syslog` |
| OPNsense Suricata | Remote syslog | `opnsense`, `syslog` |
| DVWA Docker logs | Universal Forwarder file monitor | `linux`, `docker:json` |
| DVWA Linux logs | Universal Forwarder file monitor | `linux`, `linux_secure` / `syslog` |
| AD-DC01 Security log | Universal Forwarder | Windows Security event log |
| Windows 10 logs | Universal Forwarder | Windows event logs |

## Suricata

Suricata runs directly on OPNsense and monitors traffic crossing selected firewall interfaces.

Confirmed detection:

- Nmap user-agent activity generated ET SCAN SID `2024364`.

Important limitation:

Suricata only sees traffic that crosses an interface it monitors. Host-local activity, encrypted tunnel contents, and traffic that bypasses the firewall may not be visible.

## Shuffle SOAR

Shuffle runs at `10.10.50.30`.

Completed integration:

1. Splunk scheduled alert sends an HTTP webhook to Shuffle.
2. Shuffle receives the alert payload.
3. Shuffle uses the Splunk API on TCP `8089`.
4. Shuffle retrieves related Splunk events for enrichment.

See [[Splunk and Shuffle Integration]].

## Telemetry Reliability Lesson

When the Splunk VM interface `ens33` went down:

- Forwarders could not connect to TCP `9997`.
- Windows events still existed locally.
- Universal Forwarders queued data.
- Events appeared in Splunk after network recovery.

This was a collection-transport outage, not failure of Windows auditing.
