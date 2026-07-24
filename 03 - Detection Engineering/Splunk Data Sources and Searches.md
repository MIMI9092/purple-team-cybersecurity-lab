# Splunk Data Sources and Searches

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
