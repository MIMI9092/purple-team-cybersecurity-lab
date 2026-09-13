# Splunk License and Executive Dashboard

## Status

**Enterprise Developer licensing and the full executive dashboard were
validated on 10 September 2026.**

## License State

| Field | Validated value |
|---|---|
| License type | Enterprise |
| Active license group | Enterprise |
| Label | Splunk Developer Personal License |
| Daily indexing quota | 10 GB |
| Created | 6 September 2026 |
| Expires | 6 March 2027 |

The previous Enterprise Trial group had expired. The new license was uploaded
through `Settings -> Licensing -> Add license`, after which the active group
was changed from Enterprise Trial to Enterprise and Splunk was restarted.

An attempted second upload returned `stack already has license`, which
correctly indicated that the license file was already present. The license file
itself is stored outside the Obsidian vault and must not be committed or shared.

## Dashboard Artifacts

The vault retains two Dashboard Studio source definitions:

| File | Purpose |
|---|---|
| `Purple Team Executive Overview.full-license.dashboard.json` | Current full Enterprise dashboard using indexed-event and `tstats` searches |
| `Purple Team Executive Overview.dashboard.json` | Temporary fallback for the earlier license-restricted state |

The full dashboard contains 12 visualizations, 12 data sources and one global
time-range input. It covers indexed volume, active sourcetypes, enabled project
detections, detection hits, event volume by index, index distribution, top
detections, Windows/Kerberos activity, top hosts, SOAR validation status,
telemetry freshness and recent detection executions.

## Live Dashboard Validation

With the global time range set to `All time`, the restored dashboard displayed:

| Panel | Observed value |
|---|---:|
| Security Events | 799,276 |
| Active Data Sources | 10 |
| Enabled Detections | 25 |
| Detection Hits | 2,692 |

The indexed-volume charts, Events by Index, Top Detection Activity and
Windows/Kerberos Activity also returned historical data. This confirms that
the earlier `tstats` licensing errors are resolved.

When the dashboard was set to `Last 24 hours`, the indexed-event and active-
source panels correctly returned zero because the monitoring and source VMs
had been off during the attack-only work. Configuration-derived and internal
scheduler panels could still show values. Switching to `All time` demonstrated
that this was a time-range/data-freshness condition rather than a dashboard or
license failure.

Useful independent checks are:

```spl
| tstats count WHERE index=* BY index
| sort - count
```

```spl
| tstats count WHERE index=* BY sourcetype
| stats dc(sourcetype) AS active_sources
```

## Remaining Validation

The dashboard restoration is complete. The next SIEM task is separate: start
the required Windows telemetry path and validate the preserved local privilege-
escalation evidence in Security `4663`/`4688`, PowerShell `4104`, System `7036`
and Application `9101`. Until that correlation is proven in Splunk, the attack
replay is complete but its central detection coverage remains partial.

Do not run the elevated privilege-escalation reset script until this collection
check is complete.
