# Evidence Index

## Evidence Locations

### Kali

```text
~/pfa-evidence/phase1-recon/
~/pfa-evidence/phase2-web/
~/pfa-evidence/phase3-pivot/
~/pfa-evidence/phase4-ad/
~/pfa-evidence/phase5-valid-account/
~/pfa-evidence/phase6-persistence/
~/pfa-evidence/phase7-password-spray/
```

### Important Files

| Evidence | Location |
|---|---|
| Nmap results | `phase1-recon` |
| Web fingerprinting | `phase1-recon` |
| SQLmap output | `phase2-web/sqlmap-output` |
| Reverse-shell notes | `phase2-web` |
| Chisel server logs | `phase3-pivot` |
| Proxychains DMZ configuration | `phase3-pivot/proxychains-dmz.conf` |
| Proxychains Windows configuration | `phase3-pivot/proxychains-win10.conf` |
| SPN enumeration | `phase4-ad/spn-enumeration.txt` |
| Kerberoast hash | `phase4-ad/svc_sql-kerberoast.hash` |
| Authorization test output | `phase5-valid-account` |
| Persistence and C2 evidence | `phase6-persistence` |
| Password-spray operator evidence | `phase7-password-spray` |

## Recommended Screenshot Names

```text
01-nmap-external-scan.png
02-whatweb-dvwa-fingerprint.png
03-gobuster-content-discovery.png
04-suricata-nmap-alert.png
05-sqlmap-injection-confirmed.png
06-sqlmap-users-table.png
07-dvwa-reverse-shell.png
08-chisel-dvwa-socks-1080.png
09-evil-winrm-svc-web.png
10-chisel-win10-socks-1081.png
11-ad-discovery-nltest.png
12-event-4769-kerberoasting.png
13-john-password-recovery-redacted.png
14-event-4768-valid-account.png
15-splunk-shuffle-workflow.png
P05_01_svc_sql_smb_share_enumeration.png
P05_02_svc_sql_netlogon_access.png
P05_03_svc_sql_c_share_denied.png
P05_04_svc_sql_winrm_authorization_failure.png
P05_05_svc_sql_splunk_logons.png
P05_06_winrm_group_membership.png
P05_07_winrm_event_192_authorization_failure.png
P06_01_process_creation_auditing_enabled.png
P06_02_powershell_telemetry_in_splunk.png
P06_03_run_key_and_persistence_script.png
P06_04_chisel_listener_1082.png
P06_05_persistence_execution_log_and_process.png
P06_06_persistence_events_splunk.png
P07_01_password_spray_preflight.png
P07_02_controlled_password_spray_kali.png
P07_03_authentication_failure_audit_gap.png
P07_04_kerberos_failure_auditing_enabled.png
P07_05_password_spray_events_splunk.png
P07_06_password_spray_postcheck.png
```

## Phase 2 Defensive Validation Evidence

```text
P2_D02_sql_injection_validation_results.png
P2_D04_high_volume_sqli_historical_validation.png
P2_D04_high_volume_sqli_alert_overview.png
P2_D04_high_volume_sqli_live_validation.png
P2_D05_database_enumeration_historical_validation.png
P2_D05_database_enumeration_alert_overview.png
P2_D05_database_enumeration_live_validation.png
P2_D06_command_endpoint_post_historical_validation.png
P2_D06_command_endpoint_alert_overview.png
P2_D06_real_command_injection_curl_proof.png
P2_D06_authenticated_command_injection_live_validation.png
P2_D07_unexpected_dmz_egress_historical_validation.png
P2_D07_unexpected_dmz_egress_alert_overview.png
P2_D07_real_dmz_callback_live_validation.png
P2_D08_correlated_web_compromise_historical_validation.png
P2_D08_correlated_web_compromise_alert_overview.png
P2_D08_real_reverse_shell_curl_validation.png
P2_D08_real_web_compromise_correlation_live_validation.png
P2_phase2_sqli_alerts_live_validation_summary.png
P2_phase2_command_compromise_alerts_live_summary.png
```

The final Phase 2 replay repeated the original authenticated curl command
injection and TCP 443 reverse-shell workflow. Authentication cookies,
passwords, CSRF tokens, and hashes are excluded from every screenshot and note.

## Phase 3 Defensive Validation Evidence

```text
P3-T01-Suricata-EVE-Flow-Telemetry-Validated.png
P3-T02-Splunk-Suricata-Flow-Ingestion-Validated.png
P3-D09-Chisel-Suricata-Flow-Observed.png
P3-D09-Firewall-PreNAT-Tunnel-Start-Observed.png
P3-D09-Correlated-Long-Lived-DMZ-Tunnel-Search.png
P3-D09-Alert-Configuration.png
P3-D09-Triggered-Alert-Summary.png
P3-D09-Triggered-Alert-Validated.png
P3-D10-Triggered-Alert-Validated.png
P3-D11-Triggered-Alert-Validated.png
P3-D12-Triggered-Alert-Validated.png
P3-D13-Triggered-Alert-Validated.png
P3-D14-Triggered-Alert-Validated.png
P3-D15-Triggered-Alert-Validated.png
P3-D17-Triggered-Alert-Validated.png
P3-D18-Triggered-Alert-Validated.png
OPS01-Telemetry-Silence-Triggered-Alert-Validated.png
```

## Alert Audit Evidence

The saved-alert audit uses exact filenames
`DE-P2-ALERT-AUDIT-01-saved-alert-inventory.png` through
`DE-P2-ALERT-AUDIT-24-final-staggered-inventory.png`. The final image should
show the 21 enabled production alerts, Application sharing, staggered next-run
times, disabled D03, disabled obsolete OPS01, and disabled Shuffle test alert.

That alert-audit image is a point-in-time operational inventory, not evidence
that D03 telemetry was never validated. The separate password-spray evidence
below proves the source and search path; the final report still needs a current
D03 enabled-state/trigger audit.

## Password-Spray Remediation Evidence

The named report-image source folder is:

```text
C:\Users\DELL\Images\projects
```

It currently contains 94 named PNG files. They are candidate evidence, not an
instruction to include every image. The following four files close the original
Event `4771` visibility gap:

| Evidence | Claim proved |
|---|---|
| `P07_04_kerberos_failure_auditing_enabled.png` | `Kerberos Authentication Service` auditing is `Success and Failure` |
| `P07_05_kerberos_password_spray_events.png` | Splunk received two Event `4771` failures for `svc_web` and `svc_sql`, from `::ffff:10.10.30.20`, code `0x18`, type `2` |
| `D03_01_kerberos_failure_detection_search.png` | The normalized D03 search returned both failures with client IP `10.10.30.20` |
| `D03_02_kerberos_failure_alert_configuration.png` | D03 was historically enabled and scheduled with a results-greater-than-zero trigger |

No separately named image currently proves an actual D03 triggered-alert entry
or its present enabled state. Capture one current configuration/scheduler view
and one trigger result if available; do not rerun the spray merely to obtain a
more attractive screenshot unless the safe preflight is repeated.

## SIEM Scheduler Optimization Evidence

```text
DE-OPT-01-D15-scheduler-baseline.png
DE-OPT-02-D15-15m-schedule.png
DE-OPT-03-D15-post-schedule-validation.png
DE-OPT-04-D13-scheduler-baseline.png
DE-OPT-05-D18-scheduler-baseline.png
DE-OPT-06-D13-15m-schedule.png
DE-OPT-07-D13-post-schedule-validation.png
DE-OPT-08-D18-15m-schedule.png
DE-OPT-09-D18-post-schedule-validation.png
```

D13, D15, and D18 were moved to staggered 15-minute schedules only after
scheduler telemetry showed concurrency skips despite healthy search runtimes.
Each optimization was accepted after two post-change runs completed with zero
skips, zero failures, and maximum runtime below 60 seconds.

## PB01 SOAR Engineering Evidence

Recommended evidence names for `PB01 - D13 Web Compromise to Internal Access`:

```text
SOAR-PB01-01-D13-webhook-schema.png
SOAR-PB01-02-normalized-incident.png
SOAR-PB01-03-windows-enrichment.png
SOAR-PB01-04-network-enrichment.png
SOAR-PB01-05-analyst-case.png
SOAR-PB01-06-brevo-approval-email.png
SOAR-PB01-07-approval-record.png
SOAR-PB01-08-production-gate.png
SOAR-PB01-09-opnsense-least-privilege-user-redacted.png
SOAR-PB01-10-opnsense-alias-and-rule.png
SOAR-PB01-11-live-alias-entry.png
SOAR-PB01-12-live-winrm-timeout.png
SOAR-PB01-13-manual-rollback-alias-empty.png
SOAR-PB01-14-post-rollback-winrm-restored.png
SOAR-PB01-15-rollback-design-gap.png
```

Current evidence establishes successful enrichment, analyst approval by email,
least-privilege API access, a live scoped block, observed WinRM timeout, manual
rollback, and restored connectivity. It also records the orchestration defect
that prevented the normal delayed rollback from being reached. Do not label
PB01 fully accepted until the independent automatic rollback design passes a
complete contain/verify/rollback/recovery test.

## PB04 SOAR Engineering Evidence

Recommended evidence names for
`PB04 - Active Directory Credential Access and Account Abuse`:

```text
SOAR-PB04-01-D14-webhook-normalization.png
SOAR-PB04-02-D15-webhook-normalization.png
SOAR-PB04-03-identity-asset-enrichment.png
SOAR-PB04-04-identity-risk-and-IRP-selection.png
SOAR-PB04-05-analyst-case-P2-IRP3.png
SOAR-PB04-06-analyst-review-email-redacted.png
SOAR-PB04-07-decision-validation.png
SOAR-PB04-08-fresh-safety-revalidation.png
SOAR-PB04-09-live-AD-precheck.png
SOAR-PB04-10-temporary-disable-success.png
SOAR-PB04-11-post-response-UAC-disabled.png
SOAR-PB04-12-post-response-Splunk-verification.png
SOAR-PB04-13-final-verified-success.png
SOAR-PB04-14-final-audit-persisted.png
SOAR-PB04-15-open-case-deleted.png
SOAR-PB04-16-fail-closed-AD-unreachable.png
SOAR-PB04-17-fail-closed-Splunk-unavailable.png
SOAR-PB04-18-account-manually-restored.png
SOAR-PB04-19-IRP2-monitoring-no-AD-action.png
SOAR-PB04-20-final-notification-result-redacted.png
```

The accepted final IRP3 evidence case is
`PB04-CASE-CCE7AF23B308938C`. It establishes a valid analyst decision, fresh
asset safety validation, exact-account AD precheck, successful temporary
disable, independent `ACCOUNTDISABLED` retrieval, a valid Splunk verification
window with no new authentication evidence, `VERIFIED/SUCCESS` response
assessment, final audit persistence, open-case deletion, and manual restoration
of `svc_sql` to `Enabled=True`.

PB04 also has negative-path evidence showing that an unreachable domain
controller and unavailable Splunk management service both stopped before the
AD write. Notification screenshots and logs must redact Brevo credentials,
recipient details that are unnecessary for the report, and temporary Shuffle
authorizations.

## PB05 SOAR Engineering Evidence

Recommended evidence names for
`PB05 - Endpoint Persistence and C2 Investigation and Containment`:

```text
SOAR-PB05-01-D17-webhook-normalization.png
SOAR-PB05-02-D18-webhook-normalization.png
SOAR-PB05-03-persistence-process-network-timeline.png
SOAR-PB05-04-P1-P4-stage-and-risk-assessment.png
SOAR-PB05-05-CRP2-analyst-case.png
SOAR-PB05-06-CRP3-layered-action-plan.png
SOAR-PB05-07-CRP4-reconnect-assessment.png
SOAR-PB05-08-native-user-input-waiting.png
SOAR-PB05-09-approval-email-redacted.png
SOAR-PB05-10-authenticated-approval-click-redacted.png
SOAR-PB05-11-decision-validation.png
SOAR-PB05-12-fresh-safety-revalidation.png
SOAR-PB05-13-preaction-evidence-persisted.png
SOAR-PB05-14-opnsense-c2-alias-verified.png
SOAR-PB05-15-matching-pf-states-terminated.png
SOAR-PB05-16-live-endpoint-state-before-response.png
SOAR-PB05-17-process-stop-verified.png
SOAR-PB05-18-run-value-removal-verified.png
SOAR-PB05-19-endpoint-state-after-response.png
SOAR-PB05-20-layered-containment-verified.png
SOAR-PB05-21-final-audit-and-case-update.png
SOAR-PB05-22-final-notification-redacted.png
SOAR-PB05-23-windows-postcheck-process-and-run-value.png
SOAR-PB05-24-binary-and-script-preserved.png
SOAR-PB05-25-fail-closed-process-state-changed.png
SOAR-PB05-26-fail-closed-winrm-or-ad-unavailable.png
```

The accepted PB05 campaign is `PB05-CMP-3F12E18B12B5C1DB` for
`WIN10-CLIENT01` and `svc_web`. The evidence establishes D17/D18
normalization, versioned case handling, native analyst approval, fresh safety
revalidation, immutable pre-action evidence, scoped OPNsense containment,
exact endpoint process and Run-value removal, independent verification, final
audit persistence, case update, and notification.

Windows-side post-check evidence must show zero matching Chisel processes and
an absent `PFA-Lab-Tunnel` value while confirming that the Chisel binary and
persistence script were preserved. Approval screenshots must redact active
authorization query strings, cookies, unnecessary analyst identifiers, source
addresses, passwords, and API credentials.

## Local Privilege-Escalation Replay Evidence

Accepted attack-only run: `PTR-20260909T162419Z-355a0dc0`.

The saved `events.jsonl` and `privilege-escalation-state.json` establish that
`LAB\svc_web` modified the exact vulnerable lab service script and that the
protected service wrapper subsequently executed PowerShell as
`NT AUTHORITY\SYSTEM`. The state includes both SIDs, write/start/proof
timestamps, before/after SHA-256 values, PID/parent PID, service state and the
Application-event write result. The run completed with exit code `0`, state
validation true, and both monitoring and response false.

Evidence directory:

```text
10 - Automation\Purple-Team-Attack-Replay\evidence\PTR-20260909T162419Z-355a0dc0
```

The endpoint proof and modified file remain in place for later Splunk
validation. Do not run the elevated reset until that collection is complete.

## Splunk License and Dashboard Validation Evidence

On 10 September 2026, the Enterprise Developer license was activated in the
Enterprise group. The validated license state is 10 GB/day with expiration on
6 March 2027. The license file itself is intentionally excluded from the vault.

The restored full executive dashboard was validated with `All time` selected:

```text
Security Events:     799,276
Active Data Sources: 10
Enabled Detections:  25
Detection Hits:      2,692
```

The event-volume, index-distribution, top-detection and Windows/Kerberos panels
also rendered historical data without the former license errors. Recommended
report evidence name:

```text
SPLUNK-EXEC-01-enterprise-license-and-full-dashboard.png
```

The screenshot should show the dashboard result, not the license file contents
or any license identifier.

## Evidence Rule

Every screenshot included in the report should answer:

1. What action was performed?
2. What does the screenshot prove?
3. Which system produced it?
4. Which MITRE technique or defensive control does it relate to?

Redact passwords, session cookies, hashes when unnecessary, API tokens, and personal information.

Credential artifacts such as `*.ccache`, `*.hash`, wordlists containing lab
passwords, session cookies, and authentication tokens must not be copied into
this vault or committed to Git. The repository `.gitignore` provides an
additional guard, but it does not replace manual review.
