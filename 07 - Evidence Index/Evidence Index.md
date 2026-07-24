# Evidence Index

## Evidence Locations

### Kali

```text
~/pfa-evidence/phase1-recon/
~/pfa-evidence/phase2-web/
~/pfa-evidence/phase3-pivot/
~/pfa-evidence/phase4-ad/
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
```

## Evidence Rule

Every screenshot included in the report should answer:

1. What action was performed?
2. What does the screenshot prove?
3. Which system produced it?
4. Which MITRE technique or defensive control does it relate to?

Redact passwords, session cookies, hashes when unnecessary, API tokens, and personal information.
