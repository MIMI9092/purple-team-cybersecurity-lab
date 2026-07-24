# 03 - DMZ Reverse Shell

## Objective

Convert web-level command injection into interactive operating-system command execution.

## Initial Command Execution

The DVWA command-injection page accepted an IP value that was passed unsafely to a shell command. By appending a second shell instruction, the application executed attacker-controlled commands.

Validation commands proved execution as:

```text
User: www-data
Container hostname: ea409ae2935c
Working directory: /var/www/html/vulnerabilities/exec
```

## Reverse Shell

Kali listened on TCP `443`. The vulnerable application launched a shell that initiated an outbound connection to Kali.

```text
DVWA www-data shell -> Kali TCP 443
```

The shell displayed terminal-control warnings because it was a basic non-interactive shell without a proper TTY. Command execution still worked.

## Why It Was Called a Reverse Shell

The compromised server initiated the network connection to the attacker. This often bypasses controls that block unsolicited inbound access but allow outbound traffic.

## Security Context

The shell ran as `www-data`, not root:

- It could read files available to the web service.
- It could execute commands inside the container.
- It did not automatically control the Ubuntu host.
- It did not automatically have Active Directory privileges.

## Credential Discovery

The shell found a deliberately placed legacy configuration file:

```text
/var/www/html/config/legacy-backup.conf
```

It contained a controlled `LAB\svc_web` credential and internal WinRM information. The actual password is redacted from this vault.

## Defensive Evidence

- DVWA access logs recorded POST requests to `/vulnerabilities/exec/`.
- OPNsense recorded the outbound TCP 443 connection.
- The contents of the POST body were not present in standard access logs.
- Suricata did not generate a reliable alert for the reverse shell.

## Detection Gap

The network connection was visible, but its malicious command content was not. Better endpoint process telemetry or detailed application logging is needed.

## MITRE / CKC

- MITRE `T1059.004`: Unix Shell
- MITRE `T1059`: Command and Scripting Interpreter
- CKC: Exploitation / Installation
