#!/usr/bin/env python3
"""Print focused, redacted PB05 commands from fixed lab evidence sources."""

from pathlib import Path
import re


SOURCES = (
    Path('/home/kali/.bash_history'),
    Path('/home/kali/.zsh_history'),
    Path('/home/kali/pfa-evidence/phase2-web/reverse-shell-session.txt'),
    Path('/home/kali/pfa-evidence/phase2-web/dmz-pivot-discovery-session.txt'),
)

PB05_FOCUSED = re.compile(
    r'phase3-pivot|phase6-persistence|PFA-Lab-Tunnel|pfa-tunnel\.ps1|'
    r'chisel-static\s+server|/tmp/chisel|R:1080:socks|R:1082:socks|'
    r'evil-winrm|proxychains(?:4)?[^\r\n]*(?:10\.10\.30\.(?:10|20)|nc\b)|'
    r'vulnerabilities/exec|192\.168\.111\.128:8080',
    re.IGNORECASE,
)

SENSITIVE_CONTEXT = re.compile(
    r'phase4-ad|phase5-valid-account|phase7-password-spray|GetUserSPNs|'
    r'hashcat|\bjohn\b|kerberoast|\.ccache|\.kirbi|\$krb5|'
    r'\becho\s+[^|\r\n]+\|\s*(?:proxychains4?\s+)?kinit\b',
    re.IGNORECASE,
)

ANSI_ESCAPE = re.compile(r'\x1b\[[0-?]*[ -/]*[@-~]')


def logical_commands(value: str):
    """Join shell lines ending in a backslash and retain their source range."""
    start = None
    parts = []

    for number, raw_line in enumerate(value.splitlines(), 1):
        line = ANSI_ESCAPE.sub('', raw_line).strip()
        line = re.sub(r'^:\s*\d+:\d+;', '', line)

        if not line:
            if parts:
                yield start, number - 1, ' '.join(parts)
                start = None
                parts = []
            continue

        if start is None:
            start = number

        continued = line.endswith('\\')
        parts.append(line[:-1].rstrip() if continued else line)
        if not continued:
            yield start, number, ' '.join(parts)
            start = None
            parts = []

    if parts:
        yield start, start + len(parts) - 1, ' '.join(parts)


def redact(value: str) -> str:
    value = re.sub(
        r'(?i)(evil-winrm\b[^\r\n]*?(?:\s-p|\s--password)\s+)(?:"[^"]*"|\'[^\']*\'|\S+)',
        r'\1<REDACTED>',
        value,
    )
    value = re.sub(r'(?i)(PHPSESSID=)[^;\s"\']+', r'\1<REDACTED>', value)
    value = re.sub(r'(?i)(Cookie:\s*)[^\r\n]+', r'\1<REDACTED>', value)
    value = re.sub(r'(?i)(Authorization:\s*)[^\r\n]+', r'\1<REDACTED>', value)
    value = re.sub(
        r'(?i)((?:password|passwd|pwd|token|secret)\s*[:=]\s*)(?:"[^"]*"|\'[^\']*\'|\S+)',
        r'\1<REDACTED>',
        value,
    )
    value = re.sub(r'\$krb5(?:tgs|asrep)\$\S+', '<KERBEROS_MATERIAL_REDACTED>', value)
    value = re.sub(r'(?<![0-9A-Fa-f])[0-9A-Fa-f]{48,}(?![0-9A-Fa-f])', '<LONG_HEX_REDACTED>', value)
    if len(value) > 1000:
        value = value[:1000] + ' ... <TRUNCATED>'
    return value


print('DISCOVERY_POLICY=FIXED_SOURCES_PB05_LOGICAL_COMMANDS_REDACTED')
match_count = 0
for source in SOURCES:
    if not source.is_file():
        print(f'SOURCE_MISSING={source}')
        continue

    print(f'SOURCE_BEGIN={source}')
    for start, end, command in logical_commands(source.read_text(errors='replace')):
        if not PB05_FOCUSED.search(command):
            continue
        location = f'{start}' if start == end else f'{start}-{end}'
        if SENSITIVE_CONTEXT.search(command):
            print(f'{source}:{location}:<SENSITIVE_COMMAND_OMITTED>')
            match_count += 1
            continue
        print(f'{source}:{location}:{redact(command)}')
        match_count += 1
    print(f'SOURCE_END={source}')

print(f'REDACTED_RELEVANT_LINE_COUNT={match_count}')
print('DISCOVERY_STATUS=COMPLETED')
