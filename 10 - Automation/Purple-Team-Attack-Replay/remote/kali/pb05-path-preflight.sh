#!/usr/bin/env bash
set -u

target_address="${1:-}"
target_port="${2:-}"
socks_port="${3:-}"

if [[ "$target_address" != "10.10.30.20" || "$target_port" != "5985" || "$socks_port" != "1080" ]]; then
    printf 'PATH_STATUS=REFUSED_OUTSIDE_PB05_SCOPE\n'
    exit 10
fi

missing_tools=0
for tool in proxychains4 chisel nc ss; do
    if command -v "$tool" >/dev/null 2>&1; then
        printf 'TOOL_%s=FOUND:%s\n' "${tool^^}" "$(command -v "$tool")"
    else
        printf 'TOOL_%s=MISSING\n' "${tool^^}"
        missing_tools=1
    fi
done

psrp_python='/home/kali/.local/share/pb05-replay/venv/bin/python'
if [[ -x "$psrp_python" ]] && "$psrp_python" -c 'import pypsrp' >/dev/null 2>&1; then
    printf 'TOOL_PYPSRP=FOUND:%s\n' "$psrp_python"
else
    printf 'TOOL_PYPSRP=MISSING:%s\n' "$psrp_python"
    missing_tools=1
fi

if [[ "$missing_tools" -ne 0 ]]; then
    printf 'PATH_STATUS=MISSING_REQUIRED_TOOL\n'
    exit 11
fi

if ! ss -lntH | awk '{print $4}' | grep -Eq "(^|:)${socks_port}$"; then
    printf 'SOCKS_%s=NOT_LISTENING\n' "$socks_port"
    printf 'PATH_STATUS=DMZ_PIVOT_NOT_READY\n'
    exit 12
fi

printf 'SOCKS_%s=LISTENING\n' "$socks_port"

proxy_config="$(mktemp)"
cleanup() {
    rm -f -- "$proxy_config"
}
trap cleanup EXIT

cat >"$proxy_config" <<EOF
strict_chain
proxy_dns
quiet_mode
tcp_read_time_out 10000
tcp_connect_time_out 5000

[ProxyList]
socks5 127.0.0.1 ${socks_port}
EOF

if proxychains4 -q -f "$proxy_config" nc -zvw5 "$target_address" "$target_port" >/dev/null 2>&1; then
    printf 'WINRM_THROUGH_SOCKS=REACHABLE:%s:%s\n' "$target_address" "$target_port"
    printf 'PATH_STATUS=PB05_ATTACK_PATH_READY\n'
    exit 0
fi

printf 'WINRM_THROUGH_SOCKS=UNREACHABLE:%s:%s\n' "$target_address" "$target_port"
printf 'PATH_STATUS=WINRM_NOT_REACHABLE_THROUGH_DMZ_PIVOT\n'
exit 13
