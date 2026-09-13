#!/usr/bin/env bash
set -u

dvwa_address="${1:-}"
dvwa_port="${2:-}"
callback_port="${3:-}"
socks_port="${4:-}"
static_chisel_path="${5:-}"
expected_static_sha256="${6:-}"

if [[ "$dvwa_address" != "192.168.111.128" || "$dvwa_port" != "8080" || "$callback_port" != "443" || "$socks_port" != "1080" || "$static_chisel_path" != "/home/kali/pfa-evidence/phase3-pivot/chisel-static" || "$expected_static_sha256" != "8fc08cb354379cbdfa735eb2cb6a9a045b25fe37967f28b1917625d7cdc052a3" ]]; then
    printf 'FOOTHOLD_STATUS=REFUSED_OUTSIDE_DOCUMENTED_SCOPE\n'
    exit 20
fi

missing_tools=0
for tool in curl chisel nc ss file sha256sum; do
    if command -v "$tool" >/dev/null 2>&1; then
        printf 'TOOL_%s=FOUND:%s\n' "${tool^^}" "$(command -v "$tool")"
    else
        printf 'TOOL_%s=MISSING\n' "${tool^^}"
        missing_tools=1
    fi
done

if [[ "$missing_tools" -ne 0 ]]; then
    printf 'FOOTHOLD_STATUS=MISSING_REQUIRED_TOOL\n'
    exit 21
fi

http_code="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 10 "http://${dvwa_address}:${dvwa_port}/" 2>/dev/null || true)"
if [[ "$http_code" == "000" || -z "$http_code" ]]; then
    printf 'DVWA_EXTERNAL=UNREACHABLE:http://%s:%s/\n' "$dvwa_address" "$dvwa_port"
    printf 'FOOTHOLD_STATUS=DVWA_ENTRY_POINT_UNREACHABLE\n'
    exit 22
fi
printf 'DVWA_EXTERNAL=REACHABLE_HTTP_%s:http://%s:%s/\n' "$http_code" "$dvwa_address" "$dvwa_port"

if ss -lntH | awk '{print $4}' | grep -Eq "(^|:)${callback_port}$"; then
    printf 'CALLBACK_PORT_%s=IN_USE\n' "$callback_port"
else
    printf 'CALLBACK_PORT_%s=AVAILABLE\n' "$callback_port"
fi

if ss -lntH | awk '{print $4}' | grep -Eq "(^|:)${socks_port}$"; then
    printf 'SOCKS_%s=ALREADY_LISTENING\n' "$socks_port"
else
    printf 'SOCKS_%s=NOT_LISTENING\n' "$socks_port"
fi

candidate_count=0
for candidate in \
    /usr/bin/chisel \
    "$HOME/chisel" \
    "$HOME/chisel-static" \
    "$HOME/tools/chisel" \
    "$HOME/tools/chisel-static"; do
    if [[ -f "$candidate" ]]; then
        candidate_count=$((candidate_count + 1))
        description="$(file -b "$candidate" 2>/dev/null || printf 'unknown')"
        digest="$(sha256sum "$candidate" | awk '{print $1}')"
        printf 'CHISEL_CANDIDATE_%s=%s|sha256=%s|%s\n' "$candidate_count" "$candidate" "$digest" "$description"
    fi
done

if [[ "$candidate_count" -eq 0 ]]; then
    printf 'FOOTHOLD_STATUS=NO_CHISEL_CANDIDATE\n'
    exit 23
fi

if [[ ! -f "$static_chisel_path" ]]; then
    printf 'VERIFIED_STATIC_CHISEL=MISSING:%s\n' "$static_chisel_path"
    printf 'FOOTHOLD_STATUS=VERIFIED_STATIC_CHISEL_MISSING\n'
    exit 24
fi

actual_static_sha256="$(sha256sum "$static_chisel_path" | awk '{print $1}')"
if [[ "$actual_static_sha256" != "$expected_static_sha256" ]]; then
    printf 'VERIFIED_STATIC_CHISEL=SHA256_MISMATCH:%s\n' "$static_chisel_path"
    printf 'FOOTHOLD_STATUS=VERIFIED_STATIC_CHISEL_MISMATCH\n'
    exit 25
fi

if ! file -b "$static_chisel_path" | grep -qi 'statically linked'; then
    printf 'VERIFIED_STATIC_CHISEL=NOT_STATIC:%s\n' "$static_chisel_path"
    printf 'FOOTHOLD_STATUS=VERIFIED_CHISEL_NOT_STATIC\n'
    exit 26
fi
printf 'VERIFIED_STATIC_CHISEL=OK:%s|sha256=%s\n' "$static_chisel_path" "$actual_static_sha256"

printf 'PROXYCHAINS_CONFIG_CANDIDATES_BEGIN\n'
find "$HOME" -maxdepth 3 -type f -iname '*proxychains*.conf' -print 2>/dev/null | sort
printf 'PROXYCHAINS_CONFIG_CANDIDATES_END\n'
printf 'FOOTHOLD_STATUS=FOOTHOLD_PREREQUISITES_READY\n'
