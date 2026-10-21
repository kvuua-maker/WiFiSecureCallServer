#!/usr/bin/env bash
# Install or upgrade the SIP gateway on the VPS.
#
# Usage: WSC_EXPECTED_BUILD=<40-char-commit> ./install-sipgateway.sh <binary>
#
# The configuration file is authoritative: this script validates it and refuses
# to install without it. It never prints, rewrites or defaults a credential.
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then echo "run as root" >&2; exit 1; fi
if [[ $# -ne 1 ]]; then echo "usage: WSC_EXPECTED_BUILD=<40-char-commit> $0 /path/to/sipgw-binary" >&2; exit 2; fi

source_binary=$1
expected_build=${WSC_EXPECTED_BUILD:-}
root=/opt/wifi-secure-call
env_file=$root/config/sipgw.env
service_file=/etc/systemd/system/wifi-secure-call-sipgw.service
service_source=$(cd "$(dirname "$0")" && pwd)/wifi-secure-call-sipgw.service

if [[ ! -s $source_binary ]]; then echo "sip gateway binary is missing or empty" >&2; exit 2; fi
if [[ ! $expected_build =~ ^[0-9a-f]{40}$ ]]; then echo "set WSC_EXPECTED_BUILD to the exact server commit" >&2; exit 2; fi
if [[ ! -s $env_file ]]; then
  echo "sipgw.env is missing; copy deploy/sipgw.env.example and fill it in before deployment" >&2
  exit 3
fi

required=(SIPGW_DOMAIN SIPGW_USERS SIPGW_NONCE_SECRET SIPGW_MEDIA_RELAY)
for name in "${required[@]}"; do
  if ! grep -qE "^${name}=.+$" "$env_file"; then
    echo "sipgw.env is incomplete: $name is missing" >&2
    exit 3
  fi
done
if grep -q 'REPLACE_WITH' "$env_file"; then
  echo "sipgw.env still contains a REPLACE_WITH placeholder" >&2
  exit 3
fi
if ! grep -qE '^SIPGW_NONCE_SECRET=.{16,}$' "$env_file"; then
  echo "SIPGW_NONCE_SECRET must be at least 16 characters" >&2
  exit 3
fi
if ! grep -qE '^SIPGW_MEDIA_PUBLIC_IP=[0-9.]+$' "$env_file"; then
  echo "SIPGW_MEDIA_PUBLIC_IP must be set to the public address of this host" >&2
  exit 3
fi
chmod 600 "$env_file"

id wifi-secure-call >/dev/null 2>&1 || useradd --system --home-dir "$root" --shell /usr/sbin/nologin wifi-secure-call
install -d -o wifi-secure-call -g wifi-secure-call -m 0750 "$root/bin" "$root/config" "$root/state" "$root/backups"

stamp=$(date -u +%Y%m%dT%H%M%SZ)
stage=$root/bin/.wifi-secure-call-sipgw.$expected_build.stage
backup=$root/backups/wifi-secure-call-sipgw.$stamp
service_backup=$root/backups/wifi-secure-call-sipgw.service.$stamp
target=$root/bin/wifi-secure-call-sipgw

install -o root -g root -m 0755 "$source_binary" "$stage"
if [[ -f $target ]]; then cp -p "$target" "$backup"; fi
if [[ -f $service_file ]]; then cp -p "$service_file" "$service_backup"; fi

mv -f "$stage" "$target"
install -o root -g root -m 0644 "$service_source" "$service_file"

systemctl daemon-reload
systemctl enable wifi-secure-call-sipgw >/dev/null
systemctl restart wifi-secure-call-sipgw

for _ in $(seq 1 20); do
  if curl -fsS --max-time 2 http://127.0.0.1:8791/healthz >/dev/null; then
    echo "sip gateway $expected_build is running"
    exit 0
  fi
  sleep 0.5
done

echo "sip gateway did not become healthy; recent log:" >&2
journalctl -u wifi-secure-call-sipgw -n 40 --no-pager >&2 || true
exit 4
