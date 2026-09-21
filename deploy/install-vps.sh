#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then echo "run as root" >&2; exit 1; fi
if [[ $# -ne 1 ]]; then echo "usage: WSC_EXPECTED_BUILD=<40-char-commit> $0 /path/to/server-binary" >&2; exit 2; fi

source_binary=$1
expected_build=${WSC_EXPECTED_BUILD:-}
root=/opt/wifi-secure-call
env_file=$root/config/server.env
service_file=/etc/systemd/system/wifi-secure-call.service
service_source=$(cd "$(dirname "$0")" && pwd)/wifi-secure-call.service

if [[ ! -s $source_binary ]]; then echo "server binary is missing or empty" >&2; exit 2; fi
if [[ ! $expected_build =~ ^[0-9a-f]{40}$ ]]; then echo "set WSC_EXPECTED_BUILD to the exact server commit" >&2; exit 2; fi
if [[ ! -s $env_file ]]; then
  echo "production server.env is missing; restore the protected production config before deployment" >&2
  exit 3
fi

# Production configuration is authoritative. Validate it without sourcing,
# printing, rewriting, or supplying defaults for any credential.
required=(WSC_ADDRESS WSC_STATE_PATH WSC_TOKEN_A WSC_TOKEN_B APNS_ENABLED APNS_TEAM_ID APNS_KEY_ID APNS_KEY_PATH APNS_TOPIC_IOS APNS_TOPIC_WATCH APNS_TOPIC_IOS_VOIP APNS_TOPIC_WATCH_VOIP)
for name in "${required[@]}"; do
  if ! grep -qE "^${name}=.+$" "$env_file"; then
    echo "production server.env is incomplete; restore the protected $name value before deployment" >&2
    exit 3
  fi
done
if ! grep -q '^APNS_ENABLED=true$' "$env_file"; then
  echo "production APNs configuration is not enabled; restore it before deployment" >&2
  exit 3
fi

apns_key_path=$(sed -n 's/^APNS_KEY_PATH=//p' "$env_file" | tail -n 1)
if [[ -z $apns_key_path || ! -s $apns_key_path ]]; then
  echo "configured APNs key file is unavailable; restore it before deployment" >&2
  exit 3
fi

id wifi-secure-call >/dev/null 2>&1 || useradd --system --home-dir "$root" --shell /usr/sbin/nologin wifi-secure-call
install -d -o wifi-secure-call -g wifi-secure-call -m 0750 "$root/bin" "$root/config" "$root/state" "$root/backups"
install -d -o wifi-secure-call -g wifi-secure-call -m 0700 "$root/secrets"

stamp=$(date -u +%Y%m%dT%H%M%SZ)
stage=$root/bin/.wifi-secure-call-server.$expected_build.stage
backup=$root/backups/wifi-secure-call-server.$stamp
service_backup=$root/backups/wifi-secure-call.service.$stamp
target=$root/bin/wifi-secure-call-server
had_binary=0
had_service=0
committed=0

cleanup() { rm -f "$stage"; }
rollback() {
  local status=$?
  trap - ERR
  if [[ $committed -eq 1 ]]; then
    if [[ $had_binary -eq 1 && -s $backup ]]; then
      install -o wifi-secure-call -g wifi-secure-call -m 0755 "$backup" "$target"
    else
      rm -f "$target"
    fi
    if [[ $had_service -eq 1 && -s $service_backup ]]; then
      install -o root -g root -m 0644 "$service_backup" "$service_file"
    else
      rm -f "$service_file"
    fi
    systemctl daemon-reload || true
    systemctl restart wifi-secure-call.service || true
  fi
  cleanup
  exit "$status"
}
trap rollback ERR
trap cleanup EXIT

install -o wifi-secure-call -g wifi-secure-call -m 0755 "$source_binary" "$stage"
staged_hash=$(sha256sum "$stage" | awk '{print $1}')
[[ $staged_hash =~ ^[0-9a-f]{64}$ ]]

if [[ -s $target ]]; then cp -p "$target" "$backup"; had_binary=1; fi
if [[ -s $service_file ]]; then cp -p "$service_file" "$service_backup"; had_service=1; fi
systemd-analyze verify "$service_source" >/dev/null

mv -f "$stage" "$target"
install -o root -g root -m 0644 "$service_source" "$service_file"
committed=1
systemctl daemon-reload
systemctl enable wifi-secure-call.service >/dev/null
systemctl restart wifi-secure-call.service

healthy=0
for _ in {1..20}; do
  if health=$(curl --fail --silent --max-time 2 http://127.0.0.1:8790/v1/health) &&
     jq -e --arg build "$expected_build" '.ok == true and .apnsConfigured == true and .mediaReady == true and .build == $build' <<<"$health" >/dev/null; then
    healthy=1
    break
  fi
  sleep 0.5
done
if [[ $healthy -ne 1 || $(systemctl is-active wifi-secure-call.service) != active ]]; then
  echo "new service failed readiness; previous binary is being restored" >&2
  false
fi

pid=$(systemctl show wifi-secure-call.service -p MainPID --value)
running_hash=$(sha256sum "/proc/$pid/exe" | awk '{print $1}')
disk_hash=$(sha256sum "$target" | awk '{print $1}')
if [[ $running_hash != "$staged_hash" || $disk_hash != "$staged_hash" ]]; then
  echo "running process does not match the staged binary; previous binary is being restored" >&2
  false
fi

committed=0
trap - ERR
cleanup
trap - EXIT
