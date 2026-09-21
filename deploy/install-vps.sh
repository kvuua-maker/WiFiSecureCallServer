#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then echo "run as root" >&2; exit 1; fi
if [[ $# -ne 1 ]]; then echo "usage: WSC_TOKEN_A=... WSC_TOKEN_B=... $0 /path/to/server-binary" >&2; exit 2; fi
if [[ -z ${WSC_TOKEN_A:-} || -z ${WSC_TOKEN_B:-} || ${WSC_TOKEN_A} == "${WSC_TOKEN_B}" ]]; then echo "distinct protected role tokens are required" >&2; exit 2; fi

root=/opt/wifi-secure-call
id wifi-secure-call >/dev/null 2>&1 || useradd --system --home-dir "$root" --shell /usr/sbin/nologin wifi-secure-call
install -d -o wifi-secure-call -g wifi-secure-call -m 0750 "$root/bin" "$root/config" "$root/state" "$root/backups"
install -d -o wifi-secure-call -g wifi-secure-call -m 0700 "$root/secrets"
install -o root -g wifi-secure-call -m 0750 "$1" "$root/bin/wifi-secure-call-server"

umask 077
env_file="$root/config/server.env"
tmp_file="$root/config/.server.env.new"
{
  printf 'WSC_ADDRESS=127.0.0.1:8790\n'
  printf 'WSC_STATE_PATH=/opt/wifi-secure-call/state/devices.json\n'
  printf 'WSC_TOKEN_A=%s\n' "$WSC_TOKEN_A"
  printf 'WSC_TOKEN_B=%s\n' "$WSC_TOKEN_B"
  printf 'APNS_ENABLED=false\n'
  printf 'APNS_TEAM_ID=9V5XXDXF3N\n'
  printf 'APNS_KEY_ID=\n'
  printf 'APNS_KEY_PATH=/opt/wifi-secure-call/secrets/apns.p8\n'
  printf 'APNS_TOPIC_IOS=com.vkapps.wifisecurecall\n'
  printf 'APNS_TOPIC_WATCH=com.vkapps.wifisecurecall.watchkitapp\n'
  printf 'APNS_TOPIC_IOS_VOIP=com.vkapps.wifisecurecall.voip\n'
  printf 'APNS_TOPIC_WATCH_VOIP=com.vkapps.wifisecurecall.watchkitapp.voip\n'
} > "$tmp_file"
chown root:wifi-secure-call "$tmp_file"; chmod 0640 "$tmp_file"; mv "$tmp_file" "$env_file"
install -o root -g root -m 0644 "$(dirname "$0")/wifi-secure-call.service" /etc/systemd/system/wifi-secure-call.service
systemctl daemon-reload
systemctl enable --now wifi-secure-call.service
curl --fail --silent http://127.0.0.1:8790/v1/health >/dev/null
