#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then echo "run as root" >&2; exit 1; fi
if [[ $# -ne 2 ]]; then echo "usage: $0 /secure/local/AuthKey.p8 APNS_KEY_ID" >&2; exit 2; fi
key_source=$1
key_id=$2
if [[ ! -f $key_source ]] || ! grep -q '^-----BEGIN PRIVATE KEY-----$' "$key_source" || ! grep -q '^-----END PRIVATE KEY-----$' "$key_source"; then echo "invalid APNs private key file" >&2; exit 2; fi
root=/opt/wifi-secure-call
install -d -o wifi-secure-call -g wifi-secure-call -m 0700 "$root/secrets"
install -o wifi-secure-call -g wifi-secure-call -m 0600 "$key_source" "$root/secrets/apns.p8"
env_file="$root/config/server.env"
sed -i "s/^APNS_ENABLED=.*/APNS_ENABLED=true/" "$env_file"
sed -i "s/^APNS_KEY_ID=.*/APNS_KEY_ID=$key_id/" "$env_file"
systemctl restart wifi-secure-call.service
curl --fail --silent http://127.0.0.1:8790/v1/health | grep -q '"apnsConfigured":true'

