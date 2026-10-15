#!/bin/sh
set -eu

project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cert_dir="$project_dir/certs"
cert_path="$cert_dir/localhost.pem"
key_path="$cert_dir/localhost-key.pem"

mkdir -p "$cert_dir"

private_ip=$(ipconfig getifaddr en0 2>/dev/null || true)
subject_alt_names="DNS:localhost,IP:127.0.0.1"
if [ -n "$private_ip" ]; then
    subject_alt_names="$subject_alt_names,IP:$private_ip"
fi

openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days 825 \
    -keyout "$key_path" \
    -out "$cert_path" \
    -subj "/CN=localhost" \
    -addext "subjectAltName=$subject_alt_names"

chmod 600 "$key_path"
printf 'Created local HTTPS certificate:\n  %s\n  %s\n' "$cert_path" "$key_path"
