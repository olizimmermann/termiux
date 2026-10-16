#!/usr/bin/env bash
# Starts a long-running OpenSSH server in Docker for trying the app by hand:
#   127.0.0.1:2222, user termiux, password termiux, TCP forwarding on, vim + htop installed.
# Optional: PUBLIC_KEY_FILE=path/to/key.pub to authorize a key.   Stop: docker rm -f termiux-sshd
set -euo pipefail
docker rm -f termiux-sshd >/dev/null 2>&1 || true
docker run -d --name termiux-sshd -p 2222:2222 \
  -e USER_NAME=termiux -e USER_PASSWORD=termiux -e PASSWORD_ACCESS=true \
  -e PUBLIC_KEY="$(cat "${PUBLIC_KEY_FILE:-/dev/null}")" \
  lscr.io/linuxserver/openssh-server:latest >/dev/null
for _ in $(seq 30); do docker exec termiux-sshd test -f /config/sshd/sshd_config 2>/dev/null && break; sleep 1; done
docker exec termiux-sshd sh -c '
  sed -i "s/^AllowTcpForwarding no/AllowTcpForwarding yes/; s/^GatewayPorts no/GatewayPorts clientspecified/" /config/sshd/sshd_config
  apk add -q htop vim >/dev/null 2>&1 || true'
docker restart termiux-sshd >/dev/null
for _ in $(seq 30); do nc -z 127.0.0.1 2222 && break; sleep 1; done
echo "SSH test server ready on 127.0.0.1:2222 (termiux / termiux)"
