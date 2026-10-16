#!/usr/bin/env bash
# Starts a throwaway OpenSSH server in Docker and runs the SSH integration tests against it.
set -euo pipefail
cd "$(dirname "$0")/../core"
tmp=$(mktemp -d)
trap 'docker rm -f termiux-sshd >/dev/null 2>&1; rm -rf "$tmp"' EXIT
ssh-keygen -q -t ed25519 -N '' -f "$tmp/id" -C termiux-test
docker rm -f termiux-sshd >/dev/null 2>&1 || true
docker run -d --name termiux-sshd -p 2222:2222 \
  -e USER_NAME=termiux -e USER_PASSWORD=termiux -e PASSWORD_ACCESS=true \
  -e PUBLIC_KEY="$(cat "$tmp/id.pub")" lscr.io/linuxserver/openssh-server:latest >/dev/null
for _ in $(seq 30); do docker exec termiux-sshd test -f /config/sshd/sshd_config 2>/dev/null && break; sleep 1; done
docker exec termiux-sshd sed -i "s/^AllowTcpForwarding no/AllowTcpForwarding yes/" /config/sshd/sshd_config
docker restart termiux-sshd >/dev/null
for _ in $(seq 30); do nc -z 127.0.0.1 2222 && break; sleep 1; done
sleep 2
TERMIUX_TEST_KEY="$tmp/id" cargo test -p termiux-ssh -- --ignored "$@"
