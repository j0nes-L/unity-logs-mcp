#!/usr/bin/env bash
# Sets up the Unity Logs MCP server. Run it on the server (Linux with Docker):
#   curl -fsSL https://raw.githubusercontent.com/j0nes-L/unity-logs-mcp/main/setup.sh | bash
# Running it again updates code and settings and keeps every key and log.
set -euo pipefail

REPO="https://github.com/j0nes-L/unity-logs-mcp.git"

ask() {
  local answer=""
  { read -rp "$1 [$2]: " answer </dev/tty; } 2>/dev/null || true
  echo "${answer:-$2}"
}

for cmd in git openssl docker; do
  command -v "$cmd" >/dev/null || { echo "Missing: $cmd" >&2; exit 1; }
done
docker compose version >/dev/null 2>&1 || { echo "Missing: the docker compose plugin" >&2; exit 1; }
docker info >/dev/null 2>&1 || { echo "This user cannot use Docker; add it to the docker group and log in again." >&2; exit 1; }

DIR=$(ask "Install directory" "${UNITY_LOGS_DIR:-$HOME/unity-logs-mcp}")
if [ -d "$DIR/.git" ]; then git -C "$DIR" pull --ff-only --quiet; else git clone --quiet --depth 1 "$REPO" "$DIR"; fi
cd "$DIR"

if [ -f .env ]; then . ./.env; fi

while :; do
  CONNECTION_NAME=$(ask "Name of the MCP connection in Claude" "${CONNECTION_NAME:-unity-logs}")
  [[ $CONNECTION_NAME =~ ^[A-Za-z0-9_-]+$ ]] && break
  echo "Only letters, digits, - and _ please." >&2
done

DOMAIN=$(ask "Domain pointing to this server, for HTTPS (empty = plain HTTP on port ${PORT:-8080})" "${DOMAIN:-}")

case "${LOG_RETENTION_DAYS:-30}" in 7) current=1 ;; 0) current=3 ;; *) current=2 ;; esac
echo "How long should logs be kept?  1) 7 days   2) 30 days   3) unlimited, never deleted"
case $(ask "Choice" "$current") in 1) LOG_RETENTION_DAYS=7 ;; 3) LOG_RETENTION_DAYS=0 ;; *) LOG_RETENTION_DAYS=30 ;; esac

PORT=${PORT:-8080}
API_KEY=${API_KEY:-$(openssl rand -hex 32)}
MCP_TOKEN=${MCP_TOKEN:-$(openssl rand -hex 32)}

mkdir -p secrets && chmod 700 secrets
if [ ! -f secrets/log-private.pem ]; then
  (umask 077 && openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out secrets/log-private.pem 2>/dev/null)
fi
openssl pkey -in secrets/log-private.pem -pubout -out secrets/log-public.pem

if [ -n "$DOMAIN" ]; then
  SSH_HOST=$DOMAIN; BASE_URL="https://$DOMAIN"
  BIND=127.0.0.1; BEHIND_PROXY=true; COMPOSE_PROFILES=tls   # Only Caddy talks to the API.
else
  SSH_HOST=$(hostname -I 2>/dev/null | awk '{print $1}' || true); SSH_HOST=${SSH_HOST:-SERVER-IP}
  BASE_URL="http://$SSH_HOST:$PORT"
  BIND=0.0.0.0; BEHIND_PROXY=false; COMPOSE_PROFILES=
fi

(umask 077 && cat > .env <<EOF
CONNECTION_NAME=$CONNECTION_NAME
DOMAIN=$DOMAIN
LOG_RETENTION_DAYS=$LOG_RETENTION_DAYS
API_KEY=$API_KEY
MCP_TOKEN=$MCP_TOKEN
PORT=$PORT
BIND=$BIND
BEHIND_PROXY=$BEHIND_PROXY
COMPOSE_PROFILES=$COMPOSE_PROFILES
HOST_UID=$(id -u)
EOF
)

docker compose up -d --build

cat <<EOF

=============== Unity: MCPLogger component ===============
Endpoint       : $BASE_URL/logs
API key        : $API_KEY
                 (in Unity: Tools > Unity Logs MCP > Set API Key)
Public Key Pem :
$(cat secrets/log-public.pem)

=============== Claude Code: pick one ===============
Plain text, via SSH - the private key never leaves this server (needs SSH key login from your machine):
  claude mcp add --scope user $CONNECTION_NAME -- ssh $(whoami)@$SSH_HOST docker compose -f $DIR/docker-compose.yml run --rm -T mcp-stdio

Remote, over $BASE_URL - personal data stays [pii:...] tokens:
  claude mcp add --scope user --transport http $CONNECTION_NAME $BASE_URL/mcp --header "Authorization: Bearer $MCP_TOKEN"

Settings and secrets: $DIR/.env
Private key: $DIR/secrets/log-private.pem - back it up, without it the personal data in stored logs stays encrypted.
EOF

if [ -z "$DOMAIN" ]; then
  echo "Warning: without a domain, keys and logs travel unencrypted, and Android blocks plain HTTP unless the Unity player settings allow it." >&2
fi
