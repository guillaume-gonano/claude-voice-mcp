#!/bin/bash
# Publishes the voice MCP. Two modes (TUNNEL in data/install.env):
# - cloudflare: DNS record, Cloudflare Access on /authorize, cloudflared service;
# - other: your own tunnel (Tailscale Funnel, ngrok…), /authorize protected by a password.
# Then: local config and auto-start services (macOS LaunchAgents).
# Safe to re-run: every step first checks what already exists.
# Settings come from data/install.env (see install.env.example).
set -euo pipefail
umask 077

P="$(cd "$(dirname "$0")/.." && pwd)"
[ -f "$P/data/install.env" ] || { echo "Missing data/install.env: copy install.env.example and fill it in."; exit 1; }
# shellcheck source=/dev/null
. "$P/data/install.env"
TUNNEL="${TUNNEL:-cloudflare}"
: "${HOST:?}"
LABEL="${LABEL:-local.claude-voice-mcp}"
PORT="${PORT:-47851}"
LA="$HOME/Library/LaunchAgents"
CONFIG="$P/data/config.json"
mkdir -p "$P/data" "$P/run"
[ -f "$CONFIG" ] || cp "$P/config.example.json" "$CONFIG"

if [ "$TUNNEL" = "cloudflare" ]; then
: "${ZONE:?} ${TUNNEL_ID:?} ${ACCESS_TEAM:?} ${ACCESS_EMAIL:?}"
[ -f "$P/data/tunnel-token" ] || { echo "Missing data/tunnel-token (tunnel token from the Cloudflare dashboard)."; exit 1; }

echo "1/4 DNS $HOST → tunnel"
if [ "$(cf dns records list --zone "$ZONE" --name "$HOST" | jq length)" = "0" ]; then
  cf dns records create --zone "$ZONE" --body "{\"type\":\"CNAME\",\"name\":\"$HOST\",\"content\":\"$TUNNEL_ID.cfargotunnel.com\",\"proxied\":true,\"comment\":\"Claude voice MCP\"}" | jq -c '{name,content,proxied}'
else
  echo "   already there"
fi

echo "2/4 Cloudflare Access on $HOST/authorize ($ACCESS_EMAIL only)"
AUD="$(cf zero-trust access applications list | jq -r --arg d "$HOST/authorize" '.[] | select(.domain==$d) | .aud' | head -1)"
if [ -z "$AUD" ]; then
  AUD="$(cf zero-trust access applications create --body "$(jq -n --arg host "$HOST" --arg email "$ACCESS_EMAIL" --arg idp "${ACCESS_IDP:-}" '{
    name: "claude-voice-mcp-authorize",
    type: "self_hosted",
    domain: "\($host)/authorize",
    auto_redirect_to_identity: ($idp != ""),
    session_duration: "24h",
    policies: [{ name: "Owner only", decision: "allow", include: [{ email: { email: $email } }] }]
  } + (if $idp != "" then { allowed_idps: [$idp] } else {} end)')" | jq -r .aud)"
fi
[ -n "$AUD" ] && [ "$AUD" != "null" ] || { echo "Failed: Access AUD not found"; exit 1; }
echo "   AUD read"

echo "3/4 Local config"
# Keeps the personal settings already in config.json (userName, toolsHint…).
jq --arg url "https://$HOST" --argjson port "$PORT" --arg team "$ACCESS_TEAM" --arg aud "$AUD" --arg email "$ACCESS_EMAIL" \
  '.publicUrl = $url | .port = $port | .access = {team: $team, aud: $aud, email: $email}' "$CONFIG" > "$CONFIG.tmp"
mv "$CONFIG.tmp" "$CONFIG"

elif [ "$TUNNEL" = "other" ]; then
echo "1-3/4 Local config (your own tunnel must forward https://$HOST to http://127.0.0.1:$PORT)"
NEW_PASSWORD=""
if [ "$(jq -r '.password // empty' "$CONFIG")" = "" ]; then
  NEW_PASSWORD="$(openssl rand -base64 24 | tr -d '/+=' | cut -c1-24)"
fi
jq --arg url "https://$HOST" --argjson port "$PORT" --arg pw "$NEW_PASSWORD" \
  '.publicUrl = $url | .port = $port | del(.access) | if $pw != "" then .password = $pw else . end' "$CONFIG" > "$CONFIG.tmp"
mv "$CONFIG.tmp" "$CONFIG"

else
  echo "TUNNEL must be cloudflare or other"; exit 1
fi

echo "4/4 Auto-start services"
NODE="$(command -v node)"
CLOUDFLARED="$(command -v cloudflared || true)"
write_agent() { # label, arguments as XML
  cat > "$LA/$1.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>$1</string>
  <key>ProgramArguments</key><array>$2</array>
  <key>WorkingDirectory</key><string>$P</string>
  <key>EnvironmentVariables</key><dict><key>PATH</key><string>$HOME/.local/bin:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin</string></dict>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>$P/run/$1.log</string>
  <key>StandardErrorPath</key><string>$P/run/$1.log</string>
</dict></plist>
EOF
  chmod 644 "$LA/$1.plist"
  launchctl bootout "gui/$(id -u)/$1" 2>/dev/null || true
  # macOS finishes stopping in the background: wait before starting again.
  for _ in $(seq 20); do launchctl print "gui/$(id -u)/$1" >/dev/null 2>&1 || break; sleep 0.5; done
  launchctl bootstrap "gui/$(id -u)" "$LA/$1.plist"
}
write_agent "$LABEL" "<string>$NODE</string><string>$P/server.mjs</string>"
[ "$TUNNEL" = "cloudflare" ] && write_agent "$LABEL-tunnel" "<string>$CLOUDFLARED</string><string>tunnel</string><string>--no-autoupdate</string><string>run</string><string>--token-file</string><string>$P/data/tunnel-token</string>"

sleep 5
echo "Checks:"
curl -fsS "http://127.0.0.1:$PORT/health" && echo "   local server OK"
curl -sS -o /dev/null -w "   public /mcp without a token → %{http_code} (expected 401)\n" -X POST "https://$HOST/mcp"
if [ "$TUNNEL" = "cloudflare" ]; then
  # A new Access application can take one or two minutes to apply.
  for _ in $(seq 12); do
    code="$(curl -sS -o /dev/null -w "%{http_code}" "https://$HOST/authorize")"
    [ "$code" = "302" ] && break
    sleep 10
  done
  echo "   public /authorize → $code (expected 302 to Cloudflare Access)"
else
  curl -sS -o /dev/null -w "   public /authorize → %{http_code} (expected 200, the password page)\n" "https://$HOST/authorize"
  [ -n "$NEW_PASSWORD" ] && echo "Password to type when connecting the Claude app (also in data/config.json): $NEW_PASSWORD"
fi
echo "Connector URL to add in Claude: https://$HOST/mcp"
