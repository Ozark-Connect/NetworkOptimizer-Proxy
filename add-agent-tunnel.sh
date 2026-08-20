#!/usr/bin/env bash
set -euo pipefail

# Add the multi-site agent tunnel route to an existing dynamic/config.yml.
#
# setup.sh copies config.example.yml once and never touches it again, so installs
# made before the agent tunnel shipped have no gRPC route. This adds just that
# route, in place, leaving every other line of your config alone.
#
# It finds the Network Optimizer app by its backend port (8042) rather than by
# name, reads the hostname off whichever router serves it, and inserts a matching
# gRPC router + service + serversTransport. Nothing else is read or rewritten.
#
# Usage: bash add-agent-tunnel.sh [--dry-run] [--app-port N] [--tunnel-port N]

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG=""
APP_PORT=8042
TUNNEL_PORT=8043
DRY_RUN=0
GRPC_PATH="/networkoptimizer.agent.v1.AgentTunnel/"

while [ $# -gt 0 ]; do
    case "$1" in
        --dry-run)     DRY_RUN=1 ;;
        --app-port)    APP_PORT="${2:?}"; shift ;;
        --tunnel-port) TUNNEL_PORT="${2:?}"; shift ;;
        --config)      CONFIG="${2:?}"; shift ;;
        --help|-h)     sed -n '3,14p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "Unknown option: $1 (try --help)" >&2; exit 3 ;;
    esac
    shift
done

die() { echo "ERROR: $*" >&2; exit 1; }

echo "Agent tunnel route installer"
echo "============================"
echo ""

# --- Locate the install ------------------------------------------------------
# Normally the script sits in the install directory, same as setup.sh. But it is
# small enough to be curl'd on its own, so fall back to the working directory and
# then to the documented /opt location before giving up.
if [ -z "$CONFIG" ]; then
    for dir in "$PROJECT_DIR" "$PWD" /opt/traefik /opt/networkoptimizer-proxy; do
        if [ -f "$dir/dynamic/config.yml" ]; then
            INSTALL_DIR="$dir"
            CONFIG="$dir/dynamic/config.yml"
            break
        fi
    done
    [ -n "$CONFIG" ] || die "could not find dynamic/config.yml.
  Looked in: $PROJECT_DIR, $PWD, /opt/traefik, /opt/networkoptimizer-proxy
  Run this from your install directory, or pass --config /path/to/config.yml"
    [ "$INSTALL_DIR" = "$PROJECT_DIR" ] || echo "Using install at: $INSTALL_DIR"
else
    [ -f "$CONFIG" ] || die "$CONFIG not found."
    INSTALL_DIR="$(cd "$(dirname "$CONFIG")/.." && pwd)"
fi
COMPOSE="$INSTALL_DIR/docker-compose.yml"

# --- Inspect the existing config -------------------------------------------
# One awk pass reports what we need as KEY=VALUE lines. Everything is derived
# from the file itself; nothing is assumed about names or ordering.
FACTS="$(awk -v app_port=":$APP_PORT" -v grpc_path="$GRPC_PATH" '
    # Section tracking: a two-space key under http: (routers:, services:, ...)
    /^  [A-Za-z_-]+:[[:space:]]*$/ {
        section = $0; sub(/^  /, "", section); sub(/:.*$/, "", section)
        next
    }
    # An entry key one level below the section, e.g. "    optimizer:"
    /^    [A-Za-z0-9_.-]+:[[:space:]]*$/ {
        entry = $0; sub(/^    /, "", entry); sub(/:.*$/, "", entry)
        if (section == "routers")     { routers[entry] = 1 }
        if (section == "services")    { services[entry] = 1 }
        if (section == "middlewares") { middlewares[entry] = 1 }
        next
    }
    # Backend URL for the app: remember which service owns it.
    section == "services" && index($0, "url:") && index($0, app_port) {
        app_service = entry
    }
    # Router bookkeeping: which service it points at, and its Host rule.
    section == "routers" && $1 == "service:" { router_service[entry] = $2 }
    section == "routers" && $1 == "rule:"    { router_rule[entry] = $0 }

    index($0, grpc_path) { has_tunnel = 1 }
    /^  serversTransports:[[:space:]]*$/ { has_transports = 1 }

    END {
        print "app_service=" app_service
        print "has_tunnel=" (has_tunnel ? 1 : 0)
        print "has_transports=" (has_transports ? 1 : 0)
        print "has_sec_headers=" (("security-headers" in middlewares) ? 1 : 0)
        print "router_taken=" (("agents" in routers) ? 1 : 0)
        print "service_taken=" (("agents" in services) ? 1 : 0)
        # The router that serves the app carries the hostname we need.
        for (r in router_service) {
            s = router_service[r]
            gsub(/"/, "", s)
            if (s == app_service) { print "app_router=" r; print "app_rule=" router_rule[r]; break }
        }
    }
' "$CONFIG")"

eval "$(printf '%s\n' "$FACTS" | grep -E '^(app_service|has_tunnel|has_transports|has_sec_headers|router_taken|service_taken|app_router)=')"
APP_RULE="$(printf '%s\n' "$FACTS" | sed -n 's/^app_rule=//p')"

if [ "${has_tunnel:-0}" = "1" ]; then
    echo "The agent tunnel route is already present - nothing to do."
    exit 0
fi

[ -n "${app_service:-}" ] || die "no service found with a backend on port $APP_PORT.
  This script identifies Network Optimizer by its backend port. If your app runs
  on a different port, pass it with --app-port N."

[ -n "${app_router:-}" ] || die "found service '$app_service' on port $APP_PORT, but no router points at it."

# Pull the hostname out of the app router's Host(`...`) rule.
APP_HOST="$(printf '%s\n' "$APP_RULE" | grep -o 'Host(`[^`]*`)' | head -1 | sed -e 's/^Host(`//' -e 's/`)$//')"
[ -n "$APP_HOST" ] || die "router '$app_router' has no Host(\`...\`) rule to borrow a hostname from:
  $APP_RULE"

echo "Found Network Optimizer:"
echo "  service:  $app_service  (backend port $APP_PORT)"
echo "  router:   $app_router"
echo "  hostname: $APP_HOST"
echo ""

# Avoid clobbering anything already called "agents".
ROUTER_NAME="agents"
SERVICE_NAME="agents"
[ "${router_taken:-0}" = "1" ]  && ROUTER_NAME="agent-tunnel"
[ "${service_taken:-0}" = "1" ] && SERVICE_NAME="agent-tunnel"
if [ "$ROUTER_NAME" != "agents" ] || [ "$SERVICE_NAME" != "agents" ]; then
    echo "NOTE: 'agents' is already used in this config; using '$ROUTER_NAME'/'$SERVICE_NAME' instead."
    echo ""
fi

# The shipped example gives this router security-headers. Only reference it if
# this config actually defines it - a missing middleware breaks the whole router.
MW_BLOCK=""
if [ "${has_sec_headers:-0}" = "1" ]; then
    MW_BLOCK="      middlewares:
        - security-headers"
fi

# --- Build the insertions ---------------------------------------------------
ROUTER_BLOCK="
    # Site Agents (multi-site) - added by add-agent-tunnel.sh
    # Long-lived gRPC tunnel for on-site agents. Shares the app's hostname, split
    # off by the gRPC service path, and points at the app's HTTP/2 listener on
    # port $TUNNEL_PORT. That listener serves TLS with an ephemeral self-signed cert, so
    # the backend is https:// with verification skipped (see serversTransports).
    # Harmless with no agents: the app only opens the $TUNNEL_PORT listener when multi-site
    # is enabled (and after a restart), and nothing hits this path until an agent
    # enrolls. Priority must beat the host-only app router so the path wins.
    $ROUTER_NAME:
      rule: \"Host(\`$APP_HOST\`) && PathPrefix(\`$GRPC_PATH\`)\"
      priority: 100
      entryPoints:
        - websecure
      service: $SERVICE_NAME
      tls:
        certResolver: letsencrypt
$MW_BLOCK"

SERVICE_BLOCK="
    # Site agent tunnel - gRPC over HTTP/2 to the app's $TUNNEL_PORT listener.
    $SERVICE_NAME:
      loadBalancer:
        servers:
          - url: \"https://127.0.0.1:$TUNNEL_PORT\"
        serversTransport: agent-tunnel-insecure"

# serversTransports is a sibling of routers/services under http:. Only add the
# whole section if the config doesn't already have one.
if [ "${has_transports:-0}" = "1" ]; then
    TRANSPORT_BLOCK="
    # Added by add-agent-tunnel.sh
    agent-tunnel-insecure:
      insecureSkipVerify: true"
else
    TRANSPORT_BLOCK="
  # --- ServersTransports ------------------------------------------------------
  # The agent tunnel's cert is a throwaway self-signed cert regenerated on every
  # app start, so it cannot be pinned. Encryption on the proxy-to-app hop is the
  # goal here, not backend authentication.
  serversTransports:
    agent-tunnel-insecure:
      insecureSkipVerify: true"
fi

# --- Splice them in ---------------------------------------------------------
# Insert after the last real entry line of each section. Flushing at the next
# section header instead would drop the block below that section's comment
# banner - valid YAML, but it reads like it belongs to the wrong section.
TMP="$(mktemp)"
trap 'rm -f "$TMP"' EXIT

ENDS="$(awk '
    /^  [A-Za-z_-]+:[[:space:]]*$/ {
        section = $0; sub(/^  /, "", section); sub(/:.*$/, "", section); next
    }
    /^[A-Za-z]/ { section = "" }
    # Any non-blank line indented under the section is section content - including
    # the 6-space body lines of an entry. Matching only 4-space key lines would put
    # the insertion point at the LAST ENTRY NAME, splicing the new block into that
    # entry and stealing its body.
    section != "" && /^    / && $0 !~ /^[[:space:]]*$/ { last[section] = NR }
    END {
        print "routers_end="    (("routers" in last)           ? last["routers"]           : 0)
        print "services_end="   (("services" in last)          ? last["services"]          : 0)
        print "transports_end=" (("serversTransports" in last) ? last["serversTransports"] : 0)
    }
' "$CONFIG")"
eval "$ENDS"

[ "${routers_end:-0}"  -gt 0 ] || die "could not locate the end of the 'routers:' section in $CONFIG"
[ "${services_end:-0}" -gt 0 ] || die "could not locate the end of the 'services:' section in $CONFIG"

awk -v router_block="$ROUTER_BLOCK" -v service_block="$SERVICE_BLOCK"     -v transport_block="$TRANSPORT_BLOCK"     -v r_end="$routers_end" -v s_end="$services_end" -v t_end="${transports_end:-0}" '
    { print }
    NR == r_end { print router_block }
    NR == s_end { print service_block }
    t_end > 0 && NR == t_end { print transport_block }
    END { if (t_end == 0) print transport_block }
' "$CONFIG" > "$TMP"

if [ "$DRY_RUN" = "1" ]; then
    echo "Changes (dry run - nothing written):"
    echo ""
    diff -u --label "dynamic/config.yml" --label "dynamic/config.yml (with tunnel)" \
        "$CONFIG" "$TMP" || true
    exit 0
fi

# Validate before installing: a broken dynamic config is a live outage.
if command -v python3 >/dev/null 2>&1; then PY=python3
elif command -v python >/dev/null 2>&1; then PY=python
else PY=""; fi
if [ -n "$PY" ] && "$PY" -c 'import yaml' >/dev/null 2>&1; then
    # Parsing is not enough: a block spliced into the wrong place still parses,
    # it just quietly steals another route's settings. Check the result means
    # what we intended, and that nothing else moved.
    # The gRPC path is handed over WITHOUT its slashes and rebuilt inside Python.
    # MSYS/Git Bash rewrites anything that looks like a Unix path - in argv and in
    # the environment - into a Windows path, which would corrupt the comparison.
    GRPC_TOKEN="$(printf '%s' "$GRPC_PATH" | tr -d '/')"
    "$PY" - "$TMP" "$CONFIG" "$ROUTER_NAME" "$SERVICE_NAME" "$TUNNEL_PORT" "$GRPC_TOKEN" <<'PYEOF' \
        || die "the generated config failed validation - nothing was written."
import sys, yaml
new_f, old_f, rname, sname, tport, gtoken = sys.argv[1:7]
gpath = "/" + gtoken + "/"
new = yaml.safe_load(open(new_f, encoding="utf-8"))
old = yaml.safe_load(open(old_f, encoding="utf-8"))
nh, oh = new["http"], old["http"]

r = nh["routers"].get(rname)
assert r, "router %s missing" % rname
assert r.get("service") == sname, "router %s points at %r, expected %r" % (rname, r.get("service"), sname)
assert gpath in r.get("rule", ""), "router %s has the wrong rule: %r" % (rname, r.get("rule"))
assert r.get("priority") == 100, "router %s lost its priority" % rname

s = nh["services"].get(sname)
assert s, "service %s missing" % sname
url = s["loadBalancer"]["servers"][0]["url"]
assert url.endswith(":" + tport) and url.startswith("https://"), "service %s has url %r" % (sname, url)
assert s["loadBalancer"].get("serversTransport") == "agent-tunnel-insecure", "service %s lost its transport" % sname
assert nh["serversTransports"]["agent-tunnel-insecure"]["insecureSkipVerify"] is True

# Every pre-existing router and service must survive byte-identical.
for kind in ("routers", "services", "middlewares"):
    for name, body in (oh.get(kind) or {}).items():
        assert name in (nh.get(kind) or {}), "%s %s disappeared" % (kind, name)
        assert nh[kind][name] == body, "%s %s was modified: %r -> %r" % (kind, name, body, nh[kind][name])
added = set(nh["routers"]) - set(oh["routers"])
assert added == {rname}, "unexpected routers added: %r" % (added - {rname})
print("Validated: %d routers, %d services intact; %s added cleanly."
      % (len(oh["routers"]), len(oh["services"]), rname))
PYEOF
else
    echo "NOTE: python + pyyaml not available - skipping validation."
    echo "      Check 'docker compose logs traefik' after this runs."
fi

BACKUP="$CONFIG.bak-$(date +%Y%m%d-%H%M%S)"
cp "$CONFIG" "$BACKUP"
cat "$TMP" > "$CONFIG"

echo ""
echo "Added the agent tunnel route to dynamic/config.yml."
echo "  Backup: $BACKUP"
echo ""

# The route alone isn't enough: Traefik v3's default 60s readTimeout severs the
# tunnel. That setting lives in the static config, not here.
if [ -f "$COMPOSE" ] && ! grep -q 'readtimeout=0' "$COMPOSE"; then
    echo "ACTION NEEDED: docker-compose.yml is missing the readTimeout override."
    echo "  Without it Traefik cuts the tunnel at exactly 60 seconds."
    echo "  Run 'git pull' to get it, then 'docker compose up -d'."
else
    echo "readTimeout override present in docker-compose.yml."
    echo "Traefik watches dynamic/ and picks this up automatically - no restart needed."
fi
echo ""
echo "Roll back with:  cp \"$BACKUP\" \"$CONFIG\""
