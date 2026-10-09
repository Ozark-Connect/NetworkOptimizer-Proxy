#!/bin/bash
# Wrapper script for netopt-waf - sources its settings before exec
# Location on target: /usr/local/etc/netopt-waf/netopt-waf-wrapper.sh
#
# Settings file (/usr/local/etc/netopt-waf/waf.env) is box-only, not tracked:
#   WAF_MODE=detect            # detect or block
#   WAF_PARANOIA=1             # OWASP CRS paranoia level 1-4
#   WAF_API_TOKEN=<openssl rand -hex 32>
#
# Build the binary once from this repo: (cd waf && go build -o /usr/local/bin/netopt-waf .)
# Optional exclusions: before-crs.conf / after-crs.conf in /usr/local/etc/netopt-waf/
# (copy them from waf-rules/*.example).

SETTINGS_FILE="/usr/local/etc/netopt-waf/waf.env"

if [ -f "$SETTINGS_FILE" ]; then
    set -a
    source "$SETTINGS_FILE"
    set +a
else
    echo "WARNING: $SETTINGS_FILE not found - running in detect mode with the events API disabled" >&2
fi

export WAF_LISTEN="${WAF_LISTEN:-127.0.0.1:8044}"
export WAF_RULES_DIR="/usr/local/etc/netopt-waf"

exec /usr/local/bin/netopt-waf
