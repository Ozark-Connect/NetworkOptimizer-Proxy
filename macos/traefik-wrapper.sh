#!/bin/bash
# Wrapper script for Traefik - sources secrets before exec
# Location on target: /usr/local/etc/traefik/traefik-wrapper.sh
#
# Secrets file (/usr/local/etc/traefik/secrets.env) is box-only,
# not tracked in version control.

SECRETS_FILE="/usr/local/etc/traefik/secrets.env"

if [ -f "$SECRETS_FILE" ]; then
    set -a
    source "$SECRETS_FILE"
    set +a
else
    echo "WARNING: $SECRETS_FILE not found - ACME DNS challenge will fail" >&2
fi

exec /usr/local/bin/traefik --configfile=/usr/local/etc/traefik/traefik.yml
