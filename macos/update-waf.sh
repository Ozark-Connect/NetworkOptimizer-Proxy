#!/bin/bash
# Installs or updates netopt-waf on macOS from a GitHub release, then restarts its LaunchDaemon.
#   bash macos/update-waf.sh            # latest release
#   bash macos/update-waf.sh v1.2.3     # a specific release
# Settings in /usr/local/etc/netopt-waf/ and state in /usr/local/var/netopt-waf/ are kept.
set -euo pipefail

REPO="Ozark-Connect/NetworkOptimizer-Proxy"
BIN="/usr/local/bin/netopt-waf"
LABEL="net.ozarkconnect.netopt-waf"

case "$(uname -m)" in
    arm64) arch=arm64 ;;
    x86_64) arch=amd64 ;;
    *) echo "Unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac
asset="netopt-waf-darwin-$arch"

if [ $# -gt 0 ]; then
    base="https://github.com/$REPO/releases/download/$1"
else
    base="https://github.com/$REPO/releases/latest/download"
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
curl -fsSL -o "$tmp/$asset" "$base/$asset"
curl -fsSL -o "$tmp/SHA256SUMS" "$base/SHA256SUMS"
(cd "$tmp" && grep " $asset\$" SHA256SUMS | shasum -a 256 -c -)
chmod +x "$tmp/$asset"

old="$([ -x "$BIN" ] && "$BIN" -version 2>/dev/null || echo none)"
sudo install -m 755 "$tmp/$asset" "$BIN"
echo "Installed: $("$BIN" -version) (was: $old)"

if sudo launchctl print "system/$LABEL" >/dev/null 2>&1; then
    sudo launchctl kickstart -k "system/$LABEL"
    echo "Restarted $LABEL"
else
    echo "$LABEL is not loaded; see the README to install the LaunchDaemon."
fi
