#!/usr/bin/env bash
set -euo pipefail

# NetworkOptimizer-Proxy first-time setup
# Creates config files from examples and sets correct permissions

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "NetworkOptimizer-Proxy Setup"
echo "============================"
echo ""

# Create .env from example if it doesn't exist
if [ ! -f "$PROJECT_DIR/.env" ]; then
    cp "$PROJECT_DIR/.env.example" "$PROJECT_DIR/.env"
    echo "Created .env from template - edit it with your values:"
    echo "  nano $PROJECT_DIR/.env"
else
    echo ".env already exists, skipping"
fi

# Create dynamic config from example if it doesn't exist
if [ ! -f "$PROJECT_DIR/dynamic/config.yml" ]; then
    cp "$PROJECT_DIR/dynamic/config.example.yml" "$PROJECT_DIR/dynamic/config.yml"
    echo "Created dynamic/config.yml from template - edit hostnames:"
    echo "  nano $PROJECT_DIR/dynamic/config.yml"
else
    echo "dynamic/config.yml already exists, skipping"
fi

# Create secrets config from example if it doesn't exist
if [ ! -f "$PROJECT_DIR/dynamic/secrets.yml" ]; then
    cp "$PROJECT_DIR/dynamic/secrets.example.yml" "$PROJECT_DIR/dynamic/secrets.yml"
    echo "Created dynamic/secrets.yml from template (optional)"
else
    echo "dynamic/secrets.yml already exists, skipping"
fi

# Create acme directory and acme.json with correct permissions
mkdir -p "$PROJECT_DIR/acme"
if [ ! -f "$PROJECT_DIR/acme/acme.json" ]; then
    touch "$PROJECT_DIR/acme/acme.json"
    chmod 600 "$PROJECT_DIR/acme/acme.json"
    echo "Created acme/acme.json with 600 permissions"
else
    # Ensure correct permissions even if file exists
    chmod 600 "$PROJECT_DIR/acme/acme.json"
    echo "acme/acme.json already exists, verified permissions"
fi

echo ""
echo "Setup complete. Next steps:"
echo "  1. Edit .env with your Cloudflare token and email"
echo "  2. Edit dynamic/config.yml with your hostnames"
echo "  3. Run: docker compose up -d"
