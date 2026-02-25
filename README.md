# NetworkOptimizer-Proxy

A Traefik reverse proxy setup designed for [Network Optimizer](https://github.com/Ozark-Connect/NetworkOptimizer) that solves the HTTP/1.1 speed test problem with a single proxy instance.

## The Problem

OpenSpeedTest requires HTTP/1.1 for accurate throughput measurements - HTTP/2 multiplexing and flow control interfere with speed test results. Most reverse proxies (including Caddy) negotiate HTTP/2 at the TLS level and can't serve different protocols per hostname on the same port.

## The Solution

Traefik supports per-router TLS options, including ALPN protocol selection. This setup uses a custom TLS option (`h1only`) that only advertises `http/1.1` during the TLS handshake for the speed test hostname, while the main app uses the default HTTP/2 negotiation. One proxy, one IP, one port 443.

## Quick Start

```bash
git clone git@github.com:Ozark-Connect/NetworkOptimizer-Proxy.git
cd NetworkOptimizer-Proxy

# Run setup script (creates config files from examples, sets permissions)
bash setup.sh

# Edit your configuration
nano .env                    # Cloudflare token, email, listen IP
nano dynamic/config.yml      # Update hostnames

# Start
docker compose up -d
```

## Requirements

- Docker and Docker Compose
- A domain with DNS managed by Cloudflare (for automatic Let's Encrypt certificates)
- Two DNS A records pointing to the host running Traefik:
  - `optimizer.yourdomain.com` - Network Optimizer web UI
  - `speedtest.yourdomain.com` - OpenSpeedTest (HTTP/1.1)

## Configuration

### Environment Variables (`.env`)

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `ACME_EMAIL` | Yes | - | Email for Let's Encrypt registration |
| `CF_DNS_API_TOKEN` | Yes | - | Cloudflare API token with Zone:DNS:Edit permissions |
| `LISTEN_IP` | No | `0.0.0.0` | Bind to a specific IP address |
| `LOG_LEVEL` | No | `INFO` | Log verbosity: DEBUG, INFO, WARN, ERROR |

### Dynamic Config (`dynamic/config.yml`)

Copy from the example and update hostnames:

```bash
cp config.example.yml dynamic/config.yml
```

The example config includes two routers:

- **optimizer** - Network Optimizer on HTTP/2 (default TLS)
- **speedtest** - OpenSpeedTest on HTTP/1.1 (`h1only` TLS option)

Edit the `Host()` rules to match your DNS:

```yaml
optimizer:
  rule: "Host(`optimizer.yourdomain.com`)"
  # ...

speedtest:
  rule: "Host(`speedtest.yourdomain.com`)"
  # ...
```

### Secrets (`dynamic/secrets.yml`)

Optional file for middleware that injects credentials (e.g., Basic Auth headers for backend services). Copy from example if needed:

```bash
cp secrets.example.yml dynamic/secrets.yml
```

This file is gitignored and managed directly on the host.

## How It Works

### HTTP/1.1 for Speed Tests

The `h1only` TLS option restricts ALPN negotiation to `http/1.1` only:

```yaml
tls:
  options:
    h1only:
      minVersion: VersionTLS12
      alpnProtocols:
        - "http/1.1"
```

When a browser connects to the speed test hostname, the TLS handshake negotiates HTTP/1.1 instead of HTTP/2. The speed test router references this option:

```yaml
speedtest:
  rule: "Host(`speedtest.yourdomain.com`)"
  tls:
    options: h1only  # Forces HTTP/1.1 on the client connection
```

### Speed Test Optimizations

In addition to HTTP/1.1, the speed test route:
- Strips the `Accept-Encoding` header to prevent transparent compression
- Allows 35MB request/response bodies for upload/download tests

### Automatic HTTPS

Traefik uses Let's Encrypt with Cloudflare DNS-01 challenges, so:
- No port 80 exposure required for certificate validation
- Wildcard certificates are supported
- Certificates auto-renew before expiry

## Adding More Services

To proxy additional services behind Traefik, add routers and services to `dynamic/config.yml`. Example:

```yaml
http:
  routers:
    my-service:
      rule: "Host(`myservice.yourdomain.com`)"
      entryPoints:
        - websecure
      service: my-service
      tls:
        certResolver: letsencrypt
      middlewares:
        - security-headers

  services:
    my-service:
      loadBalancer:
        servers:
          - url: "http://localhost:9090"
```

### IP Restrictions

Use the `ipAllowList` middleware to restrict access:

```yaml
http:
  middlewares:
    lan-only:
      ipAllowList:
        sourceRange:
          - "192.168.0.0/16"
          - "10.0.0.0/8"

  routers:
    my-service:
      middlewares:
        - security-headers
        - lan-only
```

## Architecture

```
Internet
    |
    v
[Traefik :443]
    |
    |-- optimizer.example.com (HTTP/2, default TLS)  -->  localhost:8042
    |
    |-- speedtest.example.com (HTTP/1.1, h1only TLS) -->  localhost:8043
    |
    |-- (other services...)
    |
[Traefik :80]
    |-- All HTTP --> 301 redirect to HTTPS
```

- **Single Traefik instance** handles all hostnames
- **Host networking** (`network_mode: host`) for direct access to local services
- **DNS-01 challenges** via Cloudflare (no HTTP-01, no port 80 exposure needed)
- **File provider** watches `dynamic/` for config changes (hot reload, no restart needed)

## Extracting Certificates

Traefik stores all Let's Encrypt certificates in `acme/acme.json`. To extract a certificate for use elsewhere (e.g., a UniFi gateway):

```bash
# Install traefik-certs-dumper (or use jq)
docker run --rm -v ./acme:/acme ldez/traefik-certs-dumper file \
  --source /acme/acme.json --dest /acme/certs \
  --domain-subdir
```

## Troubleshooting

**Certificates not issuing**: Check that your Cloudflare API token has Zone:DNS:Edit permissions and that the domain's DNS is managed by Cloudflare. Check logs with `docker compose logs`.

**Speed test still using HTTP/2**: Verify the speed test router references `options: h1only` in its TLS config. Check with: `curl -v https://speedtest.yourdomain.com 2>&1 | grep ALPN`.

**Port conflict**: If another service (e.g., Caddy) is already using port 443, set `LISTEN_IP` in `.env` to bind Traefik to a specific IP address.

## License

MIT
