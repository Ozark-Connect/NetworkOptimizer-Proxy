# NetworkOptimizer-Proxy

A Traefik reverse proxy setup designed for [Network Optimizer](https://github.com/Ozark-Connect/NetworkOptimizer) that solves the HTTP/1.1 speed test problem with a single proxy instance.

## The Problem

OpenSpeedTest requires HTTP/1.1 for accurate throughput measurements - HTTP/2 multiplexing and flow control interfere with speed test results. Most reverse proxies (including Caddy) negotiate HTTP/2 at the TLS level and can't serve different protocols per hostname on the same port.

## The Solution

Traefik supports per-router TLS options, including ALPN protocol selection. This setup uses a custom TLS option (`h1only`) that only advertises `http/1.1` during the TLS handshake for the speed test hostname, while the main app uses the default HTTP/2 negotiation. One proxy, one IP, one port 443.

## Quick Start (Docker)

```bash
git clone https://github.com/Ozark-Connect/NetworkOptimizer-Proxy.git
cd NetworkOptimizer-Proxy

# Run setup script (creates config files from examples, sets permissions)
bash setup.sh

# Edit your configuration
nano .env                    # Cloudflare token, email, listen IP
nano dynamic/config.yml      # Update hostnames

# Start
docker compose up -d
```

## Windows (MSI)

Traefik is included as an optional feature in the [Network Optimizer MSI installer](https://github.com/Ozark-Connect/NetworkOptimizer/releases). When selected, the installer prompts for Cloudflare DNS settings and the service manages Traefik as a child process alongside nginx.

The `windows/` directory contains the config templates used by the MSI build:
- `traefik.yml.template` - Static config with placeholders for registry values
- `config.yml.template` - Dynamic config with placeholders for hostnames/ports

## Requirements

- **For Linux**: Docker and Docker Compose
- **For Windows**: Network Optimizer MSI installer (Traefik feature)
- A domain with DNS managed by Cloudflare (for automatic Let's Encrypt certificates)
- DNS A records pointing to the host running Traefik:
  - e.g. `optimizer.yourdomain.com` - Network Optimizer web UI
  - e.g. `speedtest.yourdomain.com` - OpenSpeedTest (HTTP/1.1)
  - e.g. `speedtest-wan.yourdomain.com` - (optional) External WAN speed test server

## Configuration

### Environment Variables (`.env`)

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `ACME_EMAIL` | Yes | - | Email for Let's Encrypt registration |
| `CF_DNS_API_TOKEN` | Yes | - | Cloudflare **User API Token** (created under [My Profile > API Tokens](https://dash.cloudflare.com/profile/api-tokens)) with `Zone:Read` and `DNS:Edit` permissions. Account API Tokens (`cfat_` prefix) are not compatible — you need a User API Token (`cfut_` prefix). |
| `LISTEN_IP` | No | `0.0.0.0` | Bind to a specific IP address |
| `DNS_RESOLVERS` | No | `1.1.1.1:53,1.0.0.1:53` | DNS servers for ACME DNS-01 validation. Override on hosts where the default resolvers are unreachable (e.g., `127.0.0.1:53` on a Pi-hole host that can't DNAT its own traffic to external DNS). |
| `LOG_LEVEL` | No | `INFO` | Log verbosity: DEBUG, INFO, WARN, ERROR |

### Dynamic Config (`dynamic/config.yml`)

Copy from the example and update hostnames:

```bash
cp config.example.yml dynamic/config.yml
```

The example config includes routers for:

- **optimizer** - Network Optimizer on HTTP/2 (default TLS)
- **speedtest** - OpenSpeedTest on HTTP/1.1 (`h1only` TLS option)
- **speedtest-wan** - (optional, commented out) External WAN speed test server on HTTP/1.1

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

In addition to HTTP/1.1, the speed test route strips the `Accept-Encoding` header to prevent transparent compression from skewing results.

### Automatic HTTPS

Traefik uses Let's Encrypt with Cloudflare DNS-01 challenges, so:
- No port 80 exposure required for certificate validation
- Wildcard certificates are supported
- Certificates auto-renew before expiry

By default, DNS propagation checking is disabled (`propagation.disablechecks=true`) and replaced with a fixed 20-second delay. This avoids certificate failures caused by local DNS resolvers (Pi-hole, NextDNS, AdGuard Home, etc.) that may not see the Cloudflare TXT records during validation. Cloudflare's API is fast enough that 20 seconds is plenty.

## WAN Speed Test Server (Optional)

If you deploy an external OpenSpeedTest server to a VPS for [Client WAN Speed Testing](https://github.com/Ozark-Connect/NetworkOptimizer/blob/main/docker/DEPLOYMENT.md#external-wan-speed-test-server-optional), you can proxy it through this same Traefik instance. This gives you HTTPS (required for browser Private Network Access) and HTTP/1.1 (required for accurate results) without installing anything extra on the VPS.

1. Deploy the speed test container on your VPS (see the Network Optimizer deployment guide)
2. Add a DNS A record for `speedtest-wan.yourdomain.com` pointing to **the host running Traefik** (not the VPS)
3. Uncomment the `speedtest-wan` router and service in `dynamic/config.yml`
4. Update the service URL to point to your VPS: `http://your-vps-hostname-or-ip:3005`
5. In Network Optimizer Settings, configure the External Speed Test Server with `https` scheme and the `speedtest-wan.yourdomain.com` hostname

Traffic flows: browser → Traefik (HTTPS/HTTP1.1) → VPS:3005 (HTTP). Traefik handles TLS termination and HTTP/1.1 enforcement. The VPS only needs port 3005 open and Docker.

## Multi-Site (On-Site Agents) (Optional)

If you enable Network Optimizer's [multi-site management](https://github.com/Ozark-Connect/NetworkOptimizer), each remote site runs an on-site agent that dials home over a long-lived gRPC tunnel to this instance. The tunnel uses the **same hostname as the app**, split off by the gRPC service path (`/networkoptimizer.agent.v1.AgentTunnel/`), and connects to the app's HTTP/2 listener on port **8043**. That listener serves TLS with an ephemeral self-signed cert, so the backend is `https://` with verification skipped - this keeps the proxy-to-app hop encrypted even when Traefik runs on a separate box from the app.

This route **ships enabled** because it's a no-op without agents: the app only opens the `8043` listener **when multi-site is enabled** (and after a restart), and nothing hits the gRPC path until an agent enrolls, so the backend is never dialed. To actually use it:

1. In Network Optimizer, turn on multi-site management and **restart the app** (this binds the `8043` listener).
2. That's it - the `agents` router reuses your existing app hostname, so no new DNS record and no config edit are needed.

### Existing installs

`setup.sh` only copies `config.example.yml` on first run, so installs predating this route don't have it:

```bash
curl -fsSL https://raw.githubusercontent.com/Ozark-Connect/NetworkOptimizer-Proxy/main/add-agent-tunnel.sh | bash
```

No git checkout needed. Run it from your install directory, or from anywhere if that's `/opt/traefik`. It backs up `config.yml` first; append `-s -- --dry-run` to preview instead of writing.

Notes:

- The `websecure` entrypoint ships with `readTimeout: 0`, which is required so the long-lived tunnel isn't severed at Traefik v3's default 60-second read deadline.
- The `insecureSkipVerify` on the `agent-tunnel-insecure` serversTransport is expected: the tunnel listener's cert is a throwaway self-signed cert regenerated on every app start, so it can't be pinned. Confidentiality on the hop is the goal, not backend authentication.
- If you enable multi-site but haven't restarted the app yet, an agent hitting the path gets a **502** until the `8043` listener binds. Without any agents, the path is simply never requested.

Traffic flows: agent → Traefik (HTTPS/HTTP2) → app:8043 (self-signed TLS, HTTP/2 gRPC).

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
    |-- speedtest.example.com (HTTP/1.1, h1only TLS) -->  localhost:3005
    |
    |-- speedtest-wan.example.com (HTTP/1.1, h1only) -->  your-vps:3005  (optional)
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

**Certificates not issuing**: Check that your Cloudflare API token is a **User API Token** (created under My Profile > API Tokens, `cfut_` prefix) with `Zone:Read` and `DNS:Edit` permissions. Account API Tokens (`cfat_` prefix) will not work. Verify the domain's DNS is managed by Cloudflare and check logs with `docker compose logs`. If you see NXDOMAIN or propagation timeout errors, your local DNS resolver may be interfering - the default config already handles this, but you can increase `propagation.delaybeforechecks` in `docker-compose.yml` if needed.

**Speed test still using HTTP/2**: Verify the speed test router references `options: h1only` in its TLS config. Check with: `curl -v https://speedtest.yourdomain.com 2>&1 | grep ALPN`.

**Port conflict**: If another service (e.g., Caddy) is already using port 443, set `LISTEN_IP` in `.env` to bind Traefik to a specific IP address.

## License

MIT
