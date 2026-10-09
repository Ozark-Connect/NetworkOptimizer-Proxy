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
| `ACME_PROPAGATION_DELAY` | No | `20` | Seconds to wait after creating the ACME TXT record before asking Let's Encrypt to validate. Raise it (e.g. `120`) if renewals intermittently fail with `Incorrect TXT record` / `No TXT record found` and then succeed on the next daily attempt. |
| `FORWARDED_TRUSTED_IPS` | No | none | Comma-separated IPs/CIDRs of upstream proxies whose `X-Forwarded-*` headers Traefik keeps on the HTTPS entrypoint. Leave unset unless another proxy sits in front of Traefik. See [Behind Cloudflare or another proxy](#behind-cloudflare-or-another-proxy-optional). |
| `LOG_LEVEL` | No | `INFO` | Log verbosity: DEBUG, INFO, WARN, ERROR |
| `COMPOSE_PROFILES` | No | none | `waf` runs the bundled web application firewall. See [Web Application Firewall](#web-application-firewall-optional). |
| `WAF_MODE` | No | `detect` | `detect` logs attacks and lets them through; `block` answers 403. |
| `WAF_PARANOIA` | No | `1` | OWASP CRS paranoia level, 1-4. Higher catches more and flags more legitimate traffic. |
| `WAF_API_TOKEN` | No | none | Shared secret Network Optimizer uses to read WAF events. |
| `WAF_LISTEN` | No | `127.0.0.1:8044` | WAF listen address. Change only if Network Optimizer runs on another host. |

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

By default, DNS propagation checking is disabled (`propagation.disablechecks=true`) and replaced with a fixed 20-second delay. This avoids certificate failures caused by local DNS resolvers (Pi-hole, NextDNS, AdGuard Home, etc.) that may not see the Cloudflare TXT records during validation. Cloudflare's API is usually fast enough that 20 seconds is plenty. If Let's Encrypt itself intermittently reports `Incorrect TXT record` or `No TXT record found` (the previous challenge value is still what Cloudflare's authoritative servers answer with), set `ACME_PROPAGATION_DELAY` in `.env` to a larger value such as `120`.

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

This route **ships enabled** because it's a no-op without agents: the app binds the `8043` listener at startup, and nothing hits the gRPC path until an agent enrolls. To actually use it, turn on multi-site management in Network Optimizer. No app restart is needed (Network Optimizer v2.7.2 and later), and the `agents` router reuses your existing app hostname, so no new DNS record and no config edit are needed either.

### Existing installs

`setup.sh` only copies `config.example.yml` on first run, so installs predating this route don't have it:

```bash
curl -fsSL https://raw.githubusercontent.com/Ozark-Connect/NetworkOptimizer-Proxy/main/add-agent-tunnel.sh | bash
```

No git checkout needed. Run it from your install directory, or from anywhere if that's `/opt/traefik`. It backs up `config.yml` first; append `-s -- --dry-run` to preview instead of writing.

Notes:

- The `websecure` entrypoint ships with `readTimeout: 0`, which is required so the long-lived tunnel isn't severed at Traefik v3's default 60-second read deadline.
- The `insecureSkipVerify` on the `agent-tunnel-insecure` serversTransport is expected: the tunnel listener's cert is a throwaway self-signed cert regenerated on every app start, so it can't be pinned. Confidentiality on the hop is the goal, not backend authentication.
- A **502** on the gRPC path means Traefik cannot reach the app's `8043` listener. Check that the app is running and that nothing blocks the port between Traefik and the app. If the app log says `Agent tunnel not bound`, the app's `ASPNETCORE_URLS` has an HTTPS or non-port binding, and the listener cannot start alongside it.

Traffic flows: agent → Traefik (HTTPS/HTTP2) → app:8043 (self-signed TLS, HTTP/2 gRPC).

## Behind Cloudflare or Another Proxy (Optional)

By default Traefik trusts no upstream proxy. It drops any incoming `X-Forwarded-For` / `X-Forwarded-Host` and sets them from the connection itself. That is correct when clients connect to Traefik directly.

When Traefik sits behind another proxy, such as Cloudflare's orange-cloud proxy, the connecting address is that proxy, not the client. List the proxy's addresses in `.env` so Traefik keeps the forwarded headers it adds:

```bash
# Cloudflare's published ranges: https://www.cloudflare.com/ips/
FORWARDED_TRUSTED_IPS=173.245.48.0/20,103.21.244.0/22,...
```

Then recreate the container (`docker compose up -d`). This is static config, so it does not hot-reload.

Notes:

- **Anyone who can connect from a listed address chooses the client IP your app sees.** For Cloudflare that is any Cloudflare customer, so also limit the origin to your own zone, e.g. with [per-hostname Authenticated Origin Pulls](https://developers.cloudflare.com/ssl/origin-configuration/authenticated-origin-pull/). Firewalling to Cloudflare's ranges alone does not do this.
- Cloudflare's ranges change occasionally. Re-check the list when you update.
- Network Optimizer applies its own trust setting on top: set `TRUSTED_PROXIES` and `TRUSTED_PROXY_HOPS` on the app (see its [`docker/.env.example`](https://github.com/Ozark-Connect/NetworkOptimizer/blob/main/docker/.env.example)) so it reads the client address through both hops.
- Applies to the HTTPS entrypoint only. The HTTP entrypoint just redirects.
- Docker only. The Windows and macOS static templates do not read this variable.

## Web Application Firewall (Optional)

`netopt-waf` is a web application firewall built on [Coraza](https://coraza.io) and the [OWASP Core Rule Set](https://coreruleset.org) (CRS). Traefik asks it about each request on the routes you choose, through a `forwardAuth` middleware. It inspects the method, URI, headers, and body, and answers allow or block. Requests that cross the CRS anomaly threshold are kept for [Network Optimizer](https://github.com/Ozark-Connect/NetworkOptimizer), which shows them on Threat Intelligence next to the gateway's IPS events.

It complements UniFi CyberSecure rather than replacing it: the gateway's IPS sees packets, and only the proxy that terminates TLS sees the decrypted request.

1. In `.env`, set `COMPOSE_PROFILES=waf` and a `WAF_API_TOKEN` (`openssl rand -hex 32`).
2. Run `bash setup.sh` once to create `waf-rules/before-crs.conf` and `waf-rules/after-crs.conf`, then `docker compose up -d`. The first start builds the image.
3. Make sure `dynamic/config.yml` defines the `waf` middleware (copy it from `config.example.yml` on installs that predate it), then add `- waf` to a router's `middlewares`.
4. In Network Optimizer, Settings - Security & Alerts - Web Application Firewall: URL `http://127.0.0.1:8044` (same host) and the token.

It starts in `detect` mode: attacks are logged and let through. Run it that way for a while, add exclusions for anything legitimate it flags, and then set `WAF_MODE=block` and `docker compose up -d netopt-waf`.

Exclusions go in `waf-rules/`: runtime exclusions (`ctl:ruleRemoveById`, scoped to a host or path) in `before-crs.conf`, and rule removals (`SecRuleRemoveById`, `SecRuleUpdateTargetById`) in `after-crs.conf`. Restart `netopt-waf` after editing. Each event lists the CRS rule IDs that fired, so the ID to exclude is in Network Optimizer's event detail.

Notes:

- **It fails closed.** While `netopt-waf` is down, every router that lists the `waf` middleware answers 500. Add it to the routes you want protected, not to everything.
- **Never add it to the `speedtest` or `agents` routers.** Traefik buffers a request body before asking the WAF, which breaks speed tests and long-lived streams.
- Request bodies larger than the middleware's `maxBodySize` (10 MB in the example) are refused on routes that use it. Raise it for upload-heavy apps.
- The client IP comes from the `X-Forwarded-For` header Traefik builds, so set `FORWARDED_TRUSTED_IPS` when Traefik sits behind Cloudflare (see above), or every event shows Cloudflare's address.
- `/api/events` needs `WAF_API_TOKEN`. Without it the WAF still filters, but Network Optimizer cannot read its events.
- Response bodies are never inspected: `forwardAuth` sees only the request.
- **Windows (MSI):** the Traefik feature ships `netopt-waf.exe`. Set the registry value `TRAEFIK_WAF_MODE` (string, `detect` or `block`) under `HKLM\SOFTWARE\Ozark Connect\Network Optimizer` and restart the Network Optimizer service. The service starts the WAF, puts it on the app's router, and connects Threat Intelligence to it. Exclusions go in `Traefik\waf-rules\` in the install folder.
- **macOS (native):** build the binary (`cd waf && go build -o /usr/local/bin/netopt-waf .`), copy `macos/netopt-waf-wrapper.sh` and a `waf.env` to `/usr/local/etc/netopt-waf/`, load `macos/net.ozarkconnect.netopt-waf.plist` with `launchctl`, and uncomment `- waf` on the optimizer router.

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

**Certificates not issuing**: Check that your Cloudflare API token is a **User API Token** (created under My Profile > API Tokens, `cfut_` prefix) with `Zone:Read` and `DNS:Edit` permissions. Account API Tokens (`cfat_` prefix) will not work. Verify the domain's DNS is managed by Cloudflare and check logs with `docker compose logs`. If you see NXDOMAIN or propagation timeout errors, your local DNS resolver may be interfering - the default config already handles this, but you can increase the delay by setting `ACME_PROPAGATION_DELAY` in `.env` if needed.

**Speed test still using HTTP/2**: Verify the speed test router references `options: h1only` in its TLS config. Check with: `curl -v https://speedtest.yourdomain.com 2>&1 | grep ALPN`.

**Port conflict**: If another service (e.g., Caddy) is already using port 443, set `LISTEN_IP` in `.env` to bind Traefik to a specific IP address.

**500 on every request to a route**: The route lists the `waf` middleware and `netopt-waf` is not running. Check with `docker compose ps netopt-waf` and `docker compose logs netopt-waf`.

**WAF blocking a legitimate request**: Find its rule IDs in Network Optimizer's Threat Intelligence or in `docker compose logs netopt-waf`, and add an exclusion in `waf-rules/` (see Web Application Firewall above).

## License

MIT
