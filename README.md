# frp-ip-filter

Restricts access to an [frp](https://github.com/fatedier/frp) tunnel to known clients. A client "unlocks" access by registering their current IP (or an IPv6 prefix, DynDNS-style) before frp will let their connections through. Registrations expire automatically after a configurable time.
Does not work for `udp` / only `tcp`, `stcp`, `https` and `tcpmux`.

## Getting started

```
go build .
./frp-ip-filter
```

Runs two HTTP listeners:
- a **public** one (default `:8080`) that clients use to register themselves — terminates TLS itself if `TLS_CERT_FILE`/`TLS_KEY_FILE` are set (see Configuration below); there's no reverse proxy in front of it, so set these unless you have one
- a **private** one (default `:9090`), meant to be reached only by your frps server, not the internet — always plain HTTP

## Registering access

**Register your own IP** (e.g. from a browser or `curl`):
```
GET http://your-host:8080/unlock?token=<your-token>
```
Requires a valid token (see Configuration below). Registers whichever IP the request actually came from — you can't register an IP other than your own.

**Register an IPv6 prefix** (for a whole network behind a delegated prefix, e.g. your home router's LAN):
```
GET http://your-host:8080/dyndns?prefix=<your-ipv6-prefix>
```
Requires HTTP Basic Auth (username/password, see Configuration below). Registering again under the same login replaces the previous prefix.

### FRITZ!Box DynDNS setup

Under *Internet → Permit Access → DynDNS*, choose a user-defined provider with:
```
Update URL:  https://your-host:8080/dyndns?prefix=<ip6lanprefix>
Username:    <one of your configured logins>
Password:    <its password>
```

## Configuration

All configuration is via environment variables; there is no config file to edit.

| Var | Default | Purpose |
|---|---|---|
| `PUBLIC_ADDR` | `:8080` | Address the public listener binds to |
| `PRIVATE_ADDR` | `:9090` | Address the private listener binds to |
| `TLS_CERT_FILE` | *(none)* | Path to a PEM certificate (full chain) for the public listener. Must be set together with `TLS_KEY_FILE`, or not at all |
| `TLS_KEY_FILE` | *(none)* | Path to the matching PEM private key |
| `IP_TOKENS` | *(none)* | Comma-separated tokens valid for `/unlock` |
| `IP_TOKEN_<N>` | *(none)* | Same, one per env var (e.g. `IP_TOKEN_1`, `IP_TOKEN_2`, ...) — combined with `IP_TOKENS` |
| `DYNDNS_LOGINS` | *(none)* | Comma-separated `user:pass` pairs valid for `/dyndns` |
| `DYNDNS_LOGIN_<N>` | *(none)* | Same, one per env var — combined with `DYNDNS_LOGINS` |
| `ALLOWLIST_PATH` | `allowlist.json` | Where registrations are persisted, so they survive a restart |
| `ALLOWLIST_MAX_IPS` | `50` | Max number of distinct IPs registered at once |
| `ALLOWLIST_IP_TTL` | `24h` | How long a registered IP stays valid |
| `ALLOWLIST_PREFIX_TTL` | `24h` | How long a registered prefix stays valid |
| `ACCESS_LOG` | `true` | Log each registration attempt and its outcome |
| `FRP_DEBUG` | `false` | Verbose logging of every frp allow/reject decision |

Example:
```
IP_TOKENS=my-secret-token
DYNDNS_LOGINS=alice:hunter2
ALLOWLIST_IP_TTL=12h
```

The process refuses to start if a configured value is malformed (e.g. `ALLOWLIST_MAX_IPS=abc`), rather than silently ignoring it.

The cert/key files are watched for changes: if something else (e.g. certbot) renews them in place, the new cert is picked up automatically on the next TLS handshake, no restart needed.

## Connecting it to frp

Add this as an frps server plugin, in `frps.toml`:
```toml
[[httpPlugins]]
name = "ip-filter"
addr = "127.0.0.1:9090"
path = "/frp-plugin"
ops = ["Login", "NewUserConn", "NewProxy", "CloseProxy"]
```

Optionally, exclude `Login` to not gate the frpc connection itself behind the filter.

By default, every proxy is protected: only registered IPs/prefixes can connect. To make a specific proxy public (skip filtering for it), add to its definition in `frpc.toml`:
```toml
[[proxies]]
name = "public-site"
...
metadatas = { ip_filter = "false" }
```
