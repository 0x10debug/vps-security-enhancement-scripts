# Network Zero Trust (WireGuard + Headscale)

> Zero Trust network deployment with WireGuard mesh VPN, Headscale control plane, ACL-based access control, CrowdSec integration, and GeoIP filtering.

## Overview

Traditional VPNs trust internal network traffic by default. Zero Trust assumes no traffic is trusted — every connection must be authenticated, authorized, and encrypted. This chapter covers the zero trust network setup tool:

- **`scripts/zerotrust_setup.sh`** — WireGuard + Headscale deployment, ACL generation, CrowdSec integration, GeoIP filtering

## Architecture

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│  Client A   │─────│  Headscale  │─────│  Server B   │
│  (WireGuard)│     │  (Control)  │     │  (WireGuard)│
└─────────────┘     └─────────────┘     └─────────────┘
                          │
                    ┌─────┴─────┐
                    │  ACL Policy │
                    │  (Huac)    │
                    └───────────┘
                          │
                    ┌─────┴─────┐
                    │  CrowdSec  │
                    │  (Threat)  │
                    └───────────┘
```

## Components

| Component | Role | Technology |
|---|---|---|
| WireGuard | Encrypted mesh tunnel | Kernel-level VPN |
| Headscale | Control plane (Tailscale alternative) | Open source coordination server |
| ACL | Access control policy | Huac format policy file |
| CrowdSec | Threat detection + auto-block | Log analysis + bouncer |
| GeoIP | Country-level filtering | MaxMind GeoLite2 |

## Usage

```bash
# Interactive wizard
sudo ./scripts/zerotrust_setup.sh

# Install WireGuard
sudo ./scripts/zerotrust_setup.sh --install-wireguard

# Install Headscale
sudo ./scripts/zerotrust_setup.sh --install-headscale

# Generate ACL configuration
sudo ./scripts/zerotrust_setup.sh --acl

# Generate CrowdSec integration
sudo ./scripts/zerotrust_setup.sh --crowdsec

# Generate GeoIP filtering
sudo ./scripts/zerotrust_setup.sh --geoip

# Audit existing zero trust setup (read-only)
sudo ./scripts/zerotrust_setup.sh --audit
```

## ACL Configuration

The generated ACL defines:
- **Groups**: admin, developer, viewer
- **Tags**: server, workstation, monitoring
- **Rules**: accept/deny based on group + tag + port
- **SSH rules**: separate SSH access control
- **Tests**: automated ACL verification

### Example ACL Rule
```huac
// developer: access dev servers (SSH + Web)
{ action = "accept", src = ["group:developer"], dst = ["tag:server:80,443,22"] },
// viewer: read-only web access
{ action = "accept", src = ["group:viewer"], dst = ["tag:server:80,443"] },
// default deny
{ action = "deny", src = ["*"], dst = ["*:*"] },
```

## CrowdSec Integration

- **Log acquisition**: Headscale + WireGuard logs fed to CrowdSec
- **Brute force scenario**: Detects repeated auth failures on Headscale API
- **WireGuard bouncer**: Removes blocked IPs from WireGuard peer list

## GeoIP Filtering

- Uses MaxMind GeoLite2 Country database
- Only allows connections from specified countries
- Runs as cron job every 5 minutes
- Defense-in-depth measure (not a complete solution)

## Audit Checks (13 items)

| Section | Checks | Key Areas |
|---|---|---|
| WireGuard | 5 | Installation, kernel module, interface, IP forwarding, config permissions |
| Headscale | 5 | Installation, service, config, ACL, listen address |
| CrowdSec | 3 | Installation, Headscale acquisition, WireGuard acquisition |
| Network | 3 | Non-default port, key permissions, TLS |

## Common Findings and Fixes

### WireGuard using default port 51820

**Risk**: Default port is well-known, easier to scan.
**Fix**: Change ListenPort in /etc/wireguard/wg0.conf:
```ini
ListenPort = 51821
```

### Headscale listening on all interfaces

**Risk**: Control plane exposed to public internet.
**Fix**: Bind to 127.0.0.1 in config.yaml:
```yaml
server_url: https://zt.example.com
listen_addr: 127.0.0.1:8080
```

### No ACL configured

**Risk**: All nodes can access all resources — not zero trust.
**Fix**: Generate and deploy ACL:
```bash
sudo ./scripts/zerotrust_setup.sh --acl
# Copy to /etc/headscale/acl.huac
# Update config.yaml: acl_path: /etc/headscale/acl.huac
```

## Integration with the Main Script

From `secure-vps`, zero trust is accessible via:

```
B · Security hardening → b8 Zero-trust network → WireGuard/Headscale deployment
```

## Related Tools

| Tool | Repo | Focus |
|---|---|---|
| Zero trust setup (this script) | vps-security-enhancement-scripts | WireGuard + Headscale deployment |
| CrowdSec module | vps-bootstrap | CrowdSec installation |
| CrowdSec audit | security-audit | CrowdSec status audit |
| Edge firewall | network-toolkit | nftables + ipset blocklist |

## References

- [WireGuard](https://www.wireguard.com/) — Official site
- [Headscale](https://github.com/juanfont/headscale) — Open source Tailscale control server
- [Tailscale ACL](https://tailscale.com/kb/1018/acls) — ACL syntax reference
- [CrowdSec](https://crowdsec.net/) — Collaborative threat intelligence
- [MaxMind GeoLite2](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data) — Free GeoIP database
