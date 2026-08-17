# Network Troubleshooting

> "My service is unreachable" — the decision tree that finds the problem in minutes, not hours.

## Overview

"The website is down" is the most common — and most stressful — ops message you'll receive. Network troubleshooting on a VPS involves multiple layers: the application listening on a port, the OS firewall, Docker's iptables rules, the cloud provider's security group, DNS resolution, and the route between client and server. The mistake most people make is checking one layer, finding nothing, and getting stuck — instead of systematically walking the full path from the socket to the client.

This chapter provides a decision tree for "service unreachable" scenarios, plus tools for DNS troubleshooting, route tracing, bandwidth testing, streaming unlock detection, IP quality assessment, and BBR congestion control. Each section follows the closed loop: **Problem → Investigate (which layer is blocking?) → Fix → Verify**. We reference `vps_secure.sh` menu entries and cross-reference **network-toolkit** for reverse proxy and SSL termination needs.

## Problem: Service Unreachable

### The Decision Tree

When a service is unreachable, walk this path from the server outward. Stop at the first layer that fails — that's where the problem is.

```
Client can't reach service
  │
  ├─ Layer 1: Is the service listening?
  │   └─ ss -tlnp | grep <port>
  │       ├─ Not listening → start the service / fix the app
  │       └─ Listening → go to Layer 2
  │
  ├─ Layer 2: Is the OS firewall blocking it?
  │   └─ ufw status / firewall-cmd --list-all
  │       ├─ Port not allowed → ufw allow <port>
  │       └─ Port allowed → go to Layer 3
  │
  ├─ Layer 3: Is Docker bypassing the firewall?
  │   └─ iptables -L DOCKER -n | grep <port>
  │       ├─ Docker rule exists but UFW doesn't → apply UFW takeover (Ch.03)
  │       └─ No Docker involvement → go to Layer 4
  │
  ├─ Layer 4: Is the cloud security group blocking it?
  │   └─ Check provider console (AWS/GCP/Azure/Hetzner/Aliyun)
  │       ├─ Port not allowed → add rule in provider console
  │       └─ Port allowed → go to Layer 5
  │
  ├─ Layer 5: Is DNS resolving correctly?
  │   └─ dig <domain> / nslookup <domain>
  │       ├─ Wrong IP or no answer → fix DNS records
  │       └─ Correct IP → go to Layer 6
  │
  └─ Layer 6: Is the route blocked or down?
      └─ mtr <server-ip> / traceroute <server-ip>
          ├─ Packets lost at a hop → ISP/transit issue
          └─ Reaches server → check if service binds to 0.0.0.0 not 127.0.0.1
```

### Layer 1: Is the service listening?

```bash
# On the server:
ss -tlnp | grep -E ':80 |:443 |:8080 '
# State  Local Address:Port  Process
# LISTEN  0.0.0.0:80          nginx: master
# LISTEN  0.0.0.0:443         nginx: master
# LISTEN  127.0.0.1:8080      myapp   ← bound to localhost only!
```

**Common trap**: the service binds to `127.0.0.1` (localhost) instead of `0.0.0.0` (all interfaces). It's reachable from the server itself but not from outside. Fix the app config to bind `0.0.0.0` or the public IP.

```bash
# Quick local test:
curl -m 3 http://127.0.0.1:8080
# Works locally but not externally → binding issue

# Test from server's public IP:
curl -m 3 http://203.0.113.10:8080
# Connection refused → not listening on public interface
```

`vps_secure.sh` has a port connectivity probe:

```bash
secure-vps  # c1 → 6 (端口连通探测)
# Enter host:port: 203.0.113.10:8080
# Probes with a 3s timeout, reports open/closed/filtered
```

### Layer 2: Is the OS firewall blocking?

```bash
# UFW (Debian/Ubuntu):
ufw status numbered
# [1] 50022/tcp    ALLOW IN    Anywhere
# [2] 80/tcp       ALLOW IN    Anywhere
# [3] 443/tcp      ALLOW IN    Anywhere
# 8080 is NOT listed → blocked

ufw allow 8080/tcp
ufw reload

# firewalld (RHEL family):
firewall-cmd --list-ports
# 50022/tcp 80/tcp 443/tcp
# 8080 not listed → blocked

firewall-cmd --permanent --add-port=8080/tcp
firewall-cmd --reload

# Or via secure-vps:
secure-vps  # b2 → 3 (放行自定义端口)
```

### Layer 3: Is Docker bypassing the firewall?

```bash
# Check if Docker opened the port directly in iptables:
iptables -L DOCKER -n | grep 8080
# ACCEPT  tcp  --  0.0.0.0/0  0.0.0.0/0  tcp dpt:8080

# But UFW doesn't have it:
ufw status | grep 8080
# (empty)
```

This means Docker's `-p` flag bypassed UFW. See Chapter 03 for the full fix (`secure-vps` → `d1 → 1 → 3`). After the UFW takeover fix, you control container ports via UFW normally.

### Layer 4: Is the cloud security group blocking?

This is the most commonly missed layer. Every cloud provider has an external firewall that operates at the network layer, before traffic reaches your VPS:

| Provider | Where to check |
|----------|---------------|
| AWS EC2 | Security Groups (inbound rules) |
| GCP | VPC Firewall rules |
| Azure | Network Security Group |
| Hetzner | Cloud Firewall (project → Firewalls) |
| Aliyun | Security Group rules |
| Vultr | Firewall Group |
| DigitalOcean | Cloud Firewalls |

**Symptom**: `ufw status` shows the port allowed, `ss` shows the service listening, but external `nmap` shows the port as `filtered` (dropped by a firewall before reaching the OS).

**Fix**: add an inbound allow rule for the port in the provider's console. This is separate from UFW — both must allow the port.

### Layer 5: Is DNS resolving correctly?

```bash
# From the client:
dig example.com
# example.com.  300  IN  A  203.0.113.10   ← correct?

dig example.com +short
# 203.0.113.10

# Check from different DNS resolvers:
dig @8.8.8.8 example.com +short
dig @1.1.1.1 example.com +short

# Check NS records:
dig example.com NS +short
# ns1.cloudflare.com.
# ns2.cloudflare.com.
```

**Common DNS problems**:
- A record points to wrong IP (after migration)
- DNS propagation delay (TTL not expired — wait or lower TTL before changes)
- Domain expired
- NS records point to wrong nameservers
- CNAME chain broken

### Layer 6: Is the route blocked?

```bash
# From the client:
mtr 203.0.113.10
# Shows each hop with packet loss % and latency
# If loss starts at a specific hop, that's where the problem is

traceroute 203.0.113.10
# Classic traceroute

# vps_secure.sh offers NextTrace (better for Asian routes):
secure-vps  # d2 → 5 (回程路由 / NextTrace)
# Runs nexttrace --fast-trace (three-network quick trace from China)
```

## Port Scanning from External

### nmap

```bash
# From an external machine (NOT the server itself):
nmap -sS -p 22,80,443,8080,3306,6379 203.0.113.10
# PORT     STATE    SERVICE
# 22/tcp   filtered ssh       ← cloud security group blocking
# 80/tcp   open     http
# 443/tcp  open     https
# 8080/tcp filtered http-proxy
# 3306/tcp filtered mysql
# 6379/tcp filtered redis

# Full scan with service detection:
nmap -sV -O 203.0.113.10
# -sV: service version detection
# -O: OS detection
```

**`open`** = service reachable. **`closed`** = no service listening (port reachable but nothing there). **`filtered`** = firewall dropping packets (can't tell if service exists).

### Online tools

If you don't have an external machine:
- **shodan.io** — shows what ports your server exposes to the internet
- **censys.io** — similar, with different scanning methodology
- **nmap.online** — web-based nmap
- **ping.pe** — port check from multiple global locations

Check your server on Shodan periodically — if it shows ports you didn't intend to expose (especially 3306, 6379, 27017, 9200), you have a leak to fix.

## DNS Troubleshooting

### dig and nslookup

```bash
# Full DNS query with trace:
dig example.com +trace

# Check specific record type:
dig example.com A +short
dig example.com MX +short
dig example.com TXT +short

# Check from a specific resolver:
dig @1.1.1.1 example.com A +short

# Reverse DNS (PTR):
dig -x 203.0.113.10 +short
# server.example.com.   ← should match your forward A record

# nslookup (simpler, available everywhere):
nslookup example.com
nslookup example.com 8.8.8.8
```

### /etc/resolv.conf

```bash
cat /etc/resolv.conf
# nameserver 8.8.8.8
# nameserver 1.1.1.1

# If DNS is broken on the server itself:
nslookup google.com
# ;; connection timed out; no servers could be reached

# Fix via secure-vps:
secure-vps  # c1 → 4 (DNS 切换)
# Options: Cloudflare, Google, AliDNS, custom

# Or manually:
echo "nameserver 1.1.1.1" > /etc/resolv.conf
echo "nameserver 8.8.8.8" >> /etc/resolv.conf
```

**Note**: on systemd-resolved systems, `/etc/resolv.conf` is a symlink to a stub. Edit `/etc/systemd/resolved.conf` instead, then `systemctl restart systemd-resolved`.

### DNS propagation check

```bash
# Check from multiple global resolvers:
for ns in 8.8.8.8 1.1.1.1 208.67.222.222 9.9.9.9; do
  echo -n "$ns: "; dig @$ns example.com +short
done

# Or use an online checker:
# https://www.whatsmydns.net
# https://dnschecker.org
```

## Route Tracing

### mtr (recommended — combines traceroute + ping)

```bash
apt install -y mtr     # or: yum install -y mtr
mtr 203.0.113.10
#                              My traceroute  (v0.95)
# HOST: myclient               Loss%   Snt   Last   Avg
# 1. router.local               0.0%    10    0.5    0.5
# 2. isp-gateway                0.0%    10    8.2    8.1
# 3. transit-hop                0.0%    10   25.3   24.8
# 4. ???                       100.0%    10    —      —    ← ICMP blocked, normal
# 5. target-server              0.0%    10   45.2   45.0
```

**Reading mtr**: look for the first hop where loss appears. If loss starts at hop 4 and continues to the end, the problem is at or beyond hop 4. If a middle hop shows 100% loss but later hops are fine, that hop just blocks ICMP — it's not the problem.

### NextTrace (better for Asian routes)

```bash
secure-vps  # d2 → 5 (回程路由 / NextTrace)
# Installs NextTrace if not present, runs --fast-trace
# (traces from China Telecom, China Unicom, China Mobile)
```

NextTrace shows IP geolocation and ASN info at each hop, which helps identify which transit provider is causing latency or loss — especially useful for servers in Asia or serving Chinese users.

### traceroute (classic)

```bash
traceroute -T -p 443 203.0.113.10
# -T: TCP SYN (bypasses ICMP-blocking hops)
# -p 443: target port (some hops respond to TCP but not ICMP)
```

## Bandwidth Testing

### bench.sh

```bash
secure-vps  # d2 → 3 (带宽测速 / bench.sh)
# Runs bench.sh which tests download speed from multiple global nodes
# and reports CPU model, kernel, uptime, and disk I/O speed
```

Or manually:

```bash
wget -qO- bench.sh | bash
# Tests download from: Softlayer (US), Linode (US/UK/JP/SG),
#                       OVH (FR), Hetzner (DE), etc.
# Reports: CPU, RAM, disk, network speed
```

### iperf3 (point-to-point)

```bash
# On the server (as server):
iperf3 -s
# Server listening on 5201

# On the client:
iperf3 -c 203.0.113.10 -t 30
# [  5] 0.00-30.00 sec  2.5 GBytes  716 Mbits/sec   ← actual throughput

# Reverse test (server → client):
iperf3 -c 203.0.113.10 -t 30 -R

# UDP test (shows packet loss and jitter):
iperf3 -c 203.0.113.10 -u -b 100M
```

iperf3 gives you the actual maximum throughput between two points, unlike bench.sh which tests download from public nodes. Use it when you need to know if a specific client-server path can handle your bandwidth requirements.

## Streaming Unlock Detection

For servers used as media proxies or VPNs, you often need to know which streaming services the IP can access:

```bash
secure-vps  # d2 → 4 (流媒体解锁)
# Runs a streaming unlock detection script
# Checks: Netflix, Disney+, YouTube Premium, ChatGPT, TikTok, etc.
```

Typical output:

```
[Netflix]       Originals Only (not region-locked content)
[Disney+]       No
[YouTube]       Premium available (region: US)
[ChatGPT]       Available
[TikTok]        Region: US
```

This matters because:
- Some VPS IP ranges are flagged by streaming services (datacenter IPs)
- Netflix/Disney+ block known datacenter ranges
- If you're building a media proxy, you need a "clean" IP (residential or unflagged datacenter)

## IP Quality Check

For proxy/VPN servers, IP quality affects deliverability (email), reputation (streaming), and reachability (some sites block known VPS ranges):

```bash
secure-vps  # d2 → 7 (IP 质量评分)
# Runs IP.Check.Place or similar service
# Reports: fraud score, abuse confidence, proxy/VPN detection, blacklist status
```

What to look for:
- **Fraud score** (Scamalytics): low is good (< 25). High scores get blocked by anti-fraud systems.
- **Abuse confidence** (AbuseIPDB): 0% is ideal. High confidence means the IP has been reported for attacks.
- **Blacklists**: check if the IP appears on Spamhaus, Barracuda, SORBS. Blacklisted IPs can't send email.
- **Proxy/VPN detection**: if the IP is flagged as a proxy, some services (banks, streaming) will block it.

## BBR Congestion Control

### What BBR does

BBR (Bottleneck Bandwidth and Round-trip propagation time) is a TCP congestion control algorithm developed by Google. Unlike the default CUBIC (which uses packet loss as the congestion signal), BBR models the network's actual bandwidth and latency to maximize throughput while minimizing buffer bloat.

**When BBR helps**:
- High-latency connections (transcontinental, satellite)
- Lossy networks (where CUBIC backs off too aggressively)
- High-bandwidth links with shallow buffers
- Servers serving content to mobile users

**When BBR doesn't help (or hurts)**:
- Low-latency LAN connections (no bottleneck to model)
- Very low-bandwidth links (BBR can be too aggressive)
- Some edge cases with certain middleboxes

### Enable BBR

```bash
secure-vps  # c2 → 1 (开启 BBR)
```

Checks kernel version (needs ≥ 4.9), loads the `tcp_bbr` module, writes `/etc/sysctl.d/99-secure-vps-bbr.conf`:

```ini
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
```

### Verify

```bash
sysctl net.ipv4.tcp_congestion_control
# net.ipv4.tcp_congestion_control = bbr

sysctl net.core.default_qdisc
# net.core.default_qdisc = fq

lsmod | grep bbr
# tcp_bbr   20480  3   ← module loaded and in use
```

**Note**: `a1` quick-init enables BBR as part of the baseline. If you used `a1`, BBR is already on — verify with the commands above.

## Cross-Reference: network-toolkit

For reverse proxy, SSL termination, and advanced network configurations, use **network-toolkit** from the 0x10debug ecosystem:

- **Caddy / Nginx / Traefik** reverse proxy setups with automatic HTTPS
- **SSL certificate management** (Let's Encrypt / acme.sh)
- **WireGuard** VPN setup for private access to services
- **Cloudflare** integration (DNS, proxy, tunnel)

Use network-toolkit when your networking needs go beyond "open a port" — when you need to route multiple services through one port, terminate TLS, or set up private access tunnels.

## Common Scenarios

### Scenario: Website works from my laptop but not from China

```
Problem: Users in China can't reach the website.
Investigate:
  1. mtr from a Chinese node (or use NextTrace: secure-vps d2 → 5)
     → If packets lost at the Chinese border → GFW interference or transit issue
  2. Check if the IP is blocked: ping from China (ping.pe tool)
     → If ping fails but traceroute shows hops reaching near the server → IP blocked
  3. Check DNS: dig from a Chinese resolver (223.5.5.5)
     → If DNS returns wrong IP → DNS pollution
Fix:
  - If IP blocked: get a new IP from your provider, or use Cloudflare proxy
  - If DNS polluted: use DNS-over-HTTPS, or move DNS to Cloudflare
  - If transit issue: choose a server location with better China routing
    (Hong Kong, Tokyo, Singapore with CN2 GIA routing)
Verify:
  - Re-test from Chinese node after changes
```

### Scenario: SSH suddenly unreachable

```
Problem: Can't SSH in, was working yesterday.
Investigate:
  1. Use provider's VNC/console to access the server
  2. ss -tlnp | grep <ssh-port> → is sshd running?
  3. ufw status → is the port still allowed?
  4. fail2ban-client status sshd → is your IP banned?
Fix:
  - sshd crashed: systemctl restart sshd
  - Firewall reset: ufw allow <port>/tcp
  - Banned by fail2ban: fail2ban-client set sshd unbanip <your-ip>
Verify:
  - SSH from your machine succeeds
```

## What's Next

- **Chapter 05** — Performance tuning: BBR in the context of system performance, swap, and resource limits
- **Chapter 07** — Monitoring: detecting network issues before users report them
- **Chapter 02** — Security baseline: firewall configuration in the security context
