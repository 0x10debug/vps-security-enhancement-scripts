# Resource Security

> Resource exhaustion is an attack vector — defend against it with BBR, swap, limits, and crypto-aware performance tuning.

## Overview

A VPS is a constrained environment. Unlike a bare-metal server with 64 cores and 256 GB RAM, your typical VPS has 1-4 cores, 1-8 GB RAM, and a virtualized disk that may or may not deliver the IOPS you paid for. Performance tuning on a VPS is about extracting maximum value from limited resources — not about theoretical optimization, but about preventing the specific failure modes that kill small servers: OOM kills, disk I/O bottlenecks, network throughput ceilings, and CPU starvation under load.

This chapter covers system resource assessment, BBR congestion control, swap configuration, disk I/O diagnosis, memory analysis, CPU load management, and Docker resource limits. Each section follows the closed loop: **Problem (symptom) → Investigate (measure) → Fix (tune) → Verify (confirm improvement)**. We reference `vps_secure.sh` menu entries (`c2` for BBR/swap, `d2` for benchmarking) throughout.

## Problem: The Server Is Slow

### Investigate: System resource assessment

Before tuning anything, measure. Tuning without measurement is guessing.

```bash
secure-vps  # d2 → 1 (实时资源仪表 / Real-time resource dashboard)
# Shows: uptime, load average, CPU usage, memory, disk usage
# in a compact dashboard format
```

Or use standard tools:

```bash
# CPU and load:
uptime
# 10:30:00 up 5 days,  2 users,  load average: 2.15, 1.80, 0.90
# 1-min, 5-min, 15-min averages

nproc
# 2   ← 2 cores

# Load average interpretation:
# < nproc     : fine, system has headroom
# = nproc     : fully utilized, no spare capacity
# > nproc     : overloaded, processes are queuing
# > 2*nproc   : severely overloaded, response times degrade

# Memory:
free -h
#               total   used   free   available  buff/cache
# Mem:          1.9Gi   1.2Gi  100Mi  600Mi      600Mi
# Swap:         1.0Gi   200Mi  800Mi

# Disk:
df -h /
# /dev/vda1  39G  30G  9G  77%  /

# Disk I/O:
iostat -xz 1 5
# Device  r/s   w/s   rkB/s  wkB/s  %util  await
# vda     10.0  5.0   80.0   40.0   45.0   2.5
# %util > 80% = disk is the bottleneck
# await > 20ms = slow disk or heavy I/O
```

## Fix: BBR Congestion Control

### What BBR does

BBR (Bottleneck Bandwidth and RTT) replaces the default CUBIC TCP congestion control. Instead of reacting to packet loss (CUBIC's approach, which causes throughput to collapse on lossy links), BBR actively probes the network's bandwidth and minimum RTT, then sends at the optimal rate. For VPS servers serving content over the internet — especially across high-latency or lossy paths — BBR typically improves throughput by 2-5x compared to CUBIC.

### When to enable BBR

- **Always enable on public-facing servers.** The default CUBIC is suboptimal for internet-scale traffic.
- **Especially beneficial for**: cross-continental traffic, mobile clients, high-bandwidth links, lossy transit paths.
- **Not needed for**: LAN-only servers, local development VMs.

### Enable BBR

```bash
secure-vps  # c2 → 1 (开启 BBR)
```

The script:
1. Checks kernel version (BBR requires ≥ 4.9; CentOS 7's default 3.10 kernel is too old — upgrade via ELRepo first)
2. Loads the `tcp_bbr` module
3. Writes `/etc/sysctl.d/99-secure-vps-bbr.conf`:
   ```ini
   net.core.default_qdisc = fq
   net.ipv4.tcp_congestion_control = bbr
   ```
4. Applies and verifies

### Verify

```bash
sysctl net.ipv4.tcp_congestion_control
# net.ipv4.tcp_congestion_control = bbr

sysctl net.core.default_qdisc
# net.core.default_qdisc = fq

# Confirm the module is loaded:
lsmod | grep bbr
# tcp_bbr   20480  42   ← 42 connections using BBR
```

**Note**: `a1` quick-init (Chapter 01) enables BBR as part of the baseline. If you used `a1`, BBR is already on.

### When BBR doesn't help

If you enable BBR and throughput doesn't improve, the bottleneck is elsewhere:
- **Disk I/O**: if you're serving large files, disk read speed may be the limit (check with `iostat`)
- **CPU**: if TLS encryption is the bottleneck (check with `top` — high `sy` CPU)
- **Provider bandwidth cap**: some VPS plans have a bandwidth ceiling lower than the port speed
- **Client-side**: the client's connection may be the actual bottleneck

## Fix: Swap

### When to add swap

Swap is virtual memory on disk. It's slower than RAM but prevents the OOM killer from terminating processes when memory is exhausted. On small VPS instances (1-2 GB RAM), swap is essential as an emergency buffer.

**Rules of thumb**:
- **1-2 GB RAM**: add 1-2 GB swap (emergency buffer for spikes)
- **4-8 GB RAM**: add 1 GB swap (light buffer, mostly for hibernation safety)
- **16+ GB RAM**: swap optional (you have enough RAM; swap adds little value)
- **Database servers**: keep swap small (1 GB) and swappiness very low (1-5) — you never want the database to swap, but you want a small buffer to avoid OOM during transient spikes

### Create swap

```bash
secure-vps  # c2 → 2 (新建 Swap)
# Options: 512MB, 1GB (recommended), 2GB, 4GB, custom
```

The script:
1. Checks if swap already exists (skips if so)
2. Checks disk space (requires 30% headroom beyond the swap size)
3. Creates the swap file (`fallocate` or `dd` fallback)
4. Sets permissions (600), formats (`mkswap`), activates (`swapon`)
5. Adds to `/etc/fstab` for persistence across reboots
6. Sets `vm.swappiness = 10` (prefer RAM, only swap under pressure)

### Verify

```bash
swapon --show
# NAME       TYPE  SIZE  USED  PRIO
# /swapfile  file  1G    0B    -2

free -h
# Mem:   1.9Gi  1.2Gi  100Mi  600Mi
# Swap:  1.0Gi  0B     1.0Gi

grep swapfile /etc/fstab
# /swapfile none swap sw 0 0   ← persists across reboots

sysctl vm.swappiness
# vm.swappiness = 10
```

### Tuning swappiness

`vm.swappiness` controls how aggressively the kernel swaps pages to disk:

| Value | Behavior |
|-------|----------|
| 0 | Never swap unless out of memory (OOM risk) |
| 1-10 | Only swap under significant pressure (recommended for servers) |
| 10 (default from secure-vps) | Conservative, prefers RAM |
| 60 | Linux default, moderate swapping |
| 100 | Aggressive swapping (for desktops, not servers) |

```bash
# Change swappiness:
sysctl vm.swappiness=5
echo "vm.swappiness = 5" > /etc/sysctl.d/99-secure-vps-swap.conf

# Verify:
sysctl vm.swappiness
```

### Remove swap

```bash
secure-vps  # c2 → 3 (删除 Swap)
# Removes /swapfile, cleans fstab entry
```

## Fix: Disk I/O

### Investigate

```bash
# Install sysstat if not present:
apt install -y sysstat    # or: yum install -y sysstat

# Real-time disk I/O:
iostat -xz 1
# Device  r/s    w/s    rkB/s  wkB/s  rrqm/s  wrqm/s  %util  await  r_await  w_await
# vda     50.0   20.0   800.0  120.0  0.0     5.0     85.0   3.2    2.0      6.5
#
# Key columns:
#   %util  : percentage of time disk was busy. >80% = bottleneck
#   await  : average I/O latency in ms. >20ms = slow disk or heavy load
#   r/s,w/s: read/write operations per second

# Which process is doing the I/O:
iotop -o    # (install: apt install iotop)
# TID  PRIO  USER     DISK READ  DISK WRITE  COMMAND
# 123  be/4  mysql    5.0 M/s     2.0 M/s     mysqld
# 456  be/4  root     0.0 B/s     15.0 M/s    docker

# Disk speed test:
dd if=/dev/zero of=/tmp/testfile bs=1M count=1024 oflag=direct
# 1073741824 bytes (1.1 GB) copied, 5.2 s, 207 MB/s   ← sequential write speed
rm /tmp/testfile
```

### Fix: Dealing with slow disks

If `%util` is consistently >80% and `await` >20ms:

1. **Identify the I/O hog** with `iotop` — is it a database, a log writer, Docker?

2. **Reduce I/O**:
   - Enable database query caching (MySQL `query_cache_size`, Redis for sessions)
   - Reduce log verbosity (Nginx `access_log off` for health checks)
   - Use `noatime` mount option (stop updating file access times):
     ```bash
     # Edit /etc/fstab:
     /dev/vda1  /  ext4  defaults,noatime  0 1
     # Reboot or remount: mount -o remount /
     ```

3. **Move I/O to memory**: mount `/tmp` as tmpfs:
   ```bash
   echo "tmpfs /tmp tmpfs defaults,noatime,size=1G 0 0" >> /etc/fstab
   mount /tmp
   ```

4. **Upgrade the disk**: if the VPS provider offers SSD/NVMe tiers, upgrade. Some providers throttle IOPS on cheaper plans.

### Benchmark disk performance

```bash
secure-vps  # d2 → 2 (YABS / CPU/磁盘)
# YABS runs Geekbench (CPU) and disk speed tests
# Warning: YABS is heavy — not recommended for very low-spec VPS
```

YABS disk test output:

```
Disk Speed Tests:
+----------+-------------+-----------------+
| Test     | IOPS        | Speed           |
+----------+-------------+-----------------+
| 4k 64t   | 15.2k       | 60.5 MB/s       |
| 1m 64t   | 3.8k        | 3.8 GB/s        |
+----------+-------------+-----------------+
```

**4k random IOPS** is the most important metric for database workloads. **1m sequential** matters for large file serving. If 4k IOPS is <1000, the disk is very slow — avoid running databases on it.

## Fix: Memory

### Investigate

```bash
# Top memory consumers:
ps aux --sort=-%mem | head -10
# USER  PID  %CPU  %MEM   VSZ    RSS    COMMAND
# mysql 123  0.5   35.2   2.5g   670m   mysqld
# root  456  2.1   15.8   1.2g   300m   java -jar app.jar
# root  789  0.1   8.5    800m   162m   /usr/bin/dockerd

# RSS (Resident Set Size) is the actual physical memory used.
# VSZ (Virtual Size) includes swapped-out and shared memory — less useful.

# Memory breakdown:
free -h
#               total   used   free   available  buff/cache
# Mem:          1.9Gi   1.5Gi  50Mi   350Mi      400Mi
# Swap:         1.0Gi   500Mi  500Mi
#
# "available" is what applications can actually use
# (free + reclaimable cache). "free" alone is misleading.

# Check for OOM kills in kernel log:
dmesg | grep -i 'out of memory\|oom-killer'
# [12345.678] Out of memory: Killed process 1234 (mysqld) total-vm:2500000kB
# ← MySQL was OOM-killed at some point
```

### Fix: Identifying and addressing memory hogs

1. **Java applications**: Java is the #1 memory hog on VPS. The JVM heap size often defaults to 1/4 of system RAM, which is too much on small VPS. Set explicit limits:
   ```bash
   java -Xmx512m -Xms256m -jar app.jar
   # -Xmx: max heap, -Xms: initial heap
   ```

2. **MySQL/MariaDB**: tune `innodb_buffer_pool_size` to ~50-70% of available RAM (not total RAM):
   ```ini
   # /etc/mysql/mysql.conf.d/mysqld.cnf
   innodb_buffer_pool_size = 512M   # for 1GB RAM server
   ```

3. **Redis**: set `maxmemory` to prevent Redis from consuming all RAM:
   ```ini
   # /etc/redis/redis.conf
   maxmemory 256mb
   maxmemory-policy allkeys-lru
   ```

4. **Multiple containers on small VPS**: each container has overhead. On 1 GB RAM, run at most 2-3 small containers. Use Docker memory limits (below) to prevent any single container from monopolizing RAM.

### OOM killer behavior

When the system runs out of memory and swap is exhausted, the OOM killer selects a process to terminate. It scores processes by memory usage and "niceness" — high-memory processes get killed first.

```bash
# Check OOM scores:
cat /proc/1234/oom_score
# 500   ← higher = more likely to be killed

# Protect a critical process from OOM:
echo -1000 > /proc/1234/oom_score_adj
# -1000 = immune to OOM killer (use sparingly)

# Make a process more likely to be killed (sacrificial):
echo 1000 > /proc/1234/oom_score_adj
```

**Better than tweaking OOM scores**: prevent OOM in the first place with swap (emergency buffer) and Docker memory limits (prevent any single container from eating everything).

## Fix: CPU

### Investigate

```bash
# Top CPU consumers:
top -o %CPU
# or:
ps aux --sort=-%cpu | head -10

# Load average vs core count:
uptime
# load average: 2.15, 1.80, 0.90
nproc
# 2
# 2.15 > 2 → slightly overloaded (1-min average)

# Per-core usage:
mpstat -P ALL 1 5
# CPU   %usr   %sys   %iowait  %idle
# all   45.0   10.0   5.0      40.0
# 0     80.0   15.0   0.0      5.0    ← core 0 nearly maxed
# 1     10.0   5.0    10.0     75.0   ← core 1 mostly idle
```

**Key CPU metrics**:
- **%usr**: user-space processing (your applications)
- **%sys**: kernel-space processing (system calls, I/O)
- **%iowait**: waiting for disk I/O (high = disk bottleneck, not CPU)
- **%idle**: spare capacity (low = CPU-bound)

If `%iowait` is high, the problem is disk, not CPU. If `%sys` is very high (>20%), something is making excessive system calls (often a misconfigured network or I/O pattern).

### Fix: Process management

```bash
# Limit a process's CPU with nice/cpulimit:
nice -n 10 my_command        # lower priority (19 = lowest)
cpulimit -p 1234 -l 50       # limit to 50% CPU (install: apt install cpulimit)

# Kill a runaway process:
kill 1234                     # graceful (SIGTERM)
kill -9 1234                  # force (SIGKILL) — only if graceful fails

# Find what's causing high load:
ps -eo pid,ppid,%cpu,%mem,cmd --sort=-%cpu | head -20
```

## Fix: Docker Resource Limits

### Memory limits

```bash
# Limit a container to 512MB RAM:
docker run -d --memory=512m --memory-swap=512m myapp

# --memory-swap = --memory means no swap for the container
# --memory-swap = 2x --memory means swap up to the same amount

# In docker-compose.yml:
services:
  myapp:
    image: myapp
    mem_limit: 512m
    memswap_limit: 512m
```

When a container exceeds its memory limit, it gets OOM-killed (the container is stopped, not the whole system). This protects other containers and the host.

### CPU limits

```bash
# Limit to 1.5 cores (out of 2):
docker run -d --cpus=1.5 myapp

# Or use CPU shares (relative weight, 1024 = default):
docker run -d --cpu-shares=512 myapp   # half the default priority

# In docker-compose.yml:
services:
  myapp:
    image: myapp
    cpus: 1.5
    cpu_shares: 512
```

### Verify limits

```bash
# Check a container's resource limits:
docker inspect --format='Memory: {{.HostConfig.Memory}}, CPUs: {{.HostConfig.NanoCpus}}' myapp
# Memory: 536870912 (512MB), CPUs: 1500000000 (1.5)

# Real-time container stats:
docker stats
# CONTAINER  CPU%   MEM USAGE / LIMIT   MEM%   NET I/O
# myapp      45.2%  380MiB / 512MiB     74.2%  5.2MB/1.1MB
# db         12.1%  600MiB / 1GiB       58.6%  2.1MB/800KB
```

## Using vps_secure.sh for Performance

### Quick reference

| Task | Menu path | Function |
|------|-----------|----------|
| Enable BBR | `c2 → 1` | `net_bbr_enable` |
| Create swap | `c2 → 2` | `mem_swap_build` |
| Remove swap | `c2 → 3` | `mem_swap_drop` |
| Real-time dashboard | `d2 → 1` | `sys_pulse` |
| YABS benchmark | `d2 → 2` | `bench_cpu_disk` |
| Bandwidth test | `d2 → 3` | `bench_speed` |
| Streaming unlock | `d2 → 4` | `bench_stream` |
| Route trace | `d2 → 5` | `bench_route` |
| Comprehensive test | `d2 → 6` | `bench_omni` |
| IP quality | `d2 → 7` | `bench_ip_score` |

### Benchmarking with YABS

```bash
secure-vps  # d2 → 2 (YABS)
```

YABS (Yet Another Bench Script) runs:
- **Geekbench 6**: CPU single-core and multi-core scores
- **Disk speed**: 4k and 1M block tests, sequential and random
- **Network speed**: download from multiple global nodes

**Warning**: YABS is CPU-intensive. On a 1-core VPS, it can take 10+ minutes and make the server unresponsive during the Geekbench run. Don't run it on a production server during peak hours.

### Comprehensive benchmark

```bash
secure-vps  # d2 → 6 (融合怪综合评测)
# Runs a comprehensive test combining multiple benchmark scripts
# Includes: CPU, disk, network, streaming, IP quality, route
# Very long-running — use on a fresh server before deploying services
```

## Common Scenarios

### Scenario: MySQL keeps getting OOM-killed

```
Problem: MySQL process disappears, dmesg shows OOM kill.
Investigate:
  1. free -h → how much RAM is available?
  2. ps aux --sort=-%mem | head → what's consuming memory?
  3. Check MySQL config: innodb_buffer_pool_size
  4. swapon --show → is there swap?
Fix:
  1. If no swap: secure-vps c2 → 2 (create 1GB swap)
  2. Reduce innodb_buffer_pool_size to fit available RAM
  3. Set Docker memory limits on other containers
  4. Consider upgrading to a larger VPS if consistently memory-constrained
Verify:
  1. Monitor for 24h: no OOM kills in dmesg
  2. free -h shows healthy available memory under load
```

### Scenario: Server becomes unresponsive under load

```
Problem: SSH becomes slow/unresponsive when traffic spikes.
Investigate:
  1. uptime → load average vs nproc (is CPU overloaded?)
  2. iostat -xz 1 → is disk %util near 100%?
  3. mpstat → is %iowait high? (disk, not CPU problem)
  4. docker stats → is a container consuming all resources?
Fix:
  - CPU bound: add Docker CPU limits, optimize the application
  - Disk bound: add swap (if I/O is paging), reduce logging, upgrade disk
  - Network bound: enable BBR (c2 → 1), check for DDoS (Ch.03)
Verify:
  - Load average stays below nproc under normal traffic
  - SSH remains responsive during traffic spikes
```

## What's Next

- **Chapter 06** — Backup and migration: protecting the data on your tuned server
- **Chapter 07** — Monitoring: catching performance degradation before it becomes an outage
- **Chapter 04** — Network troubleshooting: BBR in the context of network reachability
