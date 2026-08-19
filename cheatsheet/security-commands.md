# VPS Security Commands Cheatsheet

> One-page quick reference for VPS security ops. Print on A4, pin to wall.

---

## System Info

| Command | What it does | Example |
|---|---|---|
| `uname -a` | Kernel + arch + hostname | `uname -a` |
| `hostname` / `hostnamectl` | Show/set hostname | `hostnamectl set-hostname web01` |
| `uptime` | Load avg + uptime | `uptime` |
| `last reboot` | Reboot history | `last reboot | head` |
| `lscpu` | CPU topology | `lscpu` |
| `free -h` | RAM + swap (human) | `free -h` |
| `df -h` | Disk usage by mount | `df -hT` |
| `du -sh <dir>` | Size of a directory | `du -sh /var/* \| sort -rh \| head` |
| `cat /etc/os-release` | Distro info | `cat /etc/os-release` |
| `lsb_release -a` | Ubuntu/Debian version | `lsb_release -a` |

## Process Management

| Command | What it does | Example |
|---|---|---|
| `ps aux` | All processes | `ps aux \| grep nginx` |
| `top` / `htop` | Interactive monitor | `htop` |
| `kill <pid>` | Send TERM by PID | `kill 1234` |
| `kill -9 <pid>` | Force kill | `kill -9 1234` |
| `killall <name>` | Kill by name | `killall nginx` |
| `pkill -f <pat>` | Kill by full match | `pkill -f "python run.py"` |
| `jobs` | Background jobs in shell | `jobs` |
| `bg` / `fg` | Resume bg/fg | `fg %1` |
| `nohup <cmd> &` | Survive logout | `nohup ./serve.sh &` |
| `nice -n 10 <cmd>` | Start with lower prio | `nice -n 10 tar czf backup.tgz /data` |
| `renice 5 -p <pid>` | Change prio live | `renice 5 -p 1234` |

## Network

| Command | What it does | Example |
|---|---|---|
| `ss -tlnp` | Listening TCP + proc | `ss -tlnp \| grep :80` |
| `netstat -tulpn` | Legacy listening ports | `netstat -tulpn` |
| `ip a` | Interfaces + IPs | `ip a` |
| `ip r` | Routing table | `ip r` |
| `ifconfig` | Legacy iface info | `ifconfig eth0` |
| `curl -I <url>` | Headers only | `curl -I https://example.com` |
| `wget <url>` | Download file | `wget -c https://host/file.iso` |
| `ping <host>` | ICMP reachability | `ping -c 4 1.1.1.1` |
| `dig <domain>` | DNS lookup | `dig example.com +short` |
| `nslookup <host>` | Legacy DNS | `nslookup example.com` |
| `traceroute <host>` | L3 path | `traceroute 8.8.8.8` |
| `mtr <host>` | ping + traceroute live | `mtr --report 8.8.8.8` |
| `nc -zv <host> <port>` | Port check | `nc -zv example.com 443` |

## File Operations

| Command | What it does | Example |
|---|---|---|
| `find <dir> -name <pat>` | Find by name | `find /etc -name "*.conf"` |
| `find <dir> -mtime -1` | Modified < 1 day | `find /var/log -mtime -1` |
| `locate <name>` | Indexed search | `locate nginx.conf` |
| `which <cmd>` | Binary in PATH | `which python3` |
| `whereis <cmd>` | Bin + man + src | `whereis nginx` |
| `tar czf <out> <in>` | gzip tarball | `tar czf site.tgz /var/www` |
| `tar xzf <file>` | Extract gzip | `tar xzf site.tgz` |
| `gzip <file>` | Compress (replace) | `gzip big.log` |
| `zstd -19 <file>` | Fast strong compress | `zstd -19 backup.tar` |
| `unzip <file>` | Extract zip | `unzip release.zip` |
| `rsync -avz src/ dst/` | Sync dirs | `rsync -avz --delete /srv/ user@host:/srv/` |
| `scp f host:/path` | Copy over SSH | `scp file.tar user@host:/tmp/` |
| `sftp <host>` | Interactive FTP | `sftp user@host` |

## Text Processing

| Command | What it does | Example |
|---|---|---|
| `grep -rn <pat> <dir>` | Recursive search | `grep -rn "Port " /etc/ssh` |
| `awk '{print $1}'` | Column extract | `awk '{print $2}' file.log` |
| `sed -i 's/a/b/g' f` | In-place replace | `sed -i 's/8080/80/g' nginx.conf` |
| `cut -d: -f1` | Field extract | `cut -d: -f1 /etc/passwd` |
| `sort \| uniq -c` | Count dups | `sort access.log \| uniq -c \| sort -rn` |
| `head -n 20` / `tail -n 20` | First/last lines | `tail -f /var/log/syslog` |
| `less` / `more` | Pager | `less +F /var/log/messages` |
| `diff a b` | Compare files | `diff old.conf new.conf` |
| `wc -l <file>` | Line/word/byte count | `wc -l /var/log/auth.log` |

## User & Permissions

| Command | What it does | Example |
|---|---|---|
| `useradd -m -s /bin/bash <u>` | Create user w/ home | `useradd -m -s /bin/bash deploy` |
| `usermod -aG <grp> <user>` | Add to group | `usermod -aG docker deploy` |
| `userdel -r <user>` | Delete + home | `userdel -r olduser` |
| `passwd <user>` | Set password | `passwd deploy` |
| `sudo <cmd>` | Run as root | `sudo apt update` |
| `su - <user>` | Switch user | `su - postgres` |
| `visudo` | Edit sudoers safely | `visudo` |
| `chmod 755 <f>` | Set mode | `chmod 600 ~/.ssh/id_ed25519` |
| `chown user:grp <f>` | Change owner | `chown -R deploy:deploy /var/www` |
| `chgrp <grp> <f>` | Change group | `chgrp www-data /var/www/html` |
| `umask 022` | Default perms mask | `umask 077` |

## Cron & Services

| Command | What it does | Example |
|---|---|---|
| `crontab -e` / `-l` | Edit/list cron | `crontab -l` |
| `systemctl start <svc>` | Start service | `systemctl restart nginx` |
| `systemctl enable <svc>` | Boot-start | `systemctl enable --now ufw` |
| `systemctl status <svc>` | Status | `systemctl status sshd` |
| `journalctl -u <svc>` | Service logs | `journalctl -u nginx -f` |
| `timedatectl` | Timezone/ntp | `timedatectl set-timezone Asia/Shanghai` |
| `hostnamectl` | Hostname info | `hostnamectl` |

## Disk

| Command | What it does | Example |
|---|---|---|
| `lsblk` | Block devices | `lsblk -f` |
| `fdisk -l` | Partition table | `fdisk -l /dev/sda` |
| `parted <dev>` | Advanced partitioning | `parted /dev/sda print` |
| `mkfs.ext4 <part>` | Make filesystem | `mkfs.ext4 /dev/sdb1` |
| `mount <dev> <dir>` | Mount | `mount /dev/sdb1 /data` |
| `umount <dir>` | Unmount | `umount /data` |
| `fsck <part>` | Check/repair FS | `fsck -y /dev/sda1` |
| `smartctl -a <dev>` | SMART health | `smartctl -a /dev/sda` |
| `iostat -x 1` | I/O stats | `iostat -xm 2` |

## Package Management

### Debian / Ubuntu (apt / dpkg)

| Command | What it does |
|---|---|
| `apt update && apt upgrade` | Refresh + upgrade |
| `apt install <pkg>` | Install |
| `apt remove <pkg>` | Remove (keep config) |
| `apt purge <pkg>` | Remove + config |
| `apt autoremove` | Clean deps |
| `apt-cache search <term>` | Search |
| `dpkg -l` | List installed |
| `dpkg -i <deb>` | Install .deb file |
| `apt-get clean` | Clear /var/cache/apt |

### RHEL family (dnf / yum / rpm)

| Command | What it does |
|---|---|
| `dnf upgrade` | Upgrade all |
| `dnf install <pkg>` | Install |
| `dnf remove <pkg>` | Remove |
| `dnf history` | Transaction history |
| `rpm -qa` | List installed |
| `rpm -ql <pkg>` | Files of a pkg |
| `rpm -qf <file>` | Which pkg owns file |
