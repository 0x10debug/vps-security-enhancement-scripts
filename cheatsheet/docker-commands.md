# Docker & Docker Compose Cheatsheet

> One-page quick reference for container ops on VPS. Print on A4.

---

## Docker Basics

| Command | What it does | Example |
|---|---|---|
| `docker run <img>` | Start a container | `docker run -d --name web -p 80:80 nginx` |
| `docker run -it <img> bash` | Interactive shell | `docker run -it ubuntu bash` |
| `docker ps` | Running containers | `docker ps -a` (all) |
| `docker stop <name>` | Stop container | `docker stop web` |
| `docker start <name>` | Start stopped | `docker start web` |
| `docker restart <name>` | Restart | `docker restart web` |
| `docker rm <name>` | Remove container | `docker rm -f web` |
| `docker exec -it <c> bash` | Shell in running | `docker exec -it web sh` |
| `docker logs <name>` | View logs | `docker logs -f --tail 100 web` |
| `docker images` | List images | `docker images -a` |
| `docker rmi <img>` | Remove image | `docker rmi nginx:latest` |
| `docker build -t <tag> .` | Build from Dockerfile | `docker build -t myapp:1.0 .` |
| `docker pull <img>` | Pull from registry | `docker pull postgres:16` |
| `docker push <tag>` | Push to registry | `docker push myreg/myapp:1.0` |
| `docker tag <src> <dst>` | Retag image | `docker tag myapp:1.0 myapp:latest` |

## Volumes

| Command | What it does | Example |
|---|---|---|
| `docker volume create <name>` | Create volume | `docker volume create pgdata` |
| `docker volume ls` | List volumes | `docker volume ls` |
| `docker volume rm <name>` | Remove volume | `docker volume rm pgdata` |
| `docker volume inspect <name>` | Details + mount path | `docker volume inspect pgdata` |

## Networks

| Command | What it does | Example |
|---|---|---|
| `docker network create <name>` | Create network | `docker network create appnet` |
| `docker network ls` | List networks | `docker network ls` |
| `docker network rm <name>` | Remove network | `docker network rm appnet` |
| `docker network inspect <name>` | Details + containers | `docker network inspect bridge` |

## Housekeeping

| Command | What it does |
|---|---|
| `docker stats` | Live CPU/mem/net per container |
| `docker system df` | Disk usage by images/containers/volumes |
| `docker system prune` | Remove unused data |
| `docker system prune -a --volumes` | Nuke everything unused |
| `docker image prune -a` | Remove all unused images |
| `docker container prune` | Remove stopped containers |

## Docker Compose

| Command | What it does | Example |
|---|---|---|
| `docker compose up -d` | Start stack detached | `docker compose up -d` |
| `docker compose down` | Stop + remove | `docker compose down -v` (also volumes) |
| `docker compose start` | Start (no recreate) | `docker compose start` |
| `docker compose stop` | Stop (keep containers) | `docker compose stop` |
| `docker compose restart` | Restart services | `docker compose restart web` |
| `docker compose logs -f <svc>` | Follow logs | `docker compose logs -f --tail 50 db` |
| `docker compose exec <svc> sh` | Shell in service | `docker compose exec web bash` |
| `docker compose ps` | Stack status | `docker compose ps` |
| `docker compose build` | Build images | `docker compose build --pull` |
| `docker compose pull` | Pull images | `docker compose pull` |
| `docker compose config` | Validate + render | `docker compose config` |
| `docker compose -f file.yml -p proj up -d` | Custom file + project | `docker compose -f prod.yml -p myapp up -d` |

## Useful One-liners

```bash
# Enter a running container
docker exec -it <name> bash          # use sh if no bash

# Copy file host <-> container
docker cp ./app.conf <name>:/etc/nginx/conf.d/
docker cp <name>:/var/log/app.log ./

# Export / import image (no registry needed)
docker save -o app.tar myapp:1.0
docker load -i app.tar

# Inspect everything (network mode, ports, mounts, env)
docker inspect <name>
docker inspect -f '{{json .NetworkSettings.Ports}}' <name>

# Resource limits on run
docker run -d --name api --memory=512m --cpus=1 --restart=unless-stopped myapp

# Wipe everything (careful!)
docker system prune -a --volumes
```

## Docker UFW Bypass — Critical

**The issue:** Docker manipulates `iptables` directly to publish ports, **bypassing UFW**. A container published with `-p 8080:80` is reachable from the public internet even if `ufw deny 8080` is set. UFW rules are an illusion for Docker ports.

**Check if affected:**
```bash
iptables -L -n | grep DOCKER
iptables -t nat -L -n | grep DOCKER
# If you see published ports here, UFW is NOT controlling them
```

**Fix:** Take over Docker's iptables so UFW rules apply.
```bash
# Reference: vps_secure.sh  →  d1  →  Docker  →  UFW 接管
# After fix, Docker no longer writes its own iptables nat rules;
# you must expose ports via explicit UFW allow rules + --iptables=false.
```

## Debugging

| Symptom | First step |
|---|---|
| Can't connect to container port | `docker logs <name>`; `docker inspect` (NetworkMode, Ports) |
| Disk full from Docker | `docker system df`; `docker system prune -a --volumes` |
| Container exits immediately | `docker logs <name>` — read the actual error |
| Permission denied on volume | Check host dir ownership / `user` mapping in image |
| `bind: address already in use` | `ss -tlnp \| grep :<port>` — find the hog |
| Image pull fails | Check registry auth / DNS / `docker login` |
| Compose port conflict | `docker compose ps`; `docker compose down` then `up -d` |
