# GMD Market — Kurulum

WSL (Ubuntu 26.04 LTS) üzerinde Docker Engine + Node.js 24.

## 1. Docker Engine

```bash
sudo apt update
sudo apt install -y ca-certificates curl gnupg
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
  | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg

echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo $VERSION_CODENAME) stable" \
| sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

sudo apt update
sudo apt install -y docker-ce docker-ce-cli containerd.io \
  docker-buildx-plugin docker-compose-plugin

sudo usermod -aG docker $USER
newgrp docker   # veya WSL'i kapat-aç
```

Doğrulama:

```bash
docker --version
docker compose version
docker run --rm hello-world
```

## 2. Node.js 24 (NodeSource)

```bash
curl -fsSL https://deb.nodesource.com/setup_24.x | sudo -E bash -
sudo apt install -y nodejs

node --version   # v24.x.x beklenir
npm --version
```

## 3. Doğrulama sonrası

`docker info` ve `node -v` çalışıyorsa kurulum tamam. Sonraki adım: repo
klonlama + Next.js/Fastify iskelet kurulumu.