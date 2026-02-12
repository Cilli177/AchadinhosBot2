# Deploy no Oracle Cloud Free Tier (passo a passo)

Este guia mostra como subir o `AchadinhosBot.Next` em uma VM gratuita da Oracle usando Docker Compose.

> Objetivo: manter seu app online sem depender de créditos do Railway.

---

## 1) Criar conta e VM grátis na Oracle

1. Crie conta em **Oracle Cloud Free Tier**.
2. Crie uma instância `Compute` com imagem **Ubuntu 22.04** (ou 24.04).
3. Escolha shape gratuito (`VM.Standard.A1.Flex`, dentro do limite Always Free).
4. Adicione sua chave SSH pública ao criar a VM.
5. No painel da VCN/Security List, libere entrada para:
   - `22` (SSH)
   - `80` (HTTP)
   - `443` (HTTPS)
   - `8081` (opcional, só para testes diretos)

---

## 2) Acessar a VM por SSH

No seu computador:

```bash
ssh -i ~/.ssh/sua-chave ubuntu@SEU_IP_PUBLICO
```

---

## 3) Preparar ambiente (Docker + Compose)

Na VM:

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y ca-certificates curl gnupg lsb-release git

# Docker oficial
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg

echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
  $(. /etc/os-release && echo $VERSION_CODENAME) stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

sudo apt update
sudo apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

sudo usermod -aG docker $USER
newgrp docker
```

Validar:

```bash
docker --version
docker compose version
```

---

## 4) Baixar seu projeto e preparar .env

```bash
git clone <URL_DO_SEU_REPO>.git
cd dotnet-codespaces
cp AchadinhosBot.Next/.env.example AchadinhosBot.Next/.env
nano AchadinhosBot.Next/.env
```

No `.env`, ajuste principalmente:
- `WEBHOOK_API_KEY`
- `EVOLUTION_API_KEY`
- `EVOLUTION_BASE_URL`
- `TELEGRAM_BOT_TOKEN`
- hashes de senha (`AUTH_ADMIN_PASSWORD_HASH`, etc.)

> Dica: mantenha `ASPNETCORE_ENVIRONMENT=Production` na VM.

---

## 5) Subir aplicação

```bash
docker compose up -d --build
```

Checar status:

```bash
docker compose ps
docker compose logs -f achadinhos-next
```

Testar healthcheck:

```bash
curl http://SEU_IP_PUBLICO:8081/health
```

Se estiver ok, deve retornar JSON com `status: ok`.

---

## 6) (Recomendado) Expor com Nginx + HTTPS

Em vez de deixar `:8081` público, use reverse proxy em 80/443.

### Instalar Nginx

```bash
sudo apt install -y nginx
sudo rm -f /etc/nginx/sites-enabled/default
```

Crie `/etc/nginx/sites-available/achadinhos-next`:

```nginx
server {
    listen 80;
    server_name SEU_DOMINIO;

    location / {
        proxy_pass http://127.0.0.1:8081;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

Ativar:

```bash
sudo ln -s /etc/nginx/sites-available/achadinhos-next /etc/nginx/sites-enabled/achadinhos-next
sudo nginx -t
sudo systemctl restart nginx
```

### Emitir TLS com Let's Encrypt

```bash
sudo apt install -y certbot python3-certbot-nginx
sudo certbot --nginx -d SEU_DOMINIO
```

Após isso, acesse via `https://SEU_DOMINIO`.

---

## 7) Operação do dia a dia

Atualizar aplicação:

```bash
cd ~/dotnet-codespaces
git pull
docker compose up -d --build
```

Reiniciar serviço:

```bash
docker compose restart achadinhos-next
```

Ver logs:

```bash
docker compose logs -f --tail=200 achadinhos-next
```

Backup dos dados (settings/audit):

```bash
docker run --rm -v achadinhos_data:/data -v $(pwd):/backup alpine tar czf /backup/achadinhos_data_backup.tgz -C /data .
```

---

## 8) Troubleshooting rápido

### App não sobe
- Verifique `docker compose logs -f achadinhos-next`.
- Confirme se `.env` tem valores válidos.

### Não acessa externamente
- Confirme regras de entrada na Oracle (22/80/443/8081).
- Confira firewall local da VM (`ufw status`).

### Evolution não conecta
- Verifique `EVOLUTION_BASE_URL` e `EVOLUTION_API_KEY`.
- Teste endpoint da Evolution da própria VM com `curl`.

---

## 9) Recomendação prática de arquitetura grátis

- **Produção econômica**: Oracle Free Tier (VM) + Docker Compose + Nginx + TLS.
- **Staging simples**: Render/Koyeb (free) para testes rápidos.

Assim você reduz risco de ficar sem créditos e mantém controle do ambiente.
