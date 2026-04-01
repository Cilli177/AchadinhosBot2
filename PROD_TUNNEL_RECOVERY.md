# Produção: Tunnel Recovery

## Caminho canônico
- App PROD: `docker-compose.prod.yml`
- Tunnel PROD: `docker-compose.tunnels.yml`
- Env oficial do tunnel: `.env.prod`

## Pré-check
- `http://127.0.0.1:5005/health` deve responder `200`
- `.env.prod` deve conter `CLOUDFLARED_CRED_DIR`
- o arquivo `97a029fe-3c66-446c-b727-d016928cbcb8.json` deve existir dentro desse diretório

## Recuperação do tunnel PROD
- Rode `scripts/start-docker-tunnel-prod.ps1`
- Valide:
  - `https://achadinhos.reidasofertas.ia.br/health`
  - `https://bio.reidasofertas.ia.br`

## Diagnóstico rápido
- Se o app local responde e o domínio público não:
  - cheque `docker logs achadinhos-cloudflared-prod`
  - o erro mais crítico é credencial ausente em `/etc/cloudflared/creds/...json`

## Regra operacional
- Não recriar o app PROD para corrigir falha de tunnel
- Corrija e recrie apenas `cloudflared-prod`
