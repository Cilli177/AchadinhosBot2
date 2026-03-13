# Operacao de Ambientes e Tunnels (2026-03-10)

## Objetivo
Blindar producao e desenvolvimento para que cada ambiente use:
- hostname proprio
- origin proprio
- script proprio de tunnel

## Padrao oficial

### Producao
- Hostname: `https://achadinhos.reidasofertas.ia.br`
- Dashboard: `https://achadinhos.reidasofertas.ia.br/dashboard`
- Conversor: `https://achadinhos.reidasofertas.ia.br/conversor`
- Origin local: `http://127.0.0.1:5005`
- Origem esperada: container Docker `achadinhos-next-prod`
- Stack Docker oficial: `achadinhos-prod`
- Script oficial: `powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\start-cloudflare-prod.ps1`
- Script Docker oficial: `powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\start-docker-prod.ps1`

### Desenvolvimento
- Hostname: `https://achadinhos-dev.reidasofertas.ia.br`
- Dashboard: `https://achadinhos-dev.reidasofertas.ia.br/dashboard`
- Conversor: `https://achadinhos-dev.reidasofertas.ia.br/conversor`
- Origin preferencial: `http://127.0.0.1:8081`
- Fallback local aceito pelo script: `http://127.0.0.1:5000`
- Stack Docker oficial: `achadinhos-dev`
- Script oficial: `powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\start-cloudflare-dev.ps1`
- Script Docker oficial: `powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\start-docker-dev.ps1`

## Regras obrigatorias
- Nunca subir DEV no hostname principal.
- Nunca apontar o tunnel PROD para `5000` ou `8081`.
- Tunnel PROD deve mirar somente `5005`.
- DEV deve usar apenas o subdominio `achadinhos-dev`.
- Nunca usar `docker compose up` cru para operacao rotineira dos ambientes.
- DEV deve subir apenas pela stack `achadinhos-dev`.
- PROD deve subir apenas pela stack `achadinhos-prod`.
- `PublicBaseUrl` de development deve permanecer em `https://achadinhos-dev.reidasofertas.ia.br`.
- `PublicBaseUrl` de production deve permanecer em `https://achadinhos.reidasofertas.ia.br`.

## Destinos oficiais protegidos
- WhatsApp oficial: `120363405661434395@g.us`
- Telegram oficial: `-1003632436217`
- Esses IDs devem permanecer bloqueados fora de producao via `DeliverySafety`.
- O painel admin usa esses mesmos IDs como defaults de envio manual.
- Observacao: `120363405661434395@g.us` e um group id interno, nao um link publico de convite. Para DM com convite clicavel ainda e necessario informar a URL `chat.whatsapp.com/...`.

## Scripts oficiais
- Base compartilhada: `scripts\start-cloudflare-tunnel.ps1`
- Wrapper DEV: `scripts\start-cloudflare-dev.ps1`
- Wrapper PROD: `scripts\start-cloudflare-prod.ps1`
- Docker DEV: `scripts\start-docker-dev.ps1`
- Docker DEV stop: `scripts\stop-docker-dev.ps1`
- Docker DEV status: `scripts\status-docker-dev.ps1`
- Docker PROD: `scripts\start-docker-prod.ps1`
- Docker PROD stop: `scripts\stop-docker-prod.ps1`
- Docker PROD status: `scripts\status-docker-prod.ps1`

## Estado validado em 2026-03-10
- O tunnel de producao foi religado apontando para o Docker PROD na porta `5005`.
- O link publico de producao foi validado externamente.
- O acesso publico indevido do ambiente atual no hostname principal foi desligado antes da religacao correta.

## Diagnostico do DEV Docker
- Container: `achadinhos-next-dev`
- Sintoma: reinicio em loop, sem abrir a `8081`.
- Causa objetiva encontrada em log:
  `Unable to resolve service for type 'AchadinhosBot.Next.Application.Abstractions.IMediaFailureLogStore' while attempting to activate 'AchadinhosBot.Next.Infrastructure.Telegram.TelegramUserbotService'.`
- Correcao aplicada no codigo:
  registro de `IMediaFailureLogStore` para `MediaFailureLogStore` no DI do `Program.cs`.
- Acao operacional pendente:
  rebuild/recreate do container DEV para aplicar a imagem com o ajuste.

## Checklist antes de subir tunnel

### Para PROD
1. Subir `start-docker-prod.ps1`.
2. Validar `status-docker-prod.ps1` e confirmar `achadinhos-next-prod` como `healthy`.
3. Validar `Invoke-WebRequest http://127.0.0.1:5005/health`.
4. Subir `start-cloudflare-prod.ps1`.
5. Validar externamente `https://achadinhos.reidasofertas.ia.br/dashboard`.

### Para DEV
1. Subir `start-docker-dev.ps1`.
2. Validar `status-docker-dev.ps1`.
3. Validar `Invoke-WebRequest http://127.0.0.1:8081/health` ou fallback equivalente.
4. Subir `start-cloudflare-dev.ps1`.
5. Validar externamente `https://achadinhos-dev.reidasofertas.ia.br/dashboard`.

## Comandos de referencia
```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\start-docker-prod.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\status-docker-prod.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\stop-docker-prod.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\start-docker-dev.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\status-docker-dev.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\stop-docker-dev.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\start-cloudflare-prod.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\start-cloudflare-dev.ps1
```
