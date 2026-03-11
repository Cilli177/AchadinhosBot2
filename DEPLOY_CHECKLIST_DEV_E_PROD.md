# Deploy Checklist

## DEV

1. Copiar `AchadinhosBot.Next/.env.example` para `AchadinhosBot.Next/.env`.
2. Preencher:
   - `WEBHOOK__API_KEY`
   - `AUTH__USERS__*__PASSWORDHASH`
   - `TELEGRAM__*`
   - `EVOLUTION__*`
   - `AFFILIATE__*`
3. Validar bloqueios de seguranca do ambiente:
   - `DELIVERYSAFETY__BLOCKOFFICIALWHATSAPPALWAYS`
   - destinos oficiais de WhatsApp e Telegram
4. Subir:
   - `docker compose -f docker-compose.yml -f docker-compose.dev.override.yml up -d --build`
5. Validar:
   - `http://localhost:8083/health`
   - `http://localhost:8083/conversor`
   - `http://localhost:8083/conversor-admin`

## Tunnel DEV

1. Subir:
   - `powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\start-cloudflare-dev.ps1`
2. Validar:
   - `https://achadinhos-dev.reidasofertas.ia.br/health`
   - `https://achadinhos-dev.reidasofertas.ia.br/conversor`
   - `https://achadinhos-dev.reidasofertas.ia.br/conversor-admin`

## PROD

1. Publicar segredos reais por variavel de ambiente ou secret store.
2. Nao usar `appsettings.json` como deposito de segredo operacional.
3. Garantir persistencia:
   - dados da aplicacao
   - midia em `/app/wwwroot/media/admin`
4. Validar:
   - `/health`
   - login admin
   - publicacao manual
   - agendamento
   - catalogo
   - analytics

## Tunnel PROD

1. Subir:
   - `powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\start-cloudflare-prod.ps1`
2. Se necessario, parametrizar:
   - `-TunnelName`
   - `-Hostname`
   - `-BioHostname`
3. Validar:
   - `https://achadinhos.reidasofertas.ia.br`
   - `https://bio.reidasofertas.ia.br`

## Antes De Deploy

1. Rodar:
   - `dotnet build AchadinhosBot.Next\AchadinhosBot.Next.csproj --no-restore`
   - `dotnet test AchadinhosBot.Next.Tests\AchadinhosBot.Next.Tests.csproj --no-restore`
2. Confirmar `git status` limpo, exceto `.env` local ignorado.
3. Confirmar que nenhum segredo entrou em commit.
4. Testar:
   - login admin/operator
   - draft sem catalogo
   - draft com catalogo `dev`
   - draft com catalogo `prod`
   - publicacao real controlada
   - agendamento com horario local do usuario
