# Release Notes 2026-04-01

## Scope
- hardening do caminho canonico de producao com app e tunnel separados em Docker
- preflight explicito de credencial do tunnel antes de restart/deploy
- correcao do drift de RabbitMQ em producao via `.env.prod`
- evolucao da aba `Ofertas` de trilha auditavel para fluxo assistido real

## Production Hardening
- Producao passa a usar como caminho oficial:
  - app via `docker-compose.prod.yml`
  - tunnel via `docker-compose.tunnels.yml`
  - credenciais via `.env.prod`
- Scripts operacionais relevantes:
  - `scripts/start-docker-prod.ps1`
  - `scripts/start-docker-tunnel-prod.ps1`
  - `scripts/deploy-prod.ps1`
- Runbook publicado:
  - `PROD_TUNNEL_RECOVERY.md`

## Root Cause Fixed
- O tunnel PROD ja havia sido recuperado, mas a health publica ainda podia degradar por drift de configuracao de RabbitMQ.
- O compose de producao usa:
  - `RABBITMQ__USERNAME`
  - `RABBITMQ__PASSWORD`
- O `.env.prod` ainda estava com:
  - `RABBITMQ_DEFAULT_USER`
  - `RABBITMQ_DEFAULT_PASS`
- A rodada alinhou ambos os pares para remover a degradacao do `/health`.

## Offers Assisted Routing
- `Preview + revisao` continua sendo o comportamento default e seguro.
- `Catalogo` agora materializa drafts assistidos reais reaproveitando o fluxo atual de curadoria/catalogo.
- `Fila de automacao` agora gera um intento persistente e auditavel para automacao posterior.
- A UI da aba `Ofertas` foi ajustada para aceitar o shape real dos endpoints existentes sem quebrar o dashboard.
- O parsing de precos da normalizacao foi corrigido para JSON e CSV.

## Main Files
- `AchadinhosBot.Next/Application/Services/OfferNormalizationService.cs`
- `AchadinhosBot.Next/Application/Services/OfferNormalizationRoutingService.cs`
- `AchadinhosBot.Next/Application/Abstractions/IOfferAutomationIntentStore.cs`
- `AchadinhosBot.Next/Infrastructure/Storage/OfferAutomationIntentStore.cs`
- `AchadinhosBot.Next/Domain/Offers/OfferNormalizationModels.cs`
- `AchadinhosBot.Next/Program.cs`
- `AchadinhosBot.Next/StartupServiceRegistrationExtensions.cs`
- `AchadinhosBot.Next/wwwroot/dashboard.js`
- `AchadinhosBot.Next.Tests/OfferNormalizationRoutingServiceTests.cs`
- `AchadinhosBot.Tests/IntegrationTests/ConverterTests.cs`
- `.env.prod`

## Validation
- `dotnet build AchadinhosBot.Next/AchadinhosBot.Next.csproj -c Debug --no-restore`
- `dotnet test AchadinhosBot.Next.Tests/AchadinhosBot.Next.Tests.csproj --no-restore`
- `dotnet test AchadinhosBot.Tests/AchadinhosBot.Tests.csproj --no-restore`
- `http://127.0.0.1:5005/health` = `200`
- `https://achadinhos.reidasofertas.ia.br/health` = `200`
- `https://bio.reidasofertas.ia.br` = `200`
- `https://achadinhos-dev.reidasofertas.ia.br/dashboard` = `200`

## Limits
- O fluxo `Catalogo` continua assistido; esta rodada nao publica ofertas automaticamente.
- O fluxo `Fila de automacao` registra intentos auditaveis e reabertura operacional, mas nao executa envio autonomo ainda.
- Esta rodada nao introduz publicacao automatica irreversivel na aba `Ofertas`.

## Recommended Next Step
- revisar manualmente a aba `Ofertas` no DEV autenticado
- validar merge do PR limpo `ops: harden prod tunnel flow and add assisted offers routing`
- executar o checklist de release antes da promocao final
