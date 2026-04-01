# Release Notes 2026-04-01

## Scope
- hardening do caminho canônico de produção com app e tunnel separados em Docker
- preflight explícito de credencial do tunnel antes de restart/deploy
- correção do drift de RabbitMQ em produção via `.env.prod`
- evolução da aba `Ofertas` de trilha auditável para fluxo assistido real

## Production Hardening
- Produção passa a usar como caminho oficial:
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
- O tunnel PROD já havia sido recuperado, mas a health pública ainda podia degradar por drift de configuração de RabbitMQ.
- O compose de produção usa:
  - `RABBITMQ__USERNAME`
  - `RABBITMQ__PASSWORD`
- O `.env.prod` ainda estava com:
  - `RABBITMQ_DEFAULT_USER`
  - `RABBITMQ_DEFAULT_PASS`
- A rodada alinhou ambos os pares para remover a degradação do `/health`.

## Offers Assisted Routing
- `Preview + revisão` continua sendo o comportamento default e seguro.
- `Catálogo` agora materializa drafts assistidos reais reaproveitando o fluxo atual de curadoria/catálogo.
- `Fila de automação` agora gera um intento persistente e auditável para automação posterior.
- A UI da aba `Ofertas` foi ajustada para aceitar o shape real dos endpoints existentes sem quebrar o dashboard.
- O parsing de preços da normalização foi corrigido para JSON e CSV.

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
- `.env.prod`

## Validation
- `dotnet build AchadinhosBot.Next/AchadinhosBot.Next.csproj -c Validation --no-restore /p:BaseIntermediateOutputPath=obj-validation\\ /p:BaseOutputPath=bin-validation\\`
- `dotnet test AchadinhosBot.Next.Tests/AchadinhosBot.Next.Tests.csproj --no-restore`
- `dotnet test AchadinhosBot.Tests/AchadinhosBot.Tests.csproj --no-build --no-restore`
- `http://127.0.0.1:5005/health` = `200`
- `https://achadinhos.reidasofertas.ia.br/health` = `200`
- `https://bio.reidasofertas.ia.br` = `200`
- `https://achadinhos-dev.reidasofertas.ia.br/dashboard` = `200`

## Limits
- O worktree atual continua com mudanças paralelas e não representa um pacote de release isolado.
- O PR aberto na branch atual precisa ser tratado como trilha provisória; o ideal é abrir um pacote limpo para:
  - `ops-prod-hardening`
  - `offers-assisted-routing`
- Esta rodada não introduz publicação automática irreversível na aba `Ofertas`.

## Recommended Next Step
- isolar o escopo desta rodada em um pacote limpo
- revisar manualmente a aba `Ofertas` no DEV autenticado
- só então promover merge/release formal
