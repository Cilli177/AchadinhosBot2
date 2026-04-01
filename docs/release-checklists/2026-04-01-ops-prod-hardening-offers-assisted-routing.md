# Checklist de Merge e Release

## Escopo
- PR limpo: `ops: harden prod tunnel flow and add assisted offers routing`
- foco: hardening operacional de producao + roteamento assistido real da aba `Ofertas`

## Pre-merge
- confirmar que o PR esta restrito ao escopo de:
  - producao (`.env.prod`, scripts, runbook)
  - normalizacao/roteamento de ofertas
  - testes e docs relacionados
- revisar diff de `Program.cs` apenas nas partes de DI/rotas de `Ofertas`
- revisar se `dashboard.js` muda apenas a aba `Ofertas`
- confirmar que nao ha assets temporarios, dumps ou artefatos locais no pacote

## Validacao tecnica
- `dotnet build AchadinhosBot.Next/AchadinhosBot.Next.csproj -c Debug --no-restore`
- `dotnet test AchadinhosBot.Next.Tests/AchadinhosBot.Next.Tests.csproj --no-restore`
- `dotnet test AchadinhosBot.Tests/AchadinhosBot.Tests.csproj --no-restore`
- `http://127.0.0.1:5005/health` = `200`
- `https://achadinhos.reidasofertas.ia.br/health` = `200`
- `https://bio.reidasofertas.ia.br` = `200`
- `https://achadinhos-dev.reidasofertas.ia.br/dashboard` = `200`

## Validacao funcional
- abrir a aba `Ofertas` no DEV autenticado
- colar JSON valido e verificar preview + historico
- colar CSV simples e verificar preview + historico
- rotear um run para `Preview + revisao`
- rotear um run para `Catalogo` e confirmar materializacao assistida
- rotear um run para `Fila de automacao` e confirmar intento persistente

## Promocao
- garantir `cloudflared-prod` sem erro de credencial ausente
- garantir `.env.prod` com `RABBITMQ__USERNAME` e `RABBITMQ__PASSWORD` alinhados
- se houver restart, subir:
  - app via `scripts/start-docker-prod.ps1`
  - tunnel via `scripts/start-docker-tunnel-prod.ps1`
- em incidente de borda/tunnel, seguir `PROD_TUNNEL_RECOVERY.md`

## Pos-release
- confirmar `health` publica de producao
- confirmar `bio.reidasofertas.ia.br` aberta
- confirmar aba `Ofertas` em DEV ainda funcional
- publicar update operacional no Slack com:
  - status da producao
  - link do PR
  - escopo entregue
  - risco remanescente
