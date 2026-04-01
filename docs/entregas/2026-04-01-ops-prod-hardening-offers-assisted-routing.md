# Entrega: Ops Prod Hardening + Offers Assisted Routing

## Objetivo
Transformar a recuperação de produção em procedimento operacional oficial e sair da fase “somente status” na aba `Ofertas`, conectando `Catálogo` e `Fila de automação` a efeitos reais e auditáveis.

## O que entrou
- hardening do tunnel e do app de produção com fluxo canônico explícito
- preflight operacional para credenciais de tunnel
- correção do drift de RabbitMQ que degradava a health pública
- store persistente para intentos de automação de ofertas
- roteamento assistido de runs normalizados para catálogo
- roteamento auditável de runs normalizados para fila posterior
- ajuste de compatibilidade do frontend com o shape atual dos endpoints
- testes unitários do roteamento assistido

## O que não entrou
- publicação automática de ofertas
- acoplamento direto das skills ao runtime de publicação
- limpeza completa do worktree ou separação de branch nesta mesma rodada

## Critérios de aceite executados
- produção saudável localmente e publicamente
- dashboard DEV público respondendo
- normalização continuando compatível com JSON e CSV
- `catalog` com materialização assistida real
- `queue` com persistência auditável real

## Evidências rápidas
- health local PROD: `200`
- health pública PROD: `200`
- bio pública PROD: `200`
- suíte `AchadinhosBot.Next.Tests`: verde
- suíte `AchadinhosBot.Tests`: verde

## Risco remanescente
- o repositório atual ainda acumula mudanças de outras frentes, então revisão e merge exigem cuidado extra para não promover escopo acidental.
