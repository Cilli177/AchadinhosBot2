# Checklist Executavel de Promocao: DEV -> Shadow PROD -> PROD

Script: `scripts/governance-gate-validation.ps1`

## Objetivo
Executar validacoes operacionais de gate com autenticacao admin e gerar relatorio em Markdown em `docs/reports/`.

## Pre-requisitos
- Ambiente alvo rodando e acessivel por URL.
- Usuario admin valido no ambiente alvo.
- Endpoints ativos:
  - `/health`
  - `/auth/login`
  - `/api/admin/governance/status`
  - `/api/admin/governance/incidents`
  - `/api/admin/governance/actions`
  - `/api/admin/governance/tuning`
  - `/api/admin/canary/rules`

## Comandos

### Gate DEV
```powershell
pwsh ./scripts/governance-gate-validation.ps1 \
  -BaseUrl "http://localhost:8080" \
  -Username "admin" \
  -Password "SUA_SENHA" \
  -Stage dev
```

### Gate Shadow PROD
```powershell
pwsh ./scripts/governance-gate-validation.ps1 \
  -BaseUrl "https://seu-shadow-host" \
  -Username "admin" \
  -Password "SUA_SENHA" \
  -Stage shadow
```

### Gate PROD
```powershell
pwsh ./scripts/governance-gate-validation.ps1 \
  -BaseUrl "https://seu-prod-host" \
  -Username "admin" \
  -Password "SUA_SENHA" \
  -Stage prod
```

## O que o gate verifica
- Saude da aplicacao (`/health`).
- Login administrativo.
- Disponibilidade de endpoints de governanca.
- Thresholds basicos de estabilidade:
  - incidentes criticos abertos
  - acoes falhas em 24h
- Regras por estagio:
  - `shadow`: exige evidencia recente de acao simulada.
  - `prod`: exige ausencia de acao simulada e canario estabilizado.

## Saida
- Relatorio markdown: `docs/reports/gate-validation-<stage>-<timestamp>.md`
- Exit code:
  - `0` quando aprovado
  - `2` quando houver falhas de gate

## Promocao recomendada
1. Executar gate em DEV ate `PASS` consistente.
2. Executar gate em Shadow PROD e validar relatorio sem impacto indevido.
3. Promover para PROD somente com gate `PASS` e rollback validado.
