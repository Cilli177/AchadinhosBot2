# Release Notes - 2026-03-04 (Estabilizacao PROD/DEV)

## Resumo
Este pacote consolida a estabilizacao operacional do AchadinhosBot com foco em:
- recuperacao da producao sem perda de configuracao;
- isolamento seguro entre DEV e PROD;
- padronizacao de deploy com backup obrigatorio;
- reducao de poluicao de logs locais.

## Itens principais
1. Recuperacao de producao com restauracao de dados/estado antigo.
2. Docker de producao com volumes fixos para evitar troca acidental de namespace.
3. Script oficial de deploy com backup automatico:
   - `scripts/deploy-prod.ps1`
4. Documento operacional de deploy:
   - `PRODUCAO_DEPLOY_COM_BACKUP.md`
5. Documento de integracao DEV com Evolution sem interferir na producao:
   - `EVOLUTION_DEV_SEM_IMPACTO_PROD.md`
6. Ajuste do fluxo de autenticacao do Telegram Userbot (2 etapas) e melhoria do dashboard para reduzir reconexao acidental.
7. Script de limpeza de logs:
   - `scripts/cleanup-logs.ps1`

## Padrao operacional aprovado
Deploy de producao sempre com:
```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\deploy-prod.ps1
```

Limpeza de logs local:
```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\cleanup-logs.ps1 -KeepRecent 3 -Apply
```

## Observacoes
- O backup de dados de producao criado durante a recuperacao ficou registrado como:
  - `achadinhos-prod_achadinhos_data_backup_20260304-154038`
- O legado `achadinhosbot2` foi removido do Docker para manter ambiente limpo.
