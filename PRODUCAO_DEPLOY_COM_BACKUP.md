# Deploy de Producao com Backup

## Objetivo
Garantir que toda subida de versao em producao tenha backup antes do deploy.

## Script oficial
`scripts/deploy-prod.ps1`

## Comando padrao
```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\deploy-prod.ps1
```

## O que o script faz
1. Valida `docker`, `.env.prod` e `docker-compose.prod.yml`.
2. Cria backup do volume de dados de producao.
3. Sobe producao com:
   - `--env-file .env.prod`
   - projeto fixo `achadinhos-prod`
4. Exibe o nome do volume de backup criado.

## Opcoes
- `-BackupLogs`: inclui backup do volume de logs.
- `-NoBuild`: sobe sem rebuild da imagem.
- `-SkipBackup`: pula backup (usar apenas em emergencia).

## Volumes fixos de producao
- `achadinhos-prod_achadinhos_data`
- `achadinhos-prod_achadinhos_logs`
- `achadinhos-prod_achadinhos_rabbitmq_data`

Com isso, o volume nao muda mesmo que o comando use parametros diferentes.
