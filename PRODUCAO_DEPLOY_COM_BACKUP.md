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
3. Cria backup do volume de RabbitMQ de producao.
4. Sobe producao com:
   - `--env-file .env.prod`
   - projeto fixo `achadinhos-prod`
5. Exibe o nome dos volumes de backup criados.

## Opcoes
- `-BackupLogs`: inclui backup do volume de logs.
- `-NoBuild`: sobe sem rebuild da imagem.
- `-SkipBackup`: pula backup (usar apenas em emergencia).

## Volumes fixos de producao
- `achadinhos-prod_achadinhos_data`
- `achadinhos-prod_achadinhos_logs`
- `achadinhos-prod_achadinhos_rabbitmq_data`

## Regra operacional
- Backup de `data` e `rabbitmq` e obrigatorio antes de subir PROD.
- Backup de `logs` e recomendado via `-BackupLogs`.
- `-SkipBackup` so pode ser usado em emergencia declarada e com registro posterior do motivo.

Com isso, o volume nao muda mesmo que o comando use parametros diferentes.
