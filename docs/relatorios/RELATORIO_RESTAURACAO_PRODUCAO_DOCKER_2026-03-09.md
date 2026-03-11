# RELATORIO DE RESTAURACAO DO AMBIENTE DOCKER DE PRODUCAO

## 1. Identificacao
- Data: 2026-03-09
- Ambiente: PROD
- Tipo: incidente operacional e recuperacao controlada
- Escopo: restauracao do stack Docker de producao sem perda de estado persistido

## 2. Sintoma observado
- Containers de producao do projeto nao estavam presentes no Docker.
- Havia risco de perda operacional caso o stack fosse recriado sem reaproveitar os volumes existentes.

## 3. Evidencias coletadas antes da restauracao
- Volume `achadinhos-prod_achadinhos_data` existente com arquivos de estado relevantes:
  - `WTelegram.session`
  - `automation-settings.json`
  - `conversion-logs.jsonl`
  - `mercadolivre-pending.json`
  - diretorio `media-store`
- Volume `achadinhos-prod_achadinhos_logs` existente com logs diarios de producao.
- Volume `achadinhos-prod_achadinhos_rabbitmq_data` existente com estado Mnesia e definicoes persistidas do broker.
- Imagem `achadinhos-next:prod` ainda disponivel localmente.

## 4. Acoes executadas
1. Inspecao de containers e volumes atuais.
2. Confirmacao de integridade basica dos volumes de `data`, `logs` e `rabbitmq`.
3. Backup manual adicional do volume `achadinhos-prod_achadinhos_rabbitmq_data`.
4. Execucao de `scripts/deploy-prod.ps1 -NoBuild -BackupLogs`.
5. Validacao do healthcheck local em `http://127.0.0.1:5005/health`.

## 5. Backups gerados
- `achadinhos-prod_achadinhos_rabbitmq_data_backup_20260309-173254`
- `achadinhos-prod_achadinhos_data_backup_20260309-173303`
- `achadinhos-prod_achadinhos_logs_backup_20260309-173303`

## 6. Resultado da recuperacao
- Container `achadinhos-rabbitmq` restaurado e saudavel.
- Container `achadinhos-next-prod` restaurado e saudavel.
- Endpoint `/health` respondendo com `status=ok`.
- Restauracao executada sem necessidade de recriar volumes de producao.

## 7. Ajuste de governanca aplicado
- O script oficial `scripts/deploy-prod.ps1` foi corrigido para incluir backup obrigatorio do volume de RabbitMQ antes de subir a producao.
- O documento `PRODUCAO_DEPLOY_COM_BACKUP.md` foi atualizado para refletir essa regra.

## 8. Riscos remanescentes
- O arquivo `.env.prod` ainda contem segredos sensiveis e deve continuar fora de qualquer compartilhamento indevido.
- Ainda e recomendavel validar funcionalmente os fluxos criticos de webhook, fila e entrega apos o incidente.

## 9. Proximo passo recomendado
1. Validar filas e exchanges do RabbitMQ de producao.
2. Executar smoke funcional minimo de webhook e encaminhamento.
3. Considerar automatizar um checklist de restauracao/rollback para PROD.
