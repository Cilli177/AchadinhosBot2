# Relatorio de Deploy PROD: Hardening Automacao Afiliados

Data: 2026-05-28

## Resumo

Promocao de `origin/dev` para producao executada a partir de worktree limpo, sem incluir alteracoes locais nao aprovadas do checkout principal.

- Commit promovido: `3e160dc81fed4e8bc30c8ff79e45a2fc373aaa1e`
- Branch origem: `origin/dev`
- Worktree usado: `C:\AchadinhoBot2\prod-deploy-origin-dev-20260528`
- Script oficial: `scripts/deploy-prod.ps1 -BackupLogs`
- Resultado: estavel com observacao

## Pre-check

Antes do deploy:

- `achadinhos-next-prod`: `Up 6 hours (healthy)`
- `achadinhos-rabbitmq`: `Up 16 hours (healthy)`
- `/health`: HTTP 200, `status=ok`
- `/health/live`: HTTP 200, `status=ok`
- `/health/ready`: HTTP 200, `status=ok`
- Outboxes:
  - `bot-conversor=0`
  - `whatsapp=0`
  - `telegram=0`
  - `instagram=0`
- Workers reportados como saudaveis:
  - `BotConversorOutboxReplayWorker`
  - `WhatsAppOutboundReplayWorker`
  - `TelegramOutboundReplayWorker`
  - `InstagramOutboundReplayService`

Imagem antes do deploy:

- Container image: `sha256:695b9f6abe9637099542d66c1074318b11f42780398ce871589d718013353acd`
- Container started at: `2026-05-28T14:11:06.302870947Z`

## Backup e Deploy

Comando executado no worktree limpo:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\deploy-prod.ps1 -BackupLogs
```

Backups criados:

- RabbitMQ: `achadinhos-prod_achadinhos_rabbitmq_data_backup_20260528-165124`
- Logs: `achadinhos-prod_achadinhos_logs_backup_20260528-165124`

Observacao importante:

- O script informou que o volume `achadinhos-prod_achadinhos_data` nao existe neste host.
- Por isso, o backup de `data` foi ignorado pelo proprio script.
- O deploy prosseguiu com backup de RabbitMQ e logs.

Build/deploy:

- Imagem `achadinhos-next:prod` reconstruida com sucesso.
- Container `achadinhos-next-prod` recriado e iniciado.
- RabbitMQ permaneceu rodando e saudavel.

Imagem apos deploy:

- Image ID: `sha256:f3023acbab9131b11f59a09bbf9cf7b746cc3d98d77c5d7db3dfe5821bbb73bd`
- Created: `2026-05-28T19:53:17.981716909Z`
- Container started at: `2026-05-28T19:53:46.101956298Z`

## Observacao de 10 minutos

Janela observada: aproximadamente `19:53:46Z` ate `20:04:31Z`.

Resultado final:

- `achadinhos-next-prod`: `Up 10 minutes (healthy)`
- `achadinhos-rabbitmq`: `healthy`
- `/health`: HTTP 200, `status=ok`
- `/health/ready`: HTTP 200, `status=ok`
- RabbitMQ reachable: `true`
- Evolution ready: `true`
- Telegram userbot ready: `true`
- Outboxes finais:
  - `bot-conversor=0`
  - `whatsapp=0`
  - `telegram=0`
  - `instagram=0`

Evidencias funcionais:

- Links curtos seguiram respondendo 302:
  - `ML-W026544`
  - `ML-W026545`
  - `SP-W022934`
  - `AM-W009208`
  - `AM-C009209`
  - `AM-T009212`
- Roteamento de nichos registrou envios para:
  - `beleza`
  - `moda`
  - `casa`
  - `tech`
- Autopilot de story executou com sucesso:
  - `instagramPosted=True`
  - `catalogVerified=True`
  - `whatsappPosted=True`
- Webhooks `bot-conversor` continuaram respondendo 200.
- Mercado Livre continuou bloqueado no grupo oficial quando aplicavel, com motivo `mercado_livre_paused`.

Alertas observados:

- Evolution retornou `rate-overlimit` em algumas listagens de grupos, mas o sistema usou cache e manteve health OK.
- `InstagramLinkMetaService` registrou avisos ao tentar extrair meta de URL com scheme `file://`.
- Mercado Livre informou refresh token novo e solicitou atualizacao do `.env`.
- Um item de nicho `tech` ficou como `review_required`, comportamento esperado para casos sem confianca total.

## Decisao

Status: estavel com observacao.

Motivos:

- Servico principal e RabbitMQ permaneceram saudaveis.
- Health/readiness OK durante a janela.
- Outboxes permaneceram zeradas.
- Tracking curto `/r/{trackingId}` funcionou.
- Nichos e autopilot executaram.
- Nao houve erro fatal, crash, fila travada ou necessidade de rollback.

Observacoes que precisam acompanhamento:

- Confirmar se o volume `achadinhos-prod_achadinhos_data` foi substituido por outro volume/nome neste host ou se dados criticos estao em outro mount.
- Investigar e bloquear entrada `file://` em `InstagramLinkMetaService` para reduzir warnings.
- Atualizar/rotacionar refresh token Mercado Livre fora do codigo, via `.env.prod` ou secret store.
- Monitorar `rate-overlimit` da Evolution para ajustar intervalo/cache se crescer.

## Rollback

Rollback nao executado.

Se necessario, usar como base:

- RabbitMQ backup: `achadinhos-prod_achadinhos_rabbitmq_data_backup_20260528-165124`
- Logs backup: `achadinhos-prod_achadinhos_logs_backup_20260528-165124`
- Imagem anterior observada: `sha256:695b9f6abe9637099542d66c1074318b11f42780398ce871589d718013353acd`

Antes de qualquer rollback, confirmar o volume real de dados neste host, pois `achadinhos-prod_achadinhos_data` nao existia no momento do deploy.
