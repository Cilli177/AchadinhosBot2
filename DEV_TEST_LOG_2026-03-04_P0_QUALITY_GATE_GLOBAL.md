# DEV Test Log - 2026-03-04 - P0 Quality Gate Global Anti-Link-Cru

## Objetivo
Padronizar bloqueio estrito para envio automatico quando a conversao nao gerar link afiliado valido.

## Mudancas aplicadas
- Novo helper compartilhado:
  - `AchadinhosBot.Next/Application/Services/ForwardingSafety.cs`
  - regra: so permite forward quando `Success=true`, `ConvertedLinks>0` e `ConvertedText` nao vazio.
- Fluxos atualizados para usar a regra compartilhada:
  - `Program.cs`:
    - WhatsApp responder automatico
    - WhatsApp forwarding entre grupos/rotas
  - `TelegramBotPollingService.cs`:
    - Telegram bot responder automatico

## Validacao DEV
- Build Release: OK.
- Container DEV atualizado e ativo.
- `GET http://127.0.0.1:8081/health`: `200`.
- Evidencia de bloqueio em log:
  - `TelegramUserbot bloqueou encaminhamento automatico por conversao invalida ou nao afiliada`

## Resultado
- Fluxos automaticos revisados seguem sem fallback para link cru quando conversao falha ou nao comprova afiliacao.
