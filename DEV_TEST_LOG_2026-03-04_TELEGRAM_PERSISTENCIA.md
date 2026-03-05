# DEV Test Log - 2026-03-04 - Persistencia Telegram (Userbot + Bot)

## Objetivo
Garantir persistencia de autenticacao no DEV para evitar novo login a cada restart/redeploy.

## Alteracoes aplicadas
- `TelegramUserbotService`:
  - sessao `WTelegram.session` agora padrao em `/app/data/WTelegram.session`.
- `TelegramBotApiGateway`:
  - token do bot e persistido em `/app/data/telegram-bot-token.txt` apos conexao valida.
  - leitura de token persistido quando env nao estiver preenchido.
- `TelegramBotPollingService`:
  - usa token resolvido de env/opcao/arquivo persistido.
  - nao encerra processo se token estiver ausente no startup; aguarda token aparecer.
- `Program.cs`:
  - bootstrap do worker do bot considera token persistido em arquivo.

## Deploy DEV
- Rebuild/recreate de `achadinhos-next-dev` com sucesso.
- `GET /health` retornando `200`.

## Evidencias em runtime
- Arquivo de sessao presente em volume persistente:
  - `/app/data/WTelegram.session`
- Arquivo de token do bot presente em volume persistente:
  - `/app/data/telegram-bot-token.txt`

## Resultado
- Persistencia tecnica aplicada no DEV.
- Reinicios do container passam a reutilizar sessao/token persistidos no volume.
