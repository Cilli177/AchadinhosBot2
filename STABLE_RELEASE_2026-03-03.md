# Stable Release Notes - 2026-03-03

## Objetivo
Estabilizar os fluxos:
- Telegram (grupos origem) -> Telegram destino (`Rei Das Ofertas VIP`)
- Telegram (grupos origem) -> WhatsApp (`Rei Das Ofertas VIP`)
- Webhook Evolution sem perda total quando RabbitMQ indisponivel
- Bloqueio estrito de links nao afiliados/nao convertidos

## Problemas observados
- `TelegramUserbot` oscilando por erro de conectividade na sessao anterior (`SocketException 10013`).
- Mensagens de Telegram podiam ser bloqueadas indevidamente por dependencia de `TelegramForwarding.Enabled`, mesmo com rota Telegram->WhatsApp ativa.
- Timeout no check `/instance/connectionState/{instance}` da Evolution impedia envio ao WhatsApp.
- Fluxo de fallback anterior podia encaminhar texto original quando conversao falhava (risco de link nao afiliado passar).
- RabbitMQ indisponivel causava degradacao do webhook assíncrono.

## Mudancas aplicadas no codigo

### 1) Telegram routing and strict blocking
Arquivo: `AchadinhosBot.Next/Infrastructure/Telegram/TelegramUserbotService.cs`

- Roteamento Telegram->WhatsApp nao depende apenas de `TelegramForwarding.Enabled`:
  - Agora considera rotas ativas em `TelegramToWhatsAppRoutes`.
- Fonte valida para processamento:
  - Uniao de fontes de `TelegramForwarding`, `TelegramToWhatsApp` e `TelegramToWhatsAppRoutes`.
- Remocao do fallback de envio de texto original quando conversao falha:
  - O fluxo automatico agora bloqueia quando `TryGetStrictForwardText` falha.
  - Log explicito: `bloqueou encaminhamento automatico por conversao invalida ou nao afiliada`.

### 2) Evolution connection-state tolerant send
Arquivo: `AchadinhosBot.Next/Infrastructure/WhatsApp/EvolutionWhatsAppGateway.cs`

- `EnsureInstanceOpenForSendAsync` deixou de bloquear envio em falhas transitórias de health probe:
  - timeout no `connectionState`
  - erro de consulta de estado
  - estado vazio/intermitente
- Nesses casos, o gateway agora prossegue com tentativa real de envio.
- Continua bloqueando somente quando estado explicito indica desconexao (`state != open` com valor definido).

### 3) RabbitMQ fallback no webhook principal
Arquivo: `AchadinhosBot.Next/Program.cs`

- Endpoint `/webhook/bot-conversor`:
  - Tenta `publishEndpoint.Publish` normalmente (`mode=queue`).
  - Se publicar falhar (ex.: RabbitMQ fora), aplica fallback sincronizado:
    - POST interno para `/internal/webhook/bot-conversor`
    - Repassa payload e `x-api-key`
    - Retorna `mode=fallback-internal` quando sucesso.

## Validacoes executadas
- Build do projeto principal (`AchadinhosBot.Next.csproj`) em Debug/Release: OK apos restart.
- Health endpoint: `status=ok`.
- Logs confirmaram:
  - `TelegramUserbot conectado` e dialogs carregados.
  - Envio para WhatsApp voltou a ocorrer apos ajuste de timeout.
  - Bloqueio correto para links invalidos/não afiliados:
    - exemplos: `https://meli.la/2wmutFP`, `https://meli.la/2ZdV3sB`
    - comportamento: `ConvertedLinks=0` + bloqueio de encaminhamento automatico.

## Pendencias operacionais
- Existem eventos `401` em `POST /webhook/bot-conversor`.
- Isso indica divergencia de autenticacao webhook entre Evolution e app (`WebhookSecret`/`x-api-key`).
- Recomendado alinhar configuracao da Evolution com os segredos do app para eliminar perda de eventos webhook externos.

## Arquivos alterados nesta release
- `AchadinhosBot.Next/Infrastructure/Telegram/TelegramUserbotService.cs`
- `AchadinhosBot.Next/Infrastructure/WhatsApp/EvolutionWhatsAppGateway.cs`
- `AchadinhosBot.Next/Program.cs`
- `STABLE_RELEASE_2026-03-03.md`

