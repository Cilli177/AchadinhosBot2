# AchadinhosBot.Next (sandbox de refatoração)

Projeto **isolado** para validar arquitetura sem impactar produção.

## Status atual (P0 + P1 + P2 iniciais)

### P0
- Minimal API + autenticação por cookie.
- Senhas com hash PBKDF2 (`pbkdf2$iterations$salt$hash`).
- Rate limit no endpoint de login e lockout após falhas consecutivas.
- Auditoria de ações sensíveis em `data/audit.log`.

### P1
- Integração WhatsApp via Evolution API (`/api/integrations/whatsapp/connect`).
- Webhook Evolution (`/webhooks/evolution`) com validação de assinatura HMAC (`x-signature`) e idempotência.
- Integração Telegram Bot API (`/api/integrations/telegram/connect`) com validação `getMe`.

### P2
- RBAC básico (`admin` e `operator`).
- Validação de regras automáticas (gatilho duplicado/campos obrigatórios).
- Playground de simulação (`/api/playground/preview`).
- Versionamento de configurações em `data/versions/`.

### Extra
- Healthcheck para deploy: `GET /health`.

## Rodar local (sem Docker)
```bash
dotnet run --project AchadinhosBot.Next/AchadinhosBot.Next.csproj
```

Acesse:
- `http://localhost:8081/`

## Rodar no GitHub Codespaces
No terminal do Codespace, execute na raiz do repositório:

```bash
# 1) Restaurar dependências e validar build
DOTNET_CLI_TELEMETRY_OPTOUT=1 dotnet restore AchadinhosBot2.sln
DOTNET_CLI_TELEMETRY_OPTOUT=1 dotnet build AchadinhosBot2.sln -c Release

# 2) Subir a API localmente
ASPNETCORE_ENVIRONMENT=Development dotnet run --project AchadinhosBot.Next/AchadinhosBot.Next.csproj --urls http://0.0.0.0:8081
```

Depois, na aba **Ports** do Codespaces, deixe a porta `8081` como pública (ou org/private, conforme necessidade) e abra no navegador.

### Comandos rápidos de verificação no Codespaces
```bash
# Healthcheck
curl http://127.0.0.1:8081/health

# Ver usuário autenticado (sem login deve retornar 401)
curl -i http://127.0.0.1:8081/auth/me
```

### Alternativa com Docker Compose no Codespaces
```bash
cp AchadinhosBot.Next/.env.example AchadinhosBot.Next/.env
# Preencha as variáveis obrigatórias em AchadinhosBot.Next/.env (hashes/senhas/tokens)
docker compose up -d --build
curl http://127.0.0.1:8081/health
```

## Rodar via Docker Compose
1. Copie o arquivo de exemplo:
```bash
cp AchadinhosBot.Next/.env.example AchadinhosBot.Next/.env
```
2. Suba os containers:
```bash
docker compose up -d --build
```
3. Abra:
- `http://localhost:8081/`
4. Verifique health:
```bash
curl http://localhost:8081/health
```

## Usuários de desenvolvimento
`appsettings.Development.json` contém:
- `admin / admin123`
- `operator / operator123`

## Endpoints
### Auth
- `POST /auth/login` (rate-limited)
- `POST /auth/logout`
- `GET /auth/me`

### Conversão
- `POST /converter` (header `x-api-key`)

### Webhook
- `POST /webhooks/evolution` (`x-signature` = HMAC SHA256 hex sobre body)

### API autenticada
- `GET /api/settings` (admin e operator)
- `PUT /api/settings` (admin)
- `POST /api/integrations/whatsapp/connect` (admin)
- `POST /api/integrations/telegram/connect` (admin)
- `POST /api/coupons/sync-official` (admin)
- `POST /api/playground/preview` (admin e operator)

## Variáveis de ambiente principais
- `Webhook__Port`
- `Webhook__ApiKey`
- `Auth__Users__0__Username`
- `Auth__Users__0__PasswordHash`
- `Auth__Users__0__Role`
- `Evolution__BaseUrl`
- `Evolution__ApiKey`
- `Evolution__InstanceName`
- `Evolution__WebhookSecret`
- `Telegram__BotToken`

## Cupons via API oficial (todas as lojas)
- Endpoint: `POST /api/coupons/sync-official`
- Body opcional:
```json
{
  "store": "Shopee"
}
```
- Sem `store`, sincroniza todos os providers oficiais configurados.
- Stores aceitas: `Amazon`, `Shopee`, `Shein`, `Mercado Livre`.

### ConfiguraÃ§Ã£o
No bloco `Affiliate`, configure cada loja:
- `AmazonOfficialCoupons`
- `ShopeeOfficialCoupons`
- `SheinOfficialCoupons`
- `MercadoLivreOfficialCoupons`
- `LinkTagging`

Cada bloco suporta:
- `Enabled`
- `Endpoint`
- `Method` (`GET`, `POST`, `PUT`, `PATCH`)
- `PayloadJson`
- `ApiKeyHeader`
- `ApiKey`
- `BearerToken`
- `Headers` (dicionÃ¡rio de headers extras)

### Rastreabilidade por tags em links afiliados
No bloco `Affiliate:LinkTagging`, configure:
- `Enabled`: ativa/desativa tags de rastreabilidade.
- `OverwriteExisting`: substitui `utm_*` existente quando estiver `true`.
- `IncludeStoreInCampaign`: adiciona a loja no `utm_campaign`.
- `Source`, `Medium`, `Campaign`, `Term`, `Content`: valores de UTM.
- `ExtraParams`: parametros adicionais customizados.

As tags sao aplicadas automaticamente nos links convertidos de Amazon, Mercado Livre, Shopee e Shein.

Mapeamento automatico de origem:
- `whatsapp` -> quando a conversao vem de fluxos com source contendo "whatsapp".
- `conversor_web` -> quando vem do endpoint do site conversor.
- `instagram_ofertas` -> quando vem de fluxos com source contendo "instagram".

Os valores sao aplicados em `ab_entry` e incorporados ao `utm_content`.

No endpoint `/api/conversor`, voce pode enviar `source` no body:
- `conversor_web` (padrao)
- `instagram_ofertas`
- `whatsapp`

Formato esperado no retorno JSON da API oficial:
- array de cupons no root, ou dentro de um campo (ex: `coupons`, `data.coupons`);
- cada item deve trazer ao menos um campo de cÃ³digo (`code`, `couponCode`, `promoCode`, `voucherCode`).

## Hospedagem gratuita (recomendação prática)

### Melhor equilíbrio grátis hoje
1. **Render Free** (rápido, simples, mas pode dormir)
2. **Koyeb Free** (bom para container)
3. **Oracle Cloud Free Tier (VM ARM)** (mais estável se você quer rodar 24/7 sem sleep, porém setup mais manual)

### Minha recomendação direta
- Para **teste rápido**: Render ou Koyeb.
- Para **manter no ar sem depender de créditos do Railway**: Oracle Free Tier com Docker Compose.

## Próximos passos sugeridos
- Persistir idempotência em Redis (não só memória).
- Substituir `CookieSecurePolicy.SameAsRequest` por `Always` em produção com HTTPS.
- Enriquecer auditoria com correlation-id.
- Adicionar testes automatizados de contrato para webhook e auth.


## Guia completo Oracle Cloud
- Veja o passo a passo detalhado em `ORACLE_CLOUD_DEPLOY.md`.
