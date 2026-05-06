# Handoff Executivo: Links e Mercado Livre

Data: 2026-04-19
Status: ativo

## Resumo

O sistema de Mercado Livre hoje opera assim:

- `dev` coleta as ofertas
- `prod` envia para WhatsApp
- o link final publicado deve ser sempre `https://reidasofertas.ia.br/r/...`

## O que nunca pode voltar a acontecer

- usar `tinyurl`, `bit.ly` ou outro encurtador externo no WhatsApp
- publicar `achadinhos.reidasofertas.ia.br` como link final
- publicar `meli.la` ou `mercadolivre.com.br` como link final do grupo
- usar `ProductUrl` antes de `SharedUrl` no scout do ML
- capturar preco antigo ou parcela no lugar do preco atual
- anexar `Comparativo de preços` em mensagem do Mercado Livre

## Regras operacionais

### Link final correto

Sempre:

`https://reidasofertas.ia.br/r/...`

### Mercado Livre

Ordem correta da URL:

1. `SharedUrl`
2. `ProductUrl`

### WhatsApp

Mensagem do ML deve sair com:

1. oferta principal
2. segunda mensagem separada com a comissão

## Ambientes

### Dev

Responsável por:

- scraper do Mercado Livre
- sessão autenticada do hub afiliados
- coleta e filtro das ofertas

### Prod

Responsável por:

- envio real para WhatsApp
- tracking `/r/...`
- logs finais de outbound

## Arquivos mais importantes

- `AchadinhosBot.Next/Application/Services/TrackingLinkShortenerService.cs`
- `AchadinhosBot.Next/Application/Services/WhatsAppPublishContentService.cs`
- `AchadinhosBot.Next/Infrastructure/MercadoLivre/MercadoLivreAffiliateScoutWorker.cs`
- `mercadolivre-affiliate-scraper/server.js`
- `docs/diagnostico/RUNBOOK_LINK_TRACKING_ML_DEV_PROD_2026-04-19.md`

## Diagnóstico rápido

### Se o link quebrar

Verificar se a mensagem saiu com:

- `/r/...` oficial
- ou host errado
- ou URL crua

### Se o preço estiver errado

Verificar se o scraper pegou:

- preço atual
- e não preço anterior
- e não parcela

### Se aparecer comparativo indevido

Verificar se o ML passou pelo `_messageProcessor.ProcessAsync`

Para ML, isso deve ser pulado.

## Comandos úteis

### Health prod

```powershell
Invoke-RestMethod http://127.0.0.1:5005/health | ConvertTo-Json -Depth 6
```

### Health dev

```powershell
Invoke-RestMethod http://localhost:8081/health | ConvertTo-Json -Depth 6
```

### Últimos envios do grupo de teste

```powershell
docker exec achadinhos-next-prod sh -lc "grep '120363409272515351@g.us' /app/data/whatsapp-outbound-log.jsonl | tail -n 20"
```

## Fonte detalhada

Para detalhes técnicos completos, consultar:

`docs/diagnostico/RUNBOOK_LINK_TRACKING_ML_DEV_PROD_2026-04-19.md`
