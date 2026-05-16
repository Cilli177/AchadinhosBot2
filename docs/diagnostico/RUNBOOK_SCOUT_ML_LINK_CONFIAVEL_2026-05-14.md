# Runbook - Scout Mercado Livre com link confiavel

Data: 2026-05-14

## Contexto

Os links obtidos pelo scout Mercado Livre via fluxo de compartilhamento do hub de afiliados ja chegam atribuídos corretamente para a conta do Rei das Ofertas.

Por isso, quando a origem for o scout ML, o sistema nao deve expandir, reconverter nem substituir o link capturado. A regra correta para esse fluxo e:

```text
link obtido pelo scout -> tracking interno /r/ML-* -> redireciona para o mesmo link obtido
```

Exemplo validado em PROD:

```text
Tracking: https://reidasofertas.ia.br/r/ML-015030
Location: https://meli.la/1yGxb5C
```

## Decisao tecnica

- Links do scout Mercado Livre sao tratados como confiaveis.
- O scout usa `PrepareTrustedLinksForSendAsync`.
- O tracking confiavel usa `TrackTrustedUrlAsync` e salva o target original, como `https://meli.la/...`.
- O redirect `/r/{id}` preserva `meli.la` quando o target veio de `whatsapp_grupo`.
- A protecao de reparo/conversao continua ativa para rotas nao confiaveis e para o grupo oficial.

## Arquivos principais

- `AchadinhosBot.Next/Application/Services/TrackingLinkShortenerService.cs`
  - `ApplyTrustedTrackingAsync`
  - `TrackTrustedUrlAsync`
- `AchadinhosBot.Next/Application/Services/WhatsAppPublishContentService.cs`
  - `PrepareTrustedLinksForSendAsync`
- `AchadinhosBot.Next/Infrastructure/MercadoLivre/MercadoLivreAffiliateScoutWorker.cs`
  - scout ML passou a usar o preparo confiavel
- `AchadinhosBot.Next/Program.cs`
  - redirect preserva `meli.la` confiavel de `whatsapp_grupo`

## Validacao realizada

- Build Docker de producao concluido com sucesso.
- Container `achadinhos-next-prod` recriado.
- `/health` retornou `status=ok`.
- Filas internas retornaram `pendingCount=0`.
- Teste de redirect:

```text
curl http://127.0.0.1:5005/r/ML-015030
HTTP/1.1 302 Found
Location: https://meli.la/1yGxb5C
```

## Observacoes operacionais

- O health geral do PROD esta saudavel.
- Ha avisos recorrentes `getUpdates falhou: Conflict`, indicando concorrencia no polling do bot Telegram. Isso nao travou as filas nem o WhatsApp, mas deve ser acompanhado.
- A Evolution mostrou `rate-overlimit` ao listar grupos em alguns momentos. O envio/health continuou operacional.

## Regra de manutencao

Nao usar `AffiliateTrackedContentService.RewriteAsync` no caminho de envio do scout ML quando o link foi obtido pelo botao de compartilhamento do hub afiliado.

Se futuramente o scout passar a capturar link de produto cru, sem fluxo de compartilhamento, esse caminho deve ser tratado como nao confiavel e voltar para conversao normal.
