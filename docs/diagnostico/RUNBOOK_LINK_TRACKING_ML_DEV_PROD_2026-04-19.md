# Runbook de Links, Tracking e Scout do Mercado Livre

Data: 2026-04-19
Status: vigente
Escopo: fluxo de links rastreados, WhatsApp, relay `dev -> prod` e scout do Mercado Livre

## Objetivo

Este documento existe para evitar a repeticao dos erros que ja aconteceram no ambiente `dev` e no fluxo do Mercado Livre.

Ele deve permitir que qualquer operador, desenvolvedor ou outra IA:

- entenda qual e o fluxo correto do link final;
- saiba quais componentes participam da geracao do link;
- identifique rapidamente quando o sistema voltou a usar host errado, encurtador externo ou URL crua;
- saiba qual ambiente faz coleta e qual ambiente faz envio;
- saiba como proceder em caso de quebra.

## Regra de ouro

Para oferta publicada em WhatsApp, o link final aceito pelo sistema deve sair como:

`https://reidasofertas.ia.br/r/...`

Nao deve sair como:

- `https://achadinhos.reidasofertas.ia.br/...`
- `https://tinyurl.com/...`
- `https://bit.ly/...`
- `https://meli.la/...` como link final do grupo
- `https://www.mercadolivre.com.br/...` como link final do grupo

Observacao:

- `meli.la` e `mercadolivre.com.br` podem aparecer como entrada do pipeline.
- o destino publicado no grupo deve ser sempre o redirect oficial `/r/...` do dominio raiz.

## Fonte de verdade do dominio publico

Dominio oficial de tracking para usuario final:

`https://reidasofertas.ia.br`

Subdominio que nao deve ser usado como link final:

`https://achadinhos.reidasofertas.ia.br`

Uso esperado do subdominio:

- tunel
- operacao interna
- health
- debug historico

Nunca usar esse host como URL final enviada ao usuario.

## Erros historicos que ja aconteceram

### 1. Encurtador externo no caminho errado

Sintoma:

- mensagens saiam com `tinyurl`
- ou o link final rastreado apontava para host intermediario errado

Causa:

- o pipeline ainda permitia encurtador externo em caminhos que nao deveriam usar isso
- historicamente isso contaminou Mercado Livre e outros fluxos

Estado correto:

- para WhatsApp, o `TrackingLinkShortenerService` nao deve usar encurtador externo
- o link final deve ser construido no redirect oficial `/r/...`

### 2. Host errado no redirect publico

Sintoma:

- link convertido redirecionava para `achadinhos.reidasofertas.ia.br`
- o clique abria erro ou experiencia quebrada

Causa:

- mistura entre `PublicBaseUrl` do dominio raiz e o subdominio operacional

Estado correto:

- tracking publico sempre resolve para `https://reidasofertas.ia.br/r/...`

### 3. Worker do ML preferindo `ProductUrl` em vez de `SharedUrl`

Sintoma:

- primeira mensagem funcionava
- depois a mesma oferta passava a sair com link comprometido

Causa:

- o `MercadoLivreAffiliateScoutWorker` estava preferindo `ProductUrl`
- alem disso, havia logica de `Replace` que trocava o link oficial compartilhado pelo link cru do produto

Estado correto:

- para Mercado Livre, a prioridade e:
  - `SharedUrl`
  - depois `ProductUrl`
- o `SharedUrl` vem do modal `Compartilhar oferta`
- esse e o link mais confiavel para o fluxo afiliado do ML

### 4. Captura de preco pegando valor antigo ou parcela

Sintoma:

- a oferta anunciava preco antigo como se fosse promocional
- ou capturava valor de parcela em vez do preco atual

Causa:

- o scraper lia o primeiro `.andes-money-amount__fraction` do card
- alguns cards contem:
  - preco anterior
  - preco atual
  - valor da parcela

Exemplo real:

- preco anterior: `799,90`
- preco atual: `484,90`
- parcela: `53,88`

Estado correto:

- o scraper deve priorizar o bloco `.poly-price__current`
- montar valor com `fraction + cents`
- so usar fallback depois

### 5. Comparativo de precos sendo anexado em mensagem do ML

Sintoma:

- algumas mensagens de Mercado Livre recebiam um bloco extra:
  - `Comparativo de precos`
  - com links Amazon

Causa:

- o `WhatsAppPublishContentService` chamava `_messageProcessor.ProcessAsync`
- esse caminho pode enriquecer a mensagem com comparativo

Estado correto:

- para Mercado Livre, o pipeline de WhatsApp deve pular essa etapa
- ML deve sair limpo:
  - copy
  - link `/r/...`
  - comissao separada

## Arquivos-chave do fluxo

### Tracking e links

- `AchadinhosBot.Next/Application/Services/TrackingLinkShortenerService.cs`
- `AchadinhosBot.Next/Application/Services/AffiliateTrackedContentService.cs`
- `AchadinhosBot.Next/Application/Services/WhatsAppPublishContentService.cs`
- `AchadinhosBot.Next/Application/Services/OfficialWhatsAppGroupGuard.cs`
- `AchadinhosBot.Next/Infrastructure/Storage/LinkTrackingStore.cs`

### Mercado Livre

- `AchadinhosBot.Next/Infrastructure/MercadoLivre/MercadoLivreAffiliateScoutWorker.cs`
- `AchadinhosBot.Next/Infrastructure/MercadoLivre/MercadoLivreAffiliateScoutClient.cs`
- `mercadolivre-affiliate-scraper/server.js`

### Settings

- `AchadinhosBot.Next/Domain/Settings/AutomationSettings.cs`
- `AchadinhosBot.Next/Domain/Settings/AutomationSettingsSanitizer.cs`

### Envio e endpoints

- `AchadinhosBot.Next/Endpoints/AdminEndpoints.cs`

## Arquitetura operacional atual

### Coleta do Mercado Livre

Hoje a coleta funcional do ML acontece em `dev`.

Motivo:

- o scraper do ML em `prod` caiu repetidamente em desafio de login e recaptcha
- o `dev` conseguiu operar com sessao valida do navegador/perfil

### Envio para WhatsApp

Hoje o envio para o grupo e feito por `prod`.

Motivo:

- a integracao WhatsApp/Evolution funcional e a de `prod`
- o `dev` coleta
- o `prod` publica

### Relay `dev -> prod`

O `MercadoLivreAffiliateScoutWorker` pode usar relay para publicar pelo `prod`.

Campos relevantes em `MercadoLivreAffiliateScoutSettings`:

- `PublishViaProductionRelay`
- `ProductionRelayBaseUrl`
- `ProductionRelayAdminKey`
- `ProductionRelayInstanceName`

Configuracao usada na pratica:

- `PublishViaProductionRelay = true`
- `ProductionRelayBaseUrl = http://host.docker.internal:5005`
- `ProductionRelayAdminKey = dev-local-key`
- `ProductionRelayInstanceName = ZapOfertas`

## Regras de negocio do scout ML

Filtro vigente:

- comissao `>= 19%`
- ou preco `>= 99` com comissao `>= 12%`
- ou preco `>= 189` com comissao `>= 11%`
- ou preco `>= 325` com comissao `>= 7%`

Formato de envio:

1. mensagem principal da oferta
2. segunda mensagem separada com a comissao

Texto da comissao:

`💸 *Comissao desta oferta:* GANHOS XX%`

## Fluxo correto da oferta ML

1. scraper abre `Central de afiliados e criadores`
2. tenta clicar em `Ganhos extras`
3. coleta cards `li.poly-card`
4. extrai:
   - titulo
   - preco atual correto
   - comissao
   - imagem
5. abre `Compartilhar oferta`
6. captura o link do modal
7. salva esse link como `SharedUrl`
8. worker monta a mensagem usando `SharedUrl` antes de `ProductUrl`
9. `WhatsAppPublishContentService` prepara o conteudo
10. tracking transforma o link em `https://reidasofertas.ia.br/r/...`
11. grupo recebe:
   - mensagem principal
   - mensagem de comissao

## Invariantes que nao podem ser quebrados

Se qualquer uma destas regras falhar, o fluxo deve ser tratado como regressao:

1. mensagem final de oferta para WhatsApp deve conter `/r/...` do dominio raiz
2. grupo oficial nao pode aceitar `tinyurl`, `bit.ly`, `meli.la`, `mercadolivre...` ou `achadinhos.reidasofertas...`
3. worker ML deve usar `SharedUrl` antes de `ProductUrl`
4. scraper ML deve extrair preco atual, nao preco anterior nem parcela
5. mensagem ML nao deve receber bloco automatico de comparativo
6. comissao deve ir em segunda mensagem separada

## Sintomas e diagnostico rapido

### Sintoma: link abre erro

Verificar:

- a mensagem publicada contem `reidasofertas.ia.br/r/`
- ou contem `achadinhos.reidasofertas...`
- ou contem `tinyurl`
- ou contem `meli.la`

Conduta:

- se nao for `/r/...` oficial, o pipeline esta errado
- revisar `TrackingLinkShortenerService`
- revisar se houve bypass no `WhatsAppPublishContentService`

### Sintoma: primeira vez funcionou, depois quebrou

Verificar:

- se o worker ML voltou a preferir `ProductUrl`
- se houve nova geracao de tracking a partir de URL crua
- se o `SharedUrl` nao foi capturado

Conduta:

- conferir `BuildOfferMessage`
- conferir `GetOfferIdentityUrl`
- conferir se existe algum `Replace` promovendo URL crua

### Sintoma: preco do anuncio esta errado

Verificar:

- o HTML do card contem preco anterior e preco atual
- a captura esta vindo de `.poly-price__current`
- o valor anunciado coincide com o card do ML

Conduta:

- nunca confiar no primeiro `.andes-money-amount__fraction` genérico

### Sintoma: ML recebeu comparativo com Amazon

Verificar:

- se a mensagem passou por `_messageProcessor.ProcessAsync`
- se o bypass para Mercado Livre em `WhatsAppPublishContentService` continua presente

Conduta:

- para ML, pular o processamento de comparativo

## Procedimento de validacao antes de enviar

Checklist minimo:

1. a oferta passou no filtro de comissao/preco
2. o link veio da modal `Compartilhar oferta`
3. o preco capturado e o preco promocional atual
4. a mensagem preparada nao contem `Comparativo de precos`
5. o link final publicado e `/r/...`
6. a comissao sai em segunda mensagem

## Procedimento de smoke test

### Para validar link

1. publicar uma oferta de teste no grupo controlado
2. localizar o `MessageId` no `whatsapp-outbound-log.jsonl`
3. copiar o `/r/...`
4. abrir e conferir se redireciona para a loja correta

### Para validar preco

1. abrir o hub do ML
2. localizar o card
3. comparar:
   - preco anterior
   - preco atual
   - parcela
4. garantir que a mensagem usa o preco atual

### Para validar ausencia de comparativo

1. publicar uma oferta ML de teste
2. inspecionar o `Text` no log
3. garantir que nao existe o bloco:
   - `🔍 *Comparativo de preços*`

## Comandos uteis

### Health de prod

```powershell
Invoke-RestMethod http://127.0.0.1:5005/health | ConvertTo-Json -Depth 6
```

### Health de dev

```powershell
Invoke-RestMethod http://localhost:8081/health | ConvertTo-Json -Depth 6
```

### Ultimos logs de saida do WhatsApp em prod

```powershell
docker exec achadinhos-next-prod sh -lc "tail -n 20 /app/data/whatsapp-outbound-log.jsonl"
```

### Filtrar mensagens do grupo de teste

```powershell
docker exec achadinhos-next-prod sh -lc "grep '120363409272515351@g.us' /app/data/whatsapp-outbound-log.jsonl | tail -n 20"
```

### Logs recentes do app de prod

```powershell
docker logs achadinhos-next-prod --since 5m
```

### Logs recentes do app de dev

```powershell
docker logs achadinhos-next-dev --since 5m
```

### Rebuild de dev

```powershell
powershell -ExecutionPolicy Bypass -File scripts\start-docker-dev.ps1
```

### Rebuild de prod

```powershell
docker compose -f docker-compose.prod.yml up -d --build achadinhos-next
```

## Como proceder se outra IA pegar esse projeto

A IA futura deve seguir esta ordem:

1. confirmar qual ambiente coleta e qual publica
2. confirmar se o problema e:
   - tracking
   - host
   - `SharedUrl`
   - preco
   - comparativo
3. nunca assumir que `ProductUrl` e melhor que `SharedUrl` no ML
4. nunca reintroduzir `tinyurl` ou host `achadinhos.reidasofertas...` no caminho final
5. validar no log real antes de declarar correção concluida

## O que nao fazer

- nao usar `achadinhos.reidasofertas.ia.br` como link final
- nao usar encurtador externo em WhatsApp
- nao publicar `meli.la` como destino final do grupo
- nao extrair preco usando seletor generico sem priorizar o preco atual
- nao deixar o ML passar pelo comparativo automatico
- nao mudar `SharedUrl` para `ProductUrl` por conveniencia

## Estado esperado apos esta entrega

Para Mercado Livre:

- o scraper coleta preco correto
- o worker usa `SharedUrl`
- o WhatsApp publica `/r/...`
- a mensagem sai sem comparativo
- a comissao sai em segunda mensagem

Se algum desses itens deixar de acontecer, tratar como regressao e revisar este documento primeiro.
