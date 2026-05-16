# Relatorio de incidente - Conversao de links no grupo oficial

Data: 2026-05-13
Grupo auditado: `120363405661434395@g.us`
Janela analisada: 2026-05-13 08:44:23 a 14:44:23 UTC (05:44:23 a 11:44:23 BRT)
Fonte dos dados: `D:\Achadinhos\data\whatsapp-outbound-log.jsonl`, `D:\Achadinhos\data\link-tracking.json`, `D:\Achadinhos\data\conversion-logs.jsonl`

## Resumo

Foram encontradas 81 mensagens de oferta enviadas ao grupo oficial nas ultimas 6 horas analisadas.

| Status | Quantidade | Percentual |
| --- | ---: | ---: |
| Convertidas corretamente | 40 | 49,4% |
| Com problema de conversao/rastreio | 41 | 50,6% |
| Total | 81 | 100% |

## Por loja

| Loja | Total | Corretas | Com problema |
| --- | ---: | ---: | ---: |
| Mercado Livre | 55 | 22 | 33 |
| Amazon | 12 | 4 | 8 |
| Shopee | 9 | 9 | 0 |
| Unknown | 5 | 5 | 0 |

## Tipos de problema

| Problema | Quantidade |
| --- | ---: |
| Mercado Livre com `/r/` apontando para `meli.la`/`meli.co` | 29 |
| Amazon com `/r/` apontando para `amzn.to`, sem `tag=reidasofer022-20` no destino | 8 |
| Mercado Livre saiu sem `/r/` oficial, usando URL direta com `matt_tool`/`matt_word` | 4 |

Exemplos encontrados:

- `ML-014460` apontava para `https://meli.la/2EKsRSo`.
- `ML-009199` apontava para `https://meli.la/2QvX9M3`.
- `LK-001827` apontava para `https://amzn.to/4drqe9z`.
- Oferta ML do scout saiu com `https://produto.mercadolivre.com.br/MLB-2077892011?...matt_tool=98187057&matt_word=land177`.

## Logs de conversao na janela

Os logs de conversao nao representam todos os envios, apenas os casos em que o pipeline registrou tentativa de conversao.

| Loja | Tentativas registradas | Sucesso | Falha |
| --- | ---: | ---: | ---: |
| Mercado Livre | 8 | 8 | 0 |
| Shopee | 1 | 1 | 0 |
| Amazon | 6 | 6 | 0 |

Esse descolamento foi parte do problema: muitas mensagens ja chegavam com `/r/` antigo ou encurtador oficial e eram confiadas sem reabrir o destino real.

## Causa raiz

O problema voltou por tres caminhos combinados:

1. Links `/r/` ja existentes eram considerados seguros so por estarem no dominio oficial. O sistema nao reabria o registro de tracking para verificar se o `TargetUrl` ainda era um encurtador de afiliado externo, como `meli.la` ou `amzn.to`.
2. O `TrackingLinkShortenerService` tinha fallback perigoso: quando o `/r/` recem-criado nao respondia no teste publico de resolucao, ele devolvia a URL crua de destino. Em superficie WhatsApp isso podia publicar link direto no grupo.
3. O `MercadoLivreAffiliateScoutWorker` enviava pelo gateway/fila propria e nao passava pelo mesmo guard do grupo oficial usado em outras rotas administrativas.

## Correcao aplicada em PROD

Hotfix publicado em 2026-05-13:

- `AffiliateTrackedContentService` agora repara links `/r/` oficiais antes do envio. Se o tracking aponta para alvo conversivel (`meli.la`, `amzn.to`, Shopee, ML etc.), ele reconverte com afiliado oficial e gera novo `/r/`.
- `TrackingLinkShortenerService` nao devolve mais URL crua quando a superficie e WhatsApp. Se o teste publico do `/r/` falhar, mantem o `/r/` por seguranca e registra warning.
- `OfficialWhatsAppGroupGuard` agora aceita como link de oferta convertido somente `/r/` do dominio `reidasofertas.ia.br`; `tinyurl` e `shope.ee` nao contam mais como conversao valida para o grupo oficial.
- `MercadoLivreAffiliateScoutWorker` agora chama o guard oficial antes de enfileirar envio para o grupo `REI DAS OFERTAS VIP`. Se nao houver `/r/` oficial e imagem valida, a oferta e bloqueada.

## Validacao

- Build do projeto principal: sucesso.
- Build do projeto de testes: sucesso, apesar do comando ter extrapolado o timeout apos compilar.
- Testes focados executados com binario compilado: 16 aprovados, 0 falhas.
- Deploy PROD concluido.
- Backup RabbitMQ criado: `achadinhos-prod_achadinhos_rabbitmq_data_backup_20260513-121937`.
- Readiness PROD apos deploy: OK.
- Outboxes apos deploy: `bot-conversor=0`, `whatsapp=0`, `telegram=0`, `instagram=0`.

## Proximo monitoramento

Reexecutar a auditoria sobre mensagens novas pos-hotfix quando houver novo volume no grupo oficial. O criterio esperado e:

- 100% dos envios de oferta ao grupo oficial contendo `https://reidasofertas.ia.br/r/...`.
- Nenhum `TargetUrl` de Mercado Livre apontando para `meli.la`/`meli.co`.
- Nenhum `TargetUrl` de Amazon apontando para `amzn.to` sem a tag oficial.
- Nenhuma oferta do scout ML publicada com URL direta de marketplace.

## Addendum - 2026-05-13 12:42 BRT

O link `https://achadinhos.reidasofertas.ia.br/r/ML-014623` ainda abria destino incorreto porque o registro persistido tinha:

- `TargetUrl=https://meli.la/2wA3gUk`
- Ao expandir, o Mercado Livre redirecionava para `social/agenciarice` com `matt_tool=85935425`.

Correcoes adicionais aplicadas:

- Conversao Mercado Livre nao aceita mais URL `social/*` sem `MLB-ID` confiavel como conversao valida.
- Tracking nao cria mais `/r/` para Mercado Livre social/curto sem produto identificado.
- Redirect `/r/{id}` tenta reparar o destino no clique; se nao conseguir reparar com afiliado oficial, bloqueia o envio para afiliado de terceiros e manda para o hub.
- Registro `ML-014623` corrigido em `link-tracking.json` para `https://www.mercadolivre.com.br/p/MLB54482679?matt_tool=98187057&matt_word=land177`.
- Backup do arquivo antes da correcao: `D:\Achadinhos\data\link-tracking.json.backup-20260513-154218`.

Validacao:

- `GET /r/ML-014623` retorna `302` para `https://www.mercadolivre.com.br/p/MLB54482679?matt_tool=98187057&matt_word=land177`.
- PROD `/health/ready`: OK.

## Addendum - 2026-05-13 13:55 BRT

Revisao feita com base na documentacao interna de tracking ML:

- `docs/diagnostico/RUNBOOK_LINK_TRACKING_ML_DEV_PROD_2026-04-19.md`
- `docs/entregas/HANDOFF_EXECUTIVO_LINKS_ML_DEV_PROD_2026-04-19.md`
- `templates/AI_HANDOFF_ML_MELI_LA_FIX.md`

Regras reforcadas no codigo:

- Link final de Mercado Livre no tracking nao pode ser `social/*`, `meli.la` ou `meli.co`.
- URL ML so e considerada afiliada quando for produto/catálogo com `matt_tool` e `matt_word` oficiais.
- Se o link ML tiver `matt_tool`/`matt_word` de outro afiliado, os parametros sao substituidos pelos oficiais.
- Links sociais do ML passam a ser tratados como entrada a resolver: se houver CTA/redirect confiavel para produto, converte para URL canonica com afiliado oficial; se nao houver produto confiavel, aborta.
- Expansao de curto/social ML passou a usar `IHttpClientFactory`, mantendo o caminho testavel e consistente com a configuracao da aplicacao.

Validacao local:

- Build do projeto principal: sucesso.
- Build do projeto de testes: sucesso.
- Testes focados: 43 aprovados, 0 falhas.

Estado operacional:

- Deploy PROD concluido.
- Backup RabbitMQ criado: `achadinhos-prod_achadinhos_rabbitmq_data_backup_20260513-142926`.
- Container `achadinhos-next-prod`: healthy.
- PROD `/health/live`: OK.
- PROD `/health/ready`: OK; outboxes `bot-conversor=0`, `whatsapp=0`, `telegram=0`, `instagram=0`.
- `MercadoLivreAffiliateScout.Enabled=false`.
- `MercadoLivreAffiliateScout.AutoPublishToOfficialGroup=false`.
- Rota `Ponte Mercado Livre Scout`: `Enabled=false`.
- `GET /r/ML-014623` retorna `302` para `https://www.mercadolivre.com.br/p/MLB54482679?matt_tool=98187057&matt_word=land177`.
- Mercado Livre permanece pausado para envios oficiais ate nova auditoria e liberacao manual.

## Addendum - 2026-05-13 14:45 BRT

Novo sintoma reportado: links `https://reidasofertas.ia.br/r/LK-*` estavam sendo enviados ao grupo, escondendo destinos sem conversao adequada.

Causa identificada:

- O guard do grupo oficial aceitava qualquer URL `/r/` do dominio oficial como link rastreado.
- `LK-*` e prefixo generico do `LinkTrackingStore`, usado quando a loja/destino nao e reconhecido como Amazon, Shopee, Mercado Livre, Shein, Magalu, Americanas ou AliExpress.
- Exemplos recentes em `link-tracking.json` mostravam `LK-*` apontando para `amzn.to`, `amzlink.to` e `compre.link`, com `Store=unknown`.

Correcao aplicada localmente:

- `OfficialWhatsAppGroupGuard` agora bloqueia qualquer `reidasofertas.ia.br/r/LK-*` para o grupo oficial com motivo `generic_tracking_link`.
- `TrackingLinkShortenerService` agora bloqueia criacao de tracking generico `LK-*` para superficies WhatsApp. Se o destino resolvido ainda geraria `LK-*`, o tracking nao e criado e o envio posterior fica sem `/r/`, sendo bloqueado pelo guard oficial.
- Testes adicionados para `LK-*`, `amzn.to`, `amzlink.to` e `compre.link`.

Validacao local:

- Build do projeto principal: sucesso.
- Build do projeto de testes: sucesso.
- Testes focados: 47 aprovados, 0 falhas.

Estado operacional:

- Containers PROD permanecem desligados por decisao operacional do admin ate liberacao da correcao em producao.

## Addendum - 2026-05-13 23:05 BRT

Novo sintoma reportado apos primeira subida: links continuavam sem conversao, inclusive Shopee preservando link da oferta do grupo originario.

Causa adicional identificada:

- O caminho principal do webhook de forwarding ainda usava um helper legado `ApplyTrackingAsync` em `Program.cs`.
- Esse helper criava tracking direto no `ILinkTrackingStore` via `GetOrCreateAsync(url)`, sem passar por `AffiliateTrackedContentService` nem pelas novas validacoes do `TrackingLinkShortenerService`.
- Por isso, mesmo com o guard bloqueando o envio final para o grupo oficial, ainda era possivel criar `LK-*` novo para encurtadores/origens como `compre.link`.

Correcoes aplicadas:

- `WhatsAppPublishContentService` passou a usar `AffiliateTrackedContentService.RewriteAsync` tambem quando `MessageProcessor.ProcessAsync` retorna sucesso.
- O forwarding principal em `Program.cs` passou a reescrever por destino com `AffiliateTrackedContentService.RewriteAsync`, usando `whatsapp_grupo_oficial` para grupo oficial e `whatsapp_grupo` para demais grupos.
- `TrackingLinkShortenerService` bloqueia criacao de slug generico `LK-*` globalmente, nao apenas em superficies WhatsApp.

Validacao:

- Build Docker PROD compilou com sucesso (`dotnet publish` dentro da imagem).
- PROD foi pausado ao detectar `LK-002025` depois da primeira subida.
- Segunda subida feita com imagem recompilada.
- Health PROD `/health/live`: OK.
- Health PROD `/health/ready`: OK.
- Corte de monitoramento `2026-05-14T02:02:40Z`: `LK-*` novos = 0.
- Tracking novo observado apos o corte: `ML-014983`, `Store=Mercado Livre`, `OriginSurface=whatsapp_grupo`, destino com `matt_tool=98187057` e `matt_word=land177`.
- Segunda janela de observacao: 3 trackings novos, `LK-*` novos = 0.
- Shopee observado apos o corte: `SP-016340`, `Store=Shopee`, `OriginSurface=whatsapp_grupo_oficial`, destino `s.shopee.com.br`.
- Mercado Livre para grupo oficial observado apos o corte: `ML-014984`, destino com tags oficiais e bloqueado pelo guard com motivo `mercado_livre_paused`.
- Link Magalu/`magazinevoce` sem conversao confiavel foi bloqueado antes do envio oficial com motivo `no_tracked_offer_link`.
