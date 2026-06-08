# Entrega - Story, catalogo, reels e ofertas ML - 2026-05-05

## Escopo

- Corrigir imagens ausentes no catalogo.
- Remover fallback para Google em ofertas antigas quando nao houver pagina de produto confiavel.
- Manter a imagem do catalogo original, sem a arte/edit do "link na bio" usada no story.
- Testar story Mercado Livre e sincronizacao com catalogo.
- Confirmar fluxo de reel apos correcoes de midia.
- Documentar o estado operacional antes de seguir para a campanha conversacional.

## Correcoes aplicadas

- Bio: link do WhatsApp atualizado para `https://chat.whatsapp.com/GosnHVUa2lE0nYGhO6an4x`.
- Catalogo: URLs internas do proprio catalogo/bio/item agora sao tratadas como links invalidos para produto.
- Catalogo: fallback generico para Google foi removido. Quando a loja e reconhecida, o fallback usa marketplace especifico; quando nao e reconhecida, nao cria link Google.
- Catalogo: imagens remotas deixam de ser reescritas para `/media/remote?url=...`; a pagina usa a URL original quando ela ja e publica.
- Catalogo: imagens sugeridas/originais agora tem prioridade na sincronizacao.
- Story ML: o draft guarda duas listas separadas:
  - `ImageUrls`: midia editada para publicacao no story.
  - `SuggestedImageUrls`: imagem original do produto para catalogo.
- Mercado Livre -> WhatsApp: a mensagem no grupo Rei das Ofertas nao leva comissao; a comissao fica somente na mensagem separada do grupo Mercado Livre.
- Story approvals: grupo configurado para `120363426166665839@g.us`.
- Reels: publicacao passou a usar `IInstagramPublishService`; tambem foi corrigido o mapeamento de midia local do Docker para `/app/wwwroot/media/admin`.

## Levantamento de links do catalogo

Antes da correcao, nao havia ofertas ativas salvas diretamente com `google.com/search`, mas havia 12 ofertas ativas apontando para paginas internas do Rei das Ofertas (`/catalogo`, `/item` ou `/bio`). Essas ofertas podiam cair no fallback de busca e abrir Google em vez da pagina do produto.

Depois da correcao e sincronizacao:

- Ofertas ativas no catalogo prod: 21.
- Ofertas ativas apontando para Google: 0.
- Ofertas ativas apontando para paginas internas do Rei das Ofertas: 0.
- Ofertas ativas sem `ImageUrl`: 0.
- HTML do catalogo: 21 imagens renderizadas, 0 `/media/remote?url=...`, 0 Google, sem mojibake detectado.

## Testes executados

- Build: `dotnet build AchadinhosBot2.sln`.
- Testes focados: `dotnet test AchadinhosBot.Next.Tests/AchadinhosBot.Next.Tests.csproj --filter "FullyQualifiedName~MercadoLivreStoryDraftServiceTests|FullyQualifiedName~MercadoLivreAffiliateScoutSettingsTests"`.
- Deploy prod: `docker compose -f docker-compose.prod.yml up -d --build achadinhos-next`.
- Health: `GET /health/ready` retornou `status=ok`.
- Sync catalogo: `POST /api/catalog/sync`.
- Story API: `POST /api/instagram/story/test` retornou `success=true`.
- Story publicado: draft `85e8b5ca806b4d7ea32b17760d760e45`, media id `18061817297463012`.
- Sync apos story: criado item de catalogo para o draft do story, item 25.
- Reel validado anteriormente apos correcao: draft `60d188d1fa664f6e9e8706b57f9df974`, media id `18006360362881789`, catalogo sincronizado.

## Observacoes operacionais

- O worker Mercado Livre rodou apos o deploy, encontrou 63 ofertas e colocou 24 ofertas na fila.
- Ele nao criou novos drafts de story neste ciclo porque os slots de story ML ja estavam ocupados por drafts existentes.
- A separacao de imagem original para catalogo ja esta em producao; ela sera observada nos proximos drafts novos criados pelo worker.
- O story de teste publicado neste fechamento usou um draft existente criado antes da separacao de imagens, por isso o item 25 ainda referencia a imagem editada antiga. Novos drafts passam a preencher `SuggestedImageUrls` com a imagem original.

## Proxima fase sugerida

- Campanha conversacional: revisar opt-in, segmentacao por nicho, variacoes de mensagem e respostas automaticas antes de novo disparo.
- Nichos: criar grupos por categoria com regras de curadoria e limite de frequencia por nicho.
- IA de atendimento: habilitar respostas contextualizadas com historico curto, classificacao de intencao e transferencia para humano quando houver duvida de compra, suporte ou reclamacao.
