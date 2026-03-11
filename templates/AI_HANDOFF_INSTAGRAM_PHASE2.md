# AI HANDOFF: FASE 2 - INTEGRAÇÃO INSTAGRAM (META GRAPH API)

Este documento descreve tecnicamente o que precisa ser feito para implementar a **Fase 2: O Novo Canal - Instagram**, finalizando o roteamento de postagens e o auto-reply (Bio Hub) via interface do bot.

## Contexto Atual
O sistema possui a modelagem do domínio (`InstagramPublishDraft`, `InstagramCommentPending`) e o `InstagramAutoPilotWorker` que roda periodicamente avaliando ofertas. A UI do Painel (Dashboard) já possui telas para gerenciamento do Instagram (Postagens, rascunhos, comentários) e os dados estão sendo salvos através de stores como `IInstagramPublishStore`.

Entretanto, **a conexão real com a Graph API da Meta não está efetivamente implementada para a publicação automática no Feed ou envio de comentários/Direct**. 

## Seu Objetivo (Codex)
Implementar o core de comunicação com a Graph API do Facebook/Instagram e amarrar isso às Interfaces e Controladores que servem ao Dashboard.

## Tarefas Técnicas

### 1. Implementação do MetaGraphClient
Criar ou completar a infraestrutura de comunicação HTTP com a Meta Graph API.
- **Autenticação**: Consumir os tokens configurados na UI/AppSettings (Short-Lived e Long-Lived Tokens).
- **Upload de Mídia**: O processo de postagem no Instagram via Graph API exige 2 passos: (1) Criar o container de mídia (Post/Reels/Stories) usando a URL Pública da Imagem. (2) Publicar o container.
- **Múltiplas Imagens (Carrossel)**: Se houver mais de uma imagem selecionada (`SelectedImageIndexes`), deve-se criar containers filhos e um container pai de carrossel.

### 2. Finalizar o Serviço de Publicação (IInstagramPublishService / InstagramPostComposer)
A rotina que pega o `InstagramPublishDraft` com `Status == "approved"` e o envia para o mundo real.
- Ler o draft armazenado, baixar ou construir as URLs públicas das imagens (já expostas pelo próprio bot ou de CDNs externas confiaveis).
- Executar a rotina do `MetaGraphClient`.
- Em caso de sucesso, marcar o Draft como "published", salvando o `MediaId` retornado pela Meta. Em caso de falha, assinalar o erro para refletir no Dashboard.

### 3. Implementação do Auto-Reply (Bio Hub / Comentários)
Lidar com o recebimento de Webhooks da Meta sobre novos comentários nas postagens.
- O Webhook controller precisará de uma rota (ex: `/webhook/meta` ou equivalente) validando o challenge `hub.verify_token`.
- Quando um evento `messages` ou `comments` chega, comparar o texto com a lista configurada de `Ctas` (Call-to-Action) daquele Post.
- Se a palavra-chave(`Keyword`) bater, o bot deve engatilhar uma resposta via DM (Send Message via Graph API) e possivelmente curtir o comentário original usando o `InstagramCommentStore` para persistência de estado (evitando respostas em loop).

### 4. Visibilidade para a Arquitetura Assíncrona (Fase 1)
O `InstagramAutoPilotWorker` atual avalia as ofertas de forma contínua e as coloca no `IInstagramPublishStore`. A rotina finalizadora (que vai realmente submeter ao Facebook) **deve** usar o MassTransit / Fila Outbound que estabilizamos na Fase 1, se possível. Se a API do Instagram der rate limit, a mensagem não se perde.
*Dica*: crie um comando similar ao `SendWhatsAppMessageCommand` => `PublishInstagramPostCommand` e um Consumer respectivo, ou gerencie isso via Worker dedicado (semelhante ao AutoPilotWorker).

## Validação e Critérios de Aceite
1. O painel web ("Testar Instagram") ou o fluxo isolado seja capaz de postar uma imagem genérica de teste (Simulado) na conta configurada (sandbox/teste no Meta for Developers).
2. Rate limits não congelam a aplicação (Worker assíncrono).
3. Resposta de Comentário a Keyword aciona log claro e simula DM na interface.

## Dicas Operacionais e Limitações
- Certifique-se de que URLs de imagem enviadas ao MetaGraph não sejam `localhost`, pois os servidores da Meta precisam fazer o download. O Kestrel rodando em DEV possui uma feature ou configuração ngrok associada? Fique de olho na `PublicBaseUrl`.
- A API da Meta costuma demorar. Jamais use tasks síncronas bloqueantes na porta do webhook de entrada.

**Quando finalizar a integração base do Graph API:** Retorne com um log simplificado relatando sucesso ou falhas no GraphAPI em um card DONE no `AI_COMMAND_QUEUE.md`.
