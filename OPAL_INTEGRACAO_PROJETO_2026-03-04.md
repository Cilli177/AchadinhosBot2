# Pesquisa e Integracao do OPAL no Projeto

Data: 2026-03-04
Ambiente alvo inicial: DEV
Objetivo: avaliar e definir integracao do OPAL para criacao de posts/stories e alimentacao de catalogo/site.

## 1) Resumo executivo

O OPAL deve entrar no projeto como camada de geracao assistida de conteudo, sem virar dependencia critica de runtime da publicacao.

Motivos:
- produto no-code/experimental;
- uso orientado a mini-app compartilhavel;
- na documentacao consultada nao ha API publica server-to-server de execucao/gestao.

Decisao recomendada:
- OPAL gera saida estruturada;
- backend atual valida (afiliacao, anti-link-cru, compliance) e publica;
- producao continua protegida por aprovacao e backup.

## 2) Evidencias da pesquisa (fontes oficiais)

1. Google for Developers - Opal Overview
`https://developers.google.com/opal/overview`
- Steps, tools, outputs, historico/versionamento no Drive.
- Cita exportacao para planilha no Drive.

2. Google for Developers - Opal FAQ
`https://developers.google.com/opal/faq`
- Opal privado por padrao.
- Compartilhamento pode expor prompts/graph.
- Compartilhar Opal compartilha arquivo no Drive.

3. Google Blog - Opal no Gemini web app
`https://blog.google/innovation-and-ai/models-and-research/google-labs/mini-apps-opal-gemini-app-experiment/`
- OPAL integrado ao Gemini web app e editor avancado em `opal.google`.

4. Google Blog - expansao do OPAL
`https://blog.google/innovation-and-ai/models-and-research/google-labs/opal-expansion-160/`
- disponibilidade expandida e casos de uso de automacao.

5. Google Developers Blog - Introducing OPAL
`https://developers.googleblog.com/introducing-opal/`
- reforca carater experimental/no-code.

## 3) Integracao proposta para nosso stack

Padrao: `OPAL -> fonte estruturada -> ingestao backend -> quality gates -> aprovacao -> publicacao`.

## 3.1 Componentes

1. `Opal Content Producer` (externo)
- gera copy de post/story/catalogo com campos padronizados.

2. `Opal Ingestor` (novo no backend)
- le linhas de planilha/export;
- normaliza em DTO interno.

3. `Quality Gate` (existente)
- conversao afiliada;
- bloqueio de link cru;
- validacao minima de campos.

4. `Approval + Publish` (existente)
- reaproveita fluxo atual de drafts/publicacao.

## 3.2 Mapeamento no codigo atual (onde integrar)

Pontos para receber e processar conteudo:
- `AchadinhosBot.Next/Program.cs` (registro de servicos e endpoints).
- `AchadinhosBot.Next/Infrastructure/Storage/InstagramPublishStore.cs` (persistencia de drafts).
- `AchadinhosBot.Next/Infrastructure/Storage/CatalogOfferStore.cs` (catalogo/site).
- `AchadinhosBot.Next/Infrastructure/Content/ContentCalendarAutomationService.cs` (automacao de conteudo e publicacao).
- `AchadinhosBot.Next/Application/Services/AffiliateLinkService.cs` (validacao/conversao de link afiliado).
- `AchadinhosBot.Next/Application/Services/ForwardingSafety.cs` (gate anti-link-cru global).

Implementacao minima sugerida:
- criar `Infrastructure/Content/Opal/OpalSheetIngestionService.cs`;
- criar endpoint admin DEV para import controlado (dry-run + commit);
- salvar como draft no `InstagramPublishStore`;
- sync no `CatalogOfferStore` so apos aprovacao.

## 3.3 Contrato minimo de dados (por item)

Obrigatorios:
- `source_id`
- `created_at`
- `product_name`
- `store`
- `original_url`
- `candidate_affiliate_url`
- `suggested_caption`
- `suggested_story_text`
- `image_url`
- `price_text`
- `status` (`draft|approved|rejected`)

Regras:
- URL final so segue se conversao `success=true` e `isAffiliated=true`;
- caso inconclusivo, bloquear e registrar motivo estruturado.

## 4) Riscos e mitigacoes

1. Exposicao de prompts ou regra de negocio no compartilhamento
- mitigar com compartilhamento restrito e controle de permissao no Drive.

2. Mudanca de comportamento de produto experimental
- mitigar com adaptador desacoplado (import de fonte estruturada) e fallback manual.

3. Conteudo fora do padrao comercial
- mitigar com gate tecnico + aprovacao humana antes de publicar.

## 5) Plano de execucao em DEV (sem impacto em PROD)

Fase A - Spike (2-3 dias)
1. Criar 1 OPAL de post e 1 OPAL de story.
2. Padronizar saida em planilha.
3. Fechar schema final.

Fase B - Integracao minima (3-5 dias)
1. Implementar `OpalSheetIngestionService`.
2. Criar importador DEV (`dry-run` e `apply`).
3. Mapear para drafts.
4. Aplicar gates de afiliacao e anti-link-cru.

Fase C - Validacao operacional (2-3 dias)
1. Rodar lote de 20 itens em DEV.
2. Medir:
- taxa de aprovacao;
- tempo de postagem;
- bloqueios por gate.
3. Decidir Go/No-Go para automacao ampliada.

## 6) Criterio para promover a PROD

Somente apos:
- validacao DEV concluida;
- documentacao do push e evidencias;
- aprovacao explicita de backup/deploy.

## 7) Observacao tecnica importante

Inferencia da pesquisa oficial: nao foi encontrada API publica de execucao/gestao do OPAL para integracao server-to-server.
Se houver anuncio oficial dessa API, reavaliar arquitetura para integracao direta.
