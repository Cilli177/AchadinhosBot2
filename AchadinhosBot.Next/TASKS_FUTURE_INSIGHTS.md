# Tasks e Future Insights (2026-03-03)

## Revisao tecnica (implementacoes recentes)
- Build quebrado no fluxo DeepSeek por acesso a metodos `private` de `OpenAiInstagramPostGenerator`.
- Risco de `NullReferenceException` no DeepSeek ao usar `images.Count` quando `images` for nulo.
- Dependencia `SixLabors.ImageSharp` em versao com advisories de seguranca.
- `wwwroot/debug_social.html` contem dados sensiveis (csrf token, user ip, request ids) e deve ser sanitizado.

## Melhorias priorizadas
1. Corrigir compilacao do DeepSeek com helper compartilhado para funcoes comuns.
2. Blindar nullability dos geradores OpenAI/Gemini/DeepSeek.
3. Atualizar `ImageSharp` para versao sem vulnerabilidades conhecidas.
4. Remover ou anonimizar artefatos de debug sensiveis.
5. Adicionar testes para comandos manuais de autopilot (`/story <link>` e `/post <link>`).

## Funcionalidades de alto impacto
1. Aprovacao de drafts por botoes inline no Telegram.
2. Scorecard por provider de IA (latencia, custo, qualidade).
3. Idempotencia para execucoes manuais por URL.
4. Janela inteligente de postagem por canal/horario.
5. Auditoria explicita de decisao do autopilot.

## Implementacao iniciada: tags de rastreabilidade em links
- Adicionado bloco `Affiliate:LinkTagging` para configurar UTM e parametros extras.
- Aplicacao automatica no `AffiliateLinkService` para links de Amazon, Mercado Livre, Shopee e Shein.
- Suporte a:
  - `Enabled`
  - `OverwriteExisting`
  - `IncludeStoreInCampaign`
  - `Source`, `Medium`, `Campaign`, `Term`, `Content`
  - `ExtraParams`
- Mapeamento de ponto de entrada implementado:
  - `whatsapp`
  - `conversor_web`
  - `instagram_ofertas`

## Proximo passo recomendado
- Expor no painel web os campos de `LinkTagging` para ajuste sem editar `appsettings`.
