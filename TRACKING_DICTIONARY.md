# Dicionario de Rastreabilidade (UTM + AB Tags)

## Objetivo
Padronizar tags de rastreabilidade para todos os links gerados pelo bot, com foco em:
- atribuicao por canal;
- atribuicao por superficie (grupo, DM, story, site);
- leitura consistente em relatorios.

## Campos obrigatorios
1. `ab_source`
2. `ab_channel`
3. `ab_surface`
4. `ab_content_id`
5. `ab_store`

## Campos recomendados
1. `ab_placement`
2. `ab_creator`
3. `ab_format`
4. `ab_campaign_id`
5. `ab_flow`

## Valores permitidos

### `ab_source`
1. `whatsapp_grupo`
2. `whatsapp_manual`
3. `site_conversor`
4. `telegram_grupo`
5. `telegram_manual`
6. `instagram_post`
7. `instagram_story`
8. `catalogo_site`
9. `catalogo_bio`
10. `manual_operador`
11. `autopilot`

### `ab_channel`
1. `whatsapp`
2. `telegram`
3. `instagram`
4. `catalogo`
5. `conversor`

### `ab_surface`
1. `grupo`
2. `dm`
3. `post`
4. `story`
5. `bio`
6. `site_home`
7. `site_oferta`
8. `site_busca`

### `ab_placement`
1. `cta_link`
2. `botao_oferta`
3. `comentario_fixado`
4. `menu_bot`
5. `lista_catalogo`
6. `destaque_topo`

### `ab_creator`
1. `manual`
2. `autopilot`
3. `ia`
4. `operador`

### `ab_format`
1. `texto`
2. `imagem`
3. `carrossel`
4. `video`
5. `story`

### `ab_store`
1. `amazon`
2. `mercadolivre`
3. `shopee`
4. `shein`
5. `outros`

### `ab_flow`
1. `direct` (clicou no proprio canal)
2. `crosspost` (ex.: Telegram -> WhatsApp)
3. `catalog_sync` (entrou no catalogo e clicou)

## Padrao UTM recomendado
1. `utm_source=achadinhosbot`
2. `utm_medium=affiliate`
3. `utm_campaign=conversor_{ab_store}`
4. `utm_content={ab_source}`

## Exemplo
Instagram story -> catalogo -> Amazon:
- `ab_source=instagram_story`
- `ab_channel=instagram`
- `ab_surface=story`
- `ab_placement=cta_link`
- `ab_creator=autopilot`
- `ab_format=story`
- `ab_store=amazon`
- `ab_flow=catalog_sync`
- `ab_content_id=ig_20260303_1830_001`

## Shopee (generateShortLink + subIds)
A Shopee permite ate 5 `subIds` no `generateShortLink`. Padrao definido:
1. `subIds[0]` = `ab_source`
2. `subIds[1]` = `ab_entry` (entry point normalizado)
3. `subIds[2]` = `ab_channel`
4. `subIds[3]` = `ab_surface`
5. `subIds[4]` = `ab_flow`

Exemplo de mutation:
- `generateShortLink(input:{ originUrl:"...", subIds:["whatsapp_grupo","whatsapp","whatsapp","grupo","direct"] })`
