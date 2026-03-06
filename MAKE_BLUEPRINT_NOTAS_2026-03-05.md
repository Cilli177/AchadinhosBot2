# Notas dos Blueprints Make (DEV)

Arquivos:
- `MAKE_BLUEPRINT_01_TELEGRAM_OFERTA_PARA_DRAFT.json`
- `MAKE_BLUEPRINT_02_TELEGRAM_APROVACAO_PUBLICACAO.json`

## 1) Como importar no Make

1. Criar novo Scenario.
2. Menu de tres pontos -> `Import Blueprint`.
3. Importar o arquivo 01.
4. Repetir para o arquivo 02 em outro Scenario.
5. Ajustar placeholders:
- `{{TELEGRAM_BOT_TOKEN}}`
- `{{OPS_CHAT_ID}}`
- URLs `http://localhost:8081` (trocar para URL DEV publica se Make estiver fora da mesma rede).

## 2) Formato da mensagem de oferta no Telegram (Scenario 01)

Enviar texto puro em JSON:

```json
{
  "product_name": "Smartwatch X Pro",
  "catchy_description": "Oferta relampago para quem quer performance e estilo.",
  "product_description": "Tela AMOLED, bateria de longa duracao e monitoramento completo.",
  "original_price": "R$ 599,90",
  "current_price": "R$ 379,90",
  "affiliate_link": "https://seulinkafiliado.com/produto",
  "catalog_card_image": "https://sua-imagem-publica.com/card.jpg"
}
```

## 3) Fluxo operacional

- Scenario 01:
  - recebe mensagem JSON de oferta;
  - cria draft em `/api/instagram/publish/drafts`;
  - envia para validacao no Telegram com comandos.
- Scenario 02:
  - captura `/aprovar <draftId>`;
  - publica em `/api/instagram/publish/drafts/{id}/publish`;
  - sincroniza catalogo em `/api/catalog/sync`.

## 4) Avaliacao do gerador HTML enviado

Pode ser usado, sim, e a base e boa para pagina premium.

Pontos fortes:
- estrutura clara (header/hero/detalhes/footer);
- hierarquia visual boa para conversao;
- foco em responsividade e CTA.

Ajustes recomendados para producao:
- padronizar placeholders para variaveis reais (evitar referencias de engine especifica do OPAL);
- garantir URL de imagem publica e estavel (CDN/obj storage);
- manter versao curta do prompt para reduzir variacao entre geracoes;
- separar 2 artefatos:
  - `card social` (1080x1350 para Instagram),
  - `pagina catalogo` (HTML responsivo para site).

Conclusao:
- serve como ideia e tambem como base pratica;
- para estabilidade, usar template mais deterministico (menos aberto) no passo de geracao.
