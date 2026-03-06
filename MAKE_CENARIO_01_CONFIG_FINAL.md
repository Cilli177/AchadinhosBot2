# Cenario 01 - Captura Oferta e Cria Draft (Make novo)

## 1) Modulos
1. `Telegram Bot > Watch updates` (Trigger)
2. `Flow Control > Router`
3. Rota A: `Telegram Bot > Send a message`
4. Rota B: `Google Gemini AI > Generate content`
5. `JSON > Parse JSON`
6. `Telegram Bot > Get a file`
7. `HTTP > Make a request` (`POST /auth/login`)
8. `HTTP > Make a request` (`POST /api/instagram/publish/drafts`)
9. `Telegram Bot > Send a message` (retorno DraftId)

## 2) Trigger
`Telegram Bot > Watch updates`
- Connection: bot `Rei_Teste_bot`
- Update type: `Messages`

## 3) Router - filtros

### Rota A (comando /oferta)
- Condicao:
`{{1.message.text}}` `starts with` `/oferta`

### Rota B (oferta com imagem)
- Condicoes:
`{{length(1.message.photo)}}` `greater than` `0`
`{{ifempty(1.message.caption;1.message.text)}}` `is not equal to` `""`

## 4) Rota A - mensagem de instrução
`Telegram Bot > Send a message`
- Chat ID: `{{1.message.chat.id}}`
- Reply to Message ID: `{{1.message.message_id}}`
- Text:
`Envie agora a oferta original encaminhada (com imagem).`

## 5) Gemini - extracao estruturada
`Google Gemini AI > Generate content`
- Model: `gemini-2.5-flash`
- Prompt:

```text
Extraia dados de oferta em portugues-BR e retorne SOMENTE JSON valido com:
product_name, catchy_description, product_description, original_price, current_price, affiliate_link.
Se faltar valor, retorne string vazia.
Texto da oferta: {{ifempty(1.message.caption;1.message.text)}}
```

## 6) Parse JSON
`JSON > Parse JSON`
- JSON string: saida textual do Gemini (campo `text` do modulo anterior)
- Data structure:

```json
{
  "type": "object",
  "properties": {
    "product_name": { "type": "string" },
    "catchy_description": { "type": "string" },
    "product_description": { "type": "string" },
    "original_price": { "type": "string" },
    "current_price": { "type": "string" },
    "affiliate_link": { "type": "string" }
  },
  "required": [
    "product_name",
    "catchy_description",
    "product_description",
    "original_price",
    "current_price",
    "affiliate_link"
  ]
}
```

## 7) Get file da imagem
`Telegram Bot > Get a file`
- File ID:
`{{1.message.photo[length(1.message.photo)-1].file_id}}`

## 8) Login backend
`HTTP > Make a request`
- Method: `POST`
- URL: `https://stylish-acceptance-cameras-tuesday.trycloudflare.com/auth/login`
- Headers: `Content-Type: application/json`
- Body (Raw):
```json
{"username":"admin","password":"admin123"}
```
- Cookie handling: habilitar para reutilizar no proximo request

## 9) Criar draft
`HTTP > Make a request`
- Method: `POST`
- URL: `https://stylish-acceptance-cameras-tuesday.trycloudflare.com/api/instagram/publish/drafts`
- Headers: `Content-Type: application/json`
- Body (Raw):
```json
{
  "postType": "feed",
  "productName": "{{5.product_name}}",
  "caption": "{{5.catchy_description}}\n\n{{5.product_description}}\n\nPreco VIP: {{5.current_price}}\nPreco original: {{5.original_price}}",
  "hashtags": "#achadinhos #oferta #vip",
  "imageUrls": [
    "https://api.telegram.org/file/bot8574127810:AAHxTox1c1OMx2gEoSyYE3rCAZLVOWvA0zg/{{6.file_path}}"
  ],
  "ctas": [
    {
      "keyword": "VIP",
      "link": "{{5.affiliate_link}}"
    }
  ]
}
```
- Cookies: usar cookies do passo de login

## 10) Mensagem final
`Telegram Bot > Send a message`
- Chat ID: `{{1.message.chat.id}}`
- Text:
```text
Novo draft para validacao
DraftId: {{8.body.id}}
Produto: {{5.product_name}}
Link: {{5.affiliate_link}}
Comandos: /aprovar {{8.body.id}} | /reprovar {{8.body.id}} motivo
```
