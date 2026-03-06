# Cenario 02 - Aprovacao e Publicacao (Make novo)

## 1) Modulos
1. `Telegram Bot > Watch updates` (Trigger)
2. `Tools > Set variable` (draft_id)
3. `HTTP > Make a request` (`POST /auth/login`)
4. `HTTP > Make a request` (`POST /api/instagram/publish/drafts/{id}/publish`)
5. `HTTP > Make a request` (`POST /api/catalog/sync`)
6. `Telegram Bot > Send a message` (confirmacao)

## 2) Trigger
`Telegram Bot > Watch updates`
- Connection: bot `Rei_Teste_bot`
- Update type: `Messages`

## 3) Filtro de aprovacao
Na conexao para o modulo 2:
- Condicao:
`{{1.message.text}}` `starts with` `/aprovar `

## 4) Extrair draft_id
`Tools > Set variable`
- Nome: `draft_id`
- Valor:
`{{trim(get(split(1.message.text;" ");2))}}`

## 5) Login backend
`HTTP > Make a request`
- Method: `POST`
- URL: `https://stylish-acceptance-cameras-tuesday.trycloudflare.com/auth/login`
- Headers: `Content-Type: application/json`
- Body (Raw):
```json
{"username":"admin","password":"admin123"}
```
- Cookie handling: habilitar para reutilizar no proximo request

## 6) Publicar draft no Instagram
`HTTP > Make a request`
- Method: `POST`
- URL:
`https://stylish-acceptance-cameras-tuesday.trycloudflare.com/api/instagram/publish/drafts/{{2.draft_id}}/publish`
- Headers: `Content-Type: application/json`
- Body (Raw):
```json
{}
```
- Cookies: usar cookies do passo de login

## 7) Sincronizar catalogo/site
`HTTP > Make a request`
- Method: `POST`
- URL: `https://stylish-acceptance-cameras-tuesday.trycloudflare.com/api/catalog/sync`
- Headers: `Content-Type: application/json`
- Body (Raw):
```json
{}
```
- Cookies: usar cookies do passo de login

## 8) Mensagem de confirmacao
`Telegram Bot > Send a message`
- Chat ID: `{{1.message.chat.id}}`
- Text:
```text
Publicacao concluida
DraftId: {{2.draft_id}}
MediaId: {{4.body.mediaId}}
Catalogo sincronizado.
```
