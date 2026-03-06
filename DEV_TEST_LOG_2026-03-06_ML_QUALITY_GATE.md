# DEV Test Log - 2026-03-06 - Quality Gate ML + Imagem

## Objetivo
Validar o novo quality gate de envio automatico para bloquear ofertas ruins, com foco em Mercado Livre sem imagem.

## Escopo desta rodada
- `OfferQualityGate` aplicado em:
  - fluxo WhatsApp -> WhatsApp (`Program.cs`)
  - fluxo Telegram Userbot -> WhatsApp (`TelegramUserbotService.cs`)
  - replay manual Telegram -> WhatsApp (`TelegramUserbotService.cs`)
- bloqueio com log de motivo
- encaminhamento para ponte de aprovacao quando detectar Mercado Livre bloqueado

## Commit de referencia
- HEAD local: `5065acc`

## Validacao automatizada executada
1. Build aplicacao
- Comando:
```powershell
dotnet build .\AchadinhosBot.Next\AchadinhosBot.Next.csproj
```
- Resultado: `OK` (sem erros de compilacao).

2. Testes focados no quality gate
- Comando:
```powershell
dotnet test .\AchadinhosBot.Next.Tests\AchadinhosBot.Next.Tests.csproj --filter "FullyQualifiedName~OfferQualityGateTests"
```
- Resultado: `OK` (`7 passed`, `0 failed`).

3. Suite completa de testes (baseline atual)
- Comando:
```powershell
dotnet test .\AchadinhosBot.Next.Tests\AchadinhosBot.Next.Tests.csproj --configuration Debug
```
- Resultado: `FALHA BASELINE` em teste pre-existente:
  - `ShopeeShortLinkPayloadTests.BuildShopeePayload_IncludesFiveSubIds_FromSource`
  - status geral: `19 passed`, `1 failed`
  - observacao: falha nao introduzida por este hotfix.

## Cenarios cobertos por teste unitario do quality gate
- bloqueia `empty_text`
- bloqueia `no_urls`
- bloqueia `invalid_url_format`
- bloqueia `insufficient_context`
- bloqueia `mercadolivre_without_image`
- permite Mercado Livre com imagem candidata
- permite oferta nao-ML sem imagem quando texto e link estao validos

## Checklist manual DEV (operacao)
1. Enviar oferta Mercado Livre sem imagem (origem Telegram ou WhatsApp)
- Esperado:
  - nao envia para destino final
  - log contem `quality gate` com reason `mercadolivre_without_image`
  - oferta aparece na fila de pendencias ML no dashboard

2. Aprovar pendencia ML com `link corrigido` no dashboard
- Esperado:
  - oferta aprovada reutiliza o link corrigido (nao o link convertido original)
  - anuncio segue para fluxo definido sem reprovacao indevida

3. Enviar oferta Mercado Livre com imagem valida
- Esperado:
  - passa no quality gate
  - mensagem sai com imagem no destino

4. Enviar oferta nao-ML com texto+link validos sem imagem
- Esperado:
  - envio permitido (sem bloqueio por imagem)

5. Validar rastreabilidade em logs
- Procurar por:
  - `WhatsApp forwarding bloqueado por quality gate`
  - `TelegramUserbot bloqueou envio para WhatsApp por quality gate`
  - `Replay bloqueado por quality gate`

## Status da rodada
- Qualidade de codigo: `OK` para escopo alterado.
- Validacao automatizada do novo gate: `OK`.
- Pronto para homologacao manual em DEV com dados reais de origem.
