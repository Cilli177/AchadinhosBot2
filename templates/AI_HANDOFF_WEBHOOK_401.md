# AI HANDOFF - ANTIGRAVITY

Data: 2026-03-06
Responsavel atual: Codex
Origem do handoff: Gemini
Branch: `main` (ou atual em uso no sandbox DEV)
Commit base: `HEAD`

## Objetivo
- Investigar e corrigir a falha de autenticação sistemática (HTTP 401 Unauthorized) no webhook `/webhook/bot-conversor`. (Prioridade Sprint 0)

## Contexto minimo
- Problema real: Os links estão chegando de alguma origem externa até o bot, mas a requisição está sendo barrada na porta de entrada da API por falha de middleware/assinatura de segurança (401), impedindo o fluxo sequente de ser acionado.
- Restricoes: A correção não deve remover por completo a segurança do endpoint, e sim adequar a validação do Hash/Token esperado no cabeçalho com o que está efetivamente chegando do emissor.
- Ambiente alvo: DEV/Homolog.

## Arquivos relevantes (Potenciais alvos)
- `Program.cs` ou configuração de Middlewares
- `AchadinhosBot.Next/Controllers/WebhookController.cs` (ou similar)
- `AchadinhosBot.Next/Infrastructure/Authentication/WebhookSignatureVerifier.cs` (se existir)
- `AchadinhosBot.Next.Tests/WebhookSignatureVerifierTests.cs` (visto no `ls` dos testes)

## O que ja foi feito
- N/A

## O que falta fazer
- Diagnosticar exatamente o que está sendo exigido no Header versus o que está configurado nos `ConfigureServices`/`UseAuthentication` ou atributos de Action filter.
- Aplicar correção no `Verification` se for falha de codificação da Secret/HMAC.

## Testes executados
- Comando: A testar.
- Resultado: A aguardar execução.

## Riscos
- Risco 1: Desproteger o Endpoint acidentalmente no intuito de fazer "passar a requisição", permitindo injecão de spam/fake requests.

## Proximo passo recomendado
- Codex: Assuma este handoff. Execute a etapa investigativa localizando como o webhook está validando a assinatura e relate a principal teoria ou teste a quebra atual antes de sair codando de vez. Registre o plano no card `CMD-05`.
