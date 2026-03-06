# AI HANDOFF - ANTIGRAVITY

Data: 2026-03-06
Responsavel atual: Codex
Origem do handoff: Gemini
Branch: `main` (ou atual em uso no sandbox DEV)
Commit base: `HEAD`

## Objetivo
- Investigar a falha da API oficial do Mercado Livre ao converter links e implementar/estabilizar um Fallback seguro e validado.

## Contexto minimo
- Problema real: A API do ML falha com constância (seja por timeout ou descontinuação). Isso compromete a esteira e resulta na perda de afiliação ou geração de erros para os grupos.
- Restricoes: Se o Fallback não conseguir aplicar a afiliação, a oferta DEVE ser descartada/logada. **Nunca enviar link cru/não afiliado pro canal**.
- Ambiente alvo: DEV.

## Arquivos relevantes
- `AchadinhosBot.Next\Application\Services\AffiliateLinkService.cs`
- `AchadinhosBot.Next\Application\Services\MercadoLivreAffiliateService.cs` (ou similar, dependendo de como está isolado)
- `AchadinhosBot.Next.Tests\MercadoLivreShortLinkPayloadTests.cs` (se existir)

## O que ja foi feito
- Revisada documentação arquitetural.
- Confirmado através do `CMD-02` que nosso framework de testes unitários está operante.

## O que falta fazer
- Diagnosticar exatamente em qual linha/request a rotina de link curto do ML está quebrando hoje.
- Implementar try/catch na chamada primária do ML.
- No `catch`, usar o link afiliado "hardcoded" anexando o ID do produto ou o fallback de montagem manual se as regras permitirem, caso contrário, abortar a oferta.
- Criar evidência do funcionamento do fallback.

## Testes executados
- Comando: `dotnet test` a ser feito.
- Resultado: A aguardar execução.

## Riscos
- Risco 1: Gerar um link que pareça válido mas que não direcione a comissão corretamente para o nosso ID de afiliado do ML.
- Risco 2: Timeout prender a fila de processamento global de mensagens.

## Proximo passo recomendado
- Codex: Assuma este handoff. Investigue `AffiliateLinkService` para entender como o Mercado Livre é resolvido lá dentro. Execute o diagnóstico e documente o resultado (item 1 a 13 do seu Prompt) ou através do arquivo `DEV_TEST_LOG`.
