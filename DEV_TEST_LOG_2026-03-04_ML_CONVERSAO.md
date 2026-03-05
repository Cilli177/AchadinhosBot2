# DEV Test Log - 2026-03-04 - Conversao Mercado Livre

## Objetivo
Validar em DEV o ajuste de seguranca da conversao Mercado Livre para evitar geracao de link com "pagina nao existe" quando a origem social/curta depende de sessao.

## Alteracao aplicada
- Arquivo: `AchadinhosBot.Next/Application/Services/AffiliateLinkService.cs`
- Regra nova:
  - Em link social/curto, se validacao do item via API retornar `Unknown`, aborta conversao.
  - Recuperacao de ID alternativo (`TryRecoverMercadoLivreIdAsync`) passa a aceitar apenas IDs com validacao `Valid`.

## Deploy DEV
- Data/hora: 2026-03-04 22:35:02 -03:00
- Ambiente: DEV (`achadinhos-next-dev`)
- Acao: rebuild + recreate de container DEV
- Resultado: container novo iniciado com sucesso

## Evidencias tecnicas
- `docker ps`: `achadinhos-next-dev` em `Up` apos recriacao.
- Health check:
  - `GET http://127.0.0.1:8081/health`
  - Status: `200`

## Testes funcionais realizados
1. Conversao de curto ML:
- Entrada: `https://meli.la/2mrFTYt`
- Resultado: `success=true`
- Saida convertida: `https://produto.mercadolivre.com.br/MLB-61417067?matt_tool=98187057&matt_word=land177`

2. Conversao de pagina social ML sem produto explicito:
- Entrada: `https://www.mercadolivre.com.br/social/ofertasgamer`
- Resultado: `success=false`
- Erro: `Nao foi possivel identificar um produto valido do Mercado Livre para afiliacao.`

## Observacoes
- Comportamento esperado do ajuste foi confirmado: fluxo social sem evidencia confiavel de produto nao gera link afiliado quebrado.
- Warning de Telegram userbot (`codigo de verificacao pendente`) nao bloqueou health/API.
