# Documentação de Objeto: AffiliateLinkService

- **Nome do objeto:** AffiliateLinkService
- **Tipo do objeto:** Serviço de Aplicação (Service)
- **Finalidade:** Realizar a conversão de links de produtos normais em links de afiliados (Shopee, Amazon, Mercado Livre, AliExpress etc).
- **Responsabilidade:** Extrair URLs, identificar o marketplace correto, consultar as APIs respectivas (quando aplicável) e encapsular os parâmetros de afiliado corretos devolvendo o link higienizado.
- **Versão atual:** 02

## Histórico de Versões
- **Versão 00:** Criação inicial do serviço (tracking Amazon, Shopee, etc).
- **Versão 01:** Implementada lógica de expansão `meli.la` e regra de tamanho do Mercado Livre.
- **Versão 02:** (07/03/2026) Desativada a validação da API oficial do Mercado Livre devido a instabilidades e links canônicos incorretos para catálogo. Fallback manual 100% ativado.

## Última Alteração (Versão 02)
- **Data da alteração:** 2026-03-07
- **Autor/responsável:** Gemini (Executivo) / Hand-off.
- **Motivo da alteração:** Produtos de catálogo do ML (IDs com <= 8 dígitos) estavam recebendo URLs de domínio `produto.mercadolivre.com.br` por culpa do retorno da API oficial do Mercado Livre (campo `permalink`), gerando links quebrados 404 nas pontas.
- **Descrição técnica da alteração:** 
  - Comentada/Desabilitada chamada para `ValidateMercadoLivreItemWithApiAsync`.
  - Comentada/Desabilitada chamada para `ResolveMercadoLivreCanonicalUrlAsync`.
  - Forçado uso do `BuildMercadoLivreAffiliateUrl` passando `mlbId` com `canonicalUrl = null` para ativar o fallback string-builder local que valida tamanho (<= 8 dígitos = `/p/MLB`, >8 dígitos = `produto.`).

## Entradas e Saídas
- **Entradas:** `Uri uri` (original), `Uri resolvedUri` (expandida via HttpClient).
- **Saídas:** `string` (URL com parâmetros de afiliados `matt_tool` e `matt_word` aplicados).

## Impactos e Riscos Conhecidos
- **Riscos (V02):** Se um link do Mercado Livre enviado no grupo original apontar para um ID que realmente não existe dentro do ML, não saberemos de antemão. O bot converterá matematicamente o ID sem bater na API e o usuário final no Rei das Ofertas verá um 404 ao clicar. É aceitável dado o ganho de conversão dos itens verídicos.

## Próximos passos sugeridos
- Revisitar o fluxo do Mercado Livre no futuro para checar se a API foi corrigida do lado deles.
