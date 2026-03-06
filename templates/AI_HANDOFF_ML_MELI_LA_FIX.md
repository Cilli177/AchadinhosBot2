# AI HANDOFF: Mercado Livre - meli.la & Catalog Fix

## 1. Entendimento do Cenário Atual
Links curtos `meli.la` estavam sendo retornados sem expansão, resultando em "Produto não identificado" no bot. Além disso, links resolvidos para IDs de catálogo (8 dígitos) geravam URLs 404 no formato padrão de produto.

## 2. Diagnóstico Técnico
- **Root Cause (meli.la)**: `ScoreAffiliateCandidate` atribuía score 95 a links `meli.la` (Host ML + Short + Social), o que atingia o threshold de 80 ("strong candidate") e abortava o loop de expansão HTTP antes da primeira requisição.
- **Root Cause (404/Catálogo)**: O fallback manual em `BuildMercadoLivreAffiliateUrl` sempre usava o host `produto.mercadolivre.com.br/MLB-{id}`, que é exclusivo para itens. IDs de catálogo exigem o formato `/p/MLBxxxxxxxx`.
- **Credenciais**: As tags de afiliado nos testes estavam desatualizadas em relação às credenciais reais do usuário (`land177` / `98187057`).

## 3. Problema Prioritário Identificado
Impedimento total de conversão para links encurtados pelo aplicativo do Mercado Livre (`meli.la`) e links de vitrines/social que resolvem para itens de catálogo.

## 4. Solução Implementada
1. **Penalidade de Scoring**: Inserida penalidade de `-100pts` para hosts `meli.la` e `meli.co` em `ScoreAffiliateCandidate`, forçando a expansão HTTP.
2. **Reconhecimento de URLs Sociais**: Adicionado check `IsMercadoLivreSocial` no loop de expansão para aceitar redirecionamentos para vitrines como "strong candidates".
3. **Detecção de Tipo de ID**: `BuildMercadoLivreAffiliateUrl` agora diferencia IDs pelo comprimento (≤8 dígitos = catálogo → `/p/`; 10+ dígitos = item → `produto.../`).
4. **Suporte `/gz/account-verification`**: `TryExtractGoUrl` agora extrai URLs de destino de páginas de verificação de conta do ML.

## 5. Objetos Impactados e Versões
- `AffiliateLinkService.cs`: Versão atualizada com correções de lógica de expansão e formação de URL.
- `RealLinkValidationTests.cs`: Nova suíte de testes ponta-a-ponta com 7 casos reais.

## 6. Riscos e Observações
- O link de catálogo (`/p/`) frequentemente redireciona para uma página de "account-verification" ou login do ML se acessado via browser sem cookies de sessão, mas o parâmetro de afiliado (`matt_tool`) permanece na URL.
- A rotatividade de produtos em vitrines sociais pode mudar o MLB-ID retornado, mas o fluxo de conversão agora é resiliente a isso.

## 7. Testes Executados
Execução da suíte `RealLinkValidationTests`:
- `meli.la/2Dkanv9` -> ✅ `/p/MLB27943679`
- `meli.la/1WBiGnw` -> ✅ `/p/MLB42806793`
- `meli.la/2ia6LeB` -> ✅ `/p/MLB51875426`
- social/minutoreview -> ✅ MLB-3746645279 (Item)
- p/MLB27307234 -> ✅ MLB-3467275109 (Item)

**Resultado: 7/7 Aprovados.**

## 8. Commit Sugerido
`fix(ml): resolve meli.la expansion and catalog URL format 404s`
