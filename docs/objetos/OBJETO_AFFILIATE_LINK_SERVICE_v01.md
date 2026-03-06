# DOCUMENTAÇÃO DO OBJETO: AffiliateLinkService

## 1. Identificação
- Nome do objeto: `AffiliateLinkService`
- Tipo do objeto: Classe / Serviço (C#)
- Caminho/localização: `AchadinhosBot.Next/Application/Services/AffiliateLinkService.cs`
- Responsável: Antigravity
- Data: 2026-03-06
- Versão atual: v01

## 2. Finalidade
- Descrição objetiva do propósito do objeto: Serviço central encarregado de processar, validar e converter URLs originais (Shopee, Amazon, Mercado Livre) em links de afiliado rastreáveis.
- Responsabilidade dentro do sistema: Expansão de links curtos, extração de IDs de produto, aplicação de tags de afiliado (matt_tool, matt_word, tag, etc.), e validação de sucesso da conversão.

## 3. Entradas e saídas
- Entradas: URL original (string), CancellationToken, Source (string).
- Saídas: `AffiliateConversionResult` contendo sucesso, URL convertida, IsAffiliated e metadados.

## 4. Dependências
- Dependências internas: `IMercadoLivreOAuthService`, `AmazonCreatorApiClient`, `AmazonPaApiClient`.
- Dependências externas: APIs da Shopee, Amazon e Mercado Livre.

## 5. Regras de negócio
- Regras aplicadas: 
  - Bloqueio de subIds inválidos na Shopee.
  - Fallback manual para Mercado Livre quando a API oficial está instável.
  - Preferência por URLs sociais/vitrines quando o ID de produto não é extraível diretamente.
- Restrições: Não permitir envio de links crus (sem afiliação).
- Critérios de validação: URL final deve conter as tags de afiliado configuradas.

## 6. Alteração realizada
- Tipo da alteração: Correção e Melhoria.
- Motivo: Falha na expansão de links `meli.la` e erro 404 em URLs de catálogo resolvidos de vitrines.
- Descrição técnica da alteração:
  - Inserida penalidade de `-100pts` para links curtos no `ScoreAffiliateCandidate` para garantir expansão HTTP.
  - Implementada detecção inteligente de catálogo (≤8 dígitos) vs item (10+ dígitos) para gerar o formato correto da URL (`/p/` vs `produto.../`).
  - Adicionado suporte a páginas de redirecionamento `account-verification`.
- Impacto esperado: Estabilização de 100% da conversão do aplicativo do Mercado Livre.

## 7. Histórico de versões
- v00: Criação inicial e baseline.
- v01: Correção de expansão `meli.la` e correção de formato de URL de catálogo.

## 8. Riscos e observações
- Riscos conhecidos: Dependência de padrões de URL do Mercado Livre que podem mudar.
- Observações técnicas: A lógica de catálogo é baseada no comprimento do ID numérico observado.
