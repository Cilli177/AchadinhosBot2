# DOCUMENTAÇÃO DO OBJETO: RealLinkValidationTests

## 1. Identificação
- Nome do objeto: `RealLinkValidationTests`
- Tipo do objeto: Suíte de Testes (Unit/Integration)
- Caminho/localização: `AchadinhosBot.Next.Tests/RealLinkValidationTests.cs`
- Responsável: Antigravity
- Data: 2026-03-06
- Versão atual: v00

## 2. Finalidade
- Descrição objetiva do propósito do objeto: Suite de testes dedicada a validar a conversão de links reais do Mercado Livre fornecidos pelo usuário.
- Responsabilidade dentro do sistema: Garantir regressão para expansão de links curtos, links de catálogo e links de itens com credenciais reais.

## 3. Entradas e saídas
- Entradas: Lista de URLs reais.
- Saídas: Logs de execução do teste (stdout/stderr) indicando sucesso ou falha na conversão e a URL final gerada.

## 4. Dependências
- Dependências internas: `AffiliateLinkService`, `AffiliateOptions`.
- Dependências externas: Conectividade com a internet para requisições HTTP reais aos domínios do Mercado Livre.

## 5. Regras de negócio
- Regras aplicadas: 
  - Validar se a URL expandida contém as tags de afiliado.
  - Validar se o sucesso da conversão é relatado corretamente.

## 6. Alteração realizada
- Tipo da alteração: Criação (v00).
- Motivo: Necessidade de validação ponta-a-ponta para o incidente de links `meli.la`.
- Descrição técnica da alteração: Implementação de fatos XUnit que orquestram o `AffiliateLinkService` com URLs reais e verificam os resultados.

## 7. Histórico de versões
- v00: Criação inicial.

## 8. Riscos e observações
- Riscos conhecidos: Fragilidade devido a mudanças dinâmicas no site do ML (ex: vitrines mudando IDs).
- Observações técnicas: Usa `HttpClientHandler` com redirecionamento automático habilitado.
