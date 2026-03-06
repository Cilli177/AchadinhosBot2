# DEV Test Log - 2026-03-06 - Mercado Livre Fallback

## Objetivo
Estabilizar a conversao de links do Mercado Livre quando a API oficial estiver indisponivel, mantendo a regra de seguranca de nunca encaminhar link cru.

## Mudancas aplicadas
- `AchadinhosBot.Next/Application/Services/AffiliateLinkService.cs`
  - fallback manual do Mercado Livre foi promovido para continuar ativo quando a validacao do item ficar `Unknown`, desde que exista `mlbId` confiavel;
  - cenarios sem `mlbId` confiavel continuam bloqueados;
  - logs foram detalhados para distinguir:
    - validacao inconclusiva com fallback manual ativo;
    - validacao inconclusiva sem fallback confiavel;
    - indisponibilidade de URL canonica com montagem manual de URL afiliada.
- `AchadinhosBot.Next.Tests/MercadoLivreFallbackTests.cs`
  - novo teste cobrindo fallback manual quando a API oficial do ML retorna erro;
  - novo teste cobrindo bloqueio seguro quando nao existe `mlbId` confiavel.

## Evidencias de teste unitario
1. Fallback manual ativo com API oficial indisponivel
- Entrada:
  - URL: `https://produto.mercadolivre.com.br/MLB-123456789-item-teste`
  - stub HTTP: `500` para `https://api.mercadolibre.com/items/MLB123456789` e `https://api.mercadolibre.com/products/MLB123456789`
- Resultado esperado:
  - `ConvertAsync(...)` retorna `Success=true`
  - URL final segue afiliada com `matt_tool=tool123` e `matt_word=word456`
  - fluxo nao depende da URL canonica da API para continuar.
- Resultado obtido: `OK`

2. Falha segura sem `mlbId` confiavel
- Entrada:
  - URL: `https://www.mercadolivre.com.br/ofertas/teste-sem-id`
  - stub HTML sem `MLB`
- Resultado esperado:
  - `ConvertAsync(...)` retorna `Success=false`
  - `ConvertedUrl=null`
  - oferta continua bloqueada para evitar envio de link cru.
- Resultado obtido: `OK`

## Validacao automatizada executada
1. Testes focados no fallback do Mercado Livre
- Comando:
```powershell
dotnet test .\AchadinhosBot.Next.Tests\AchadinhosBot.Next.Tests.csproj --no-restore --filter "FullyQualifiedName~MercadoLivreFallbackTests" -v minimal
```
- Resultado: `OK` (`2 passed`, `0 failed`).

2. Suite completa de testes do projeto
- Comando:
```powershell
dotnet test .\AchadinhosBot.Next.Tests\AchadinhosBot.Next.Tests.csproj --no-restore
```
- Resultado: `OK` (`23 passed`, `0 failed`).

## Observacoes
- Persistem warnings `NU1900` por indisponibilidade de acesso ao feed de vulnerabilidade do NuGet no ambiente local. Eles nao bloquearam build nem testes.
- Esta rodada validou o fallback em nivel de unidade com stubs de falha da API do ML. Nenhum link real do Mercado Livre foi disparado em producao.

## Status da rodada
- Implementacao do fallback manual seguro para ML: `OK`
- Testes unitarios dedicados: `OK`
- Suite completa: `OK`
- Pronto para homologacao DEV do fluxo real com logs operacionais.
