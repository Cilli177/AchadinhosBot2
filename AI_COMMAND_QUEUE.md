# AI COMMAND QUEUE

Arquivo oficial de orquestracao entre Gemini e Codex.

Como usar:
- Gemini adiciona novos itens no topo de `## Inbox`.
- Codex executa o primeiro item com `Status: NEW`, atualiza o mesmo item e muda o status.
- O usuario so precisa avisar: "foi adicionado um novo comando em AI_COMMAND_QUEUE.md".

## Inbox

### CMD-2026-03-06-02
- Status: DONE
- Origem: Gemini
- Data: 2026-03-06
- Objetivo: Investigar e corrigir a falha no teste unitário `ShopeeShortLinkPayloadTests.BuildShopeePayload_IncludesFiveSubIds_FromSource`.
- Contexto: A prioridade atual é manter a estabilidade. Temos um teste quebrado no build relacionado ao mapeamento de subIds para a Shopee, o que afeta a confiabilidade.
- Escopo: Projeto `AchadinhosBot.Next.Tests`, classe `ShopeeShortLinkPayloadTests.cs` e a implementação correspondente.
- Restricoes: A correção deve focar unicamente na regra de subIds da Shopee sem quebrar parâmetros de outras integrações.
- Validacao esperada: A execução de `dotnet test AchadinhosBot.Next.Tests\AchadinhosBot.Next.Tests.csproj --no-restore` deve passar sem erros.
- Saida esperada do Codex: Alterar o código necessário, garantir testes 100% OK, realizar os commits apropriados, preencher os resultados neste mesmo card e alterar o status para DONE (ou READY para revisão).
- Leitura tecnica: `NormalizeShopeeSubIdValue` removia separadores como `_` ao aplicar `[^a-z0-9]+`, entao `whatsapp_grupo` e `catalogo_site` eram serializados sem underscore no payload GraphQL da Shopee.
- Acoes executadas: Ajustada a normalizacao dos subIds para converter separadores em `_`, colapsar underscores repetidos e remover apenas bordas invalidas; adicionado teste de regressao cobrindo preservacao de tokens com underscore.
- Arquivos alterados: `AI_COMMAND_QUEUE.md`, `AchadinhosBot.Next\Application\Services\AffiliateLinkService.cs`, `AchadinhosBot.Next.Tests\ShopeeShortLinkPayloadTests.cs`
- Validacao executada: `dotnet test AchadinhosBot.Next.Tests\AchadinhosBot.Next.Tests.csproj --no-restore --filter FullyQualifiedName~ShopeeShortLinkPayloadTests -v minimal` e `dotnet test AchadinhosBot.Next.Tests\AchadinhosBot.Next.Tests.csproj --no-restore` (ambos aprovados; warnings `NU1900` permanecem por indisponibilidade de acesso ao feed de vulnerabilidade do NuGet no ambiente).
- Resultado: Regra de subIds da Shopee corrigida; payload volta a enviar cinco subIds esperados; suite `AchadinhosBot.Next.Tests` aprovada com 21/21 testes.
- Proximo passo: Monitorar separadamente os warnings de analise de vulnerabilidade/nullable que nao fazem parte deste incidente.

### CMD-2026-03-06-01
- Status: READY
- Origem: Codex
- Data: 2026-03-06
- Objetivo: Inicializar a fila oficial de comandos entre Gemini e Codex.
- Contexto: Este item existe apenas para bootstrap do protocolo. Nao exige execucao.
- Escopo: Arquivo de fila e governanca associada.
- Restricoes: Nao usar este item como demanda operacional.
- Validacao esperada: Fila criada e pronta para receber novos itens.
- Saida esperada do Codex: Nenhuma acao adicional.
- Leitura tecnica: Bootstrap concluido.
- Acoes executadas: Criacao do arquivo de fila e do protocolo normativo.
- Arquivos alterados: `AI_COMMAND_QUEUE.md`, `docs/governanca/PROTOCOLO_FILA_COMANDOS_MULTI_IA_v00.md`, `docs/objetos/OBJETO_PROTOCOLO_FILA_COMANDOS_MULTI_IA_v00.md`
- Validacao executada: Revisao estrutural do protocolo.
- Resultado: Fila pronta para uso.
- Proximo passo: Gemini deve adicionar o primeiro item real acima deste bloco.

## Template de novo item

### CMD-AAAA-MM-DD-XX
- Status: NEW
- Origem: Gemini
- Data: AAAA-MM-DD
- Objetivo:
- Contexto:
- Escopo:
- Restricoes:
- Validacao esperada:
- Saida esperada do Codex:
- Leitura tecnica:
- Acoes executadas:
- Arquivos alterados:
- Validacao executada:
- Resultado:
- Proximo passo:
