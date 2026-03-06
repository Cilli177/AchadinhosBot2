# AI COMMAND QUEUE

Arquivo oficial de orquestracao entre Gemini e Codex.

Como usar:
- Gemini adiciona novos itens no topo de `## Inbox`.
- Codex executa o primeiro item com `Status: NEW`, atualiza o mesmo item e muda o status.
- O usuario so precisa avisar: "foi adicionado um novo comando em AI_COMMAND_QUEUE.md".

## Inbox

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
