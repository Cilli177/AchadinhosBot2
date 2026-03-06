# PROTOCOLO DA FILA DE COMANDOS MULTI-IA

## 1. Identificacao
- Nome do objeto: Protocolo da fila de comandos multi-IA
- Tipo do objeto: documento normativo
- Caminho/localizacao: `docs/governanca/PROTOCOLO_FILA_COMANDOS_MULTI_IA_v00.md`
- Responsavel: Codex
- Data: 2026-03-06
- Versao atual: v00

## 2. Finalidade
- Criar um canal unico e versionado para comandos do Gemini ao Codex.
- Eliminar a necessidade de copiar e colar instrucoes a cada iteracao.
- Manter rastreabilidade do que foi pedido, executado, bloqueado ou concluido.

## 3. Arquivo oficial da fila
- O arquivo oficial desta base e `AI_COMMAND_QUEUE.md`.
- Esse arquivo deve ser lido pelo Codex sempre que o usuario informar que existe um novo comando.
- Esse arquivo deve ser atualizado pelo Gemini ao adicionar novas demandas executivas.

## 4. Papeis
- Gemini: escreve a intencao executiva, prioridade, restricoes, criterio de validacao e proximo objetivo.
- Codex: le a fila, executa a tarefa no repositorio, atualiza status tecnico e registra evidencias objetivas.
- Usuario: apenas sinaliza quando um novo item foi adicionado ou quando deseja repriorizar a fila.

## 5. Regras de operacao
- Um item novo deve ser adicionado no topo da secao `## Inbox`.
- Cada item deve ter um identificador unico no formato `CMD-AAAA-MM-DD-XX`.
- Status permitidos:
- `NEW`
- `IN_PROGRESS`
- `BLOCKED`
- `DONE`
- Codex sempre prioriza o primeiro item `NEW`, salvo instrucao explicita diferente.
- Codex pode editar somente os campos tecnicos de execucao e status.
- Gemini nao deve sobrescrever o historico tecnico do Codex; deve abrir novo item ou complementar o contexto do item atual.

## 6. Campos obrigatorios por item
- `ID`
- `Status`
- `Origem`
- `Data`
- `Objetivo`
- `Contexto`
- `Escopo`
- `Restricoes`
- `Validacao esperada`
- `Saida esperada do Codex`

## 7. Campos de retorno tecnico do Codex
- `Leitura tecnica`
- `Acoes executadas`
- `Arquivos alterados`
- `Validacao executada`
- `Resultado`
- `Proximo passo`

## 8. Regras de seguranca
- Nao registrar segredos, cookies, tokens, credenciais ou identificadores sensiveis desnecessarios.
- Nao usar a fila para armazenar dumps extensos de log; referenciar arquivo e trecho relevante.
- Se a tarefa envolver deploy, hotfix ou mudanca sensivel, a fila deve apontar tambem para runbook ou documento de governanca aplicavel.

## 9. Fluxo recomendado
1. Gemini adiciona item em `AI_COMMAND_QUEUE.md`.
2. Usuario informa ao Codex que ha um novo item na fila.
3. Codex le o topo da fila e executa.
4. Codex atualiza status e retorno tecnico no mesmo item.
5. Gemini analisa o retorno e decide se abre novo item ou encerra o ciclo.

## 10. Historico de versoes
- v00: criacao inicial do protocolo de fila de comandos entre Gemini e Codex.
