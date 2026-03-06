# GOVERNANCA DO PADRAO ANTIGRAVITY

## 1. Identificacao
- Nome do objeto: Governanca do padrao Antigravity
- Tipo do objeto: documento normativo
- Caminho/localizacao: `docs/governanca/GOVERNANCA_PADRAO_ANTIGRAVITY_v00.md`
- Responsavel: Codex
- Data: 2026-03-06
- Versao atual: v00

## 2. Finalidade
- Definir `Antigravity` como workspace padrao de desenvolvimento assistido por IA em DEV.
- Padronizar como duas IAs podem colaborar sem perder rastreabilidade tecnica no repositorio.
- Impedir que uma ferramenta externa vire fonte de verdade acima de Git, testes e pipeline.

## 3. Base da decisao
- Em 2026-03-06 foram consultadas fontes oficiais publicas sobre Antigravity.
- Fonte oficial 1: `https://antigravity.google/`
- Fonte oficial 2: `https://blog.google/technology/google-labs/antigravity-coding-project-management/`
- Inferencia operacional adotada nesta base:
- Antigravity e adequado como cockpit de exploracao, planejamento e execucao assistida em DEV.
- Nao foi assumida integracao nativa obrigatoria entre agentes externos diferentes dentro do repositorio atual.
- Portanto, a integracao entre duas IAs sera feita por processo, handoff versionado e Git.

## 4. Decisao
- `Antigravity` passa a ser o padrao de desenvolvimento assistido para descoberta, planejamento e iteracao em DEV.
- O repositorio Git continua sendo a fonte unica de verdade para codigo, docs, historico e rollback.
- Validacao final continua obrigatoriamente no projeto local com build, testes e commit rastreavel.

## 5. Modelo operacional de duas IAs
- IA 1 (`Antigravity`): descoberta, navegacao, paralelizacao, brainstorming tecnico, prototipos e execucao em ambiente visual.
- IA 2 (`Codex`/terminal): leitura precisa do repositorio, edicao controlada, testes locais, revisao tecnica e operacao de Git.
- A colaboracao entre as duas IAs deve usar handoff explicito salvo no repositorio quando a tarefa nao couber em uma unica sessao.

## 6. Regras obrigatorias
- Nenhuma alteracao relevante fica somente em workspace externo; tudo precisa voltar para o repositorio.
- Toda tarefa multi-IA deve registrar:
- objetivo;
- contexto;
- arquivos afetados;
- riscos;
- testes executados;
- proximo passo.
- O template padrao de handoff desta base fica em `templates/AI_HANDOFF_ANTIGRAVITY_v00.md`.
- A fila oficial de comandos entre Gemini e Codex fica em `AI_COMMAND_QUEUE.md`.
- O protocolo operacional dessa fila fica em `docs/governanca/PROTOCOLO_FILA_COMANDOS_MULTI_IA_v00.md`.
- Segredos, tokens, cookies e dados sensiveis nao devem ser colados em prompts quando houver alternativa por variavel de ambiente ou arquivo local protegido.
- Mudancas de producao, hotfix e rollback seguem o fluxo normal do repositorio e da pipeline; Antigravity nao substitui gate tecnico.

## 7. Quando usar Antigravity como principal
- exploracao inicial de arquitetura;
- tarefas com varios subproblemas em paralelo;
- validacao visual ou navegacao em browser;
- refinamento de plano tecnico antes de editar a base.

## 8. Quando usar o terminal como principal
- alteracoes cirurgicas em codigo real;
- execucao de build, teste e git;
- hotfix com risco operacional;
- revisao final antes de merge ou deploy.

## 9. Aplicacao pratica nesta base
- O padrao recomendado para novas tarefas e:
1. abrir a tarefa em Antigravity para descoberta e plano;
2. consolidar o handoff;
3. executar alteracoes verificaveis no repositorio local;
4. rodar validacoes;
5. registrar commit.
- Se a tarefa for pequena e objetiva, pode ser executada direto no terminal sem passar por Antigravity.

## 10. Riscos e observacoes
- Risco de duplicacao de contexto entre ferramentas se o handoff for fraco.
- Risco de codigo divergente se a saida do workspace externo nao for consolidada no Git imediatamente.
- Risco de falsa seguranca se o time tratar Antigravity como substituto de teste, revisao ou pipeline.

## 11. Historico de versoes
- v00: definicao inicial do Antigravity como padrao de desenvolvimento assistido em DEV e modelo operacional de duas IAs.
