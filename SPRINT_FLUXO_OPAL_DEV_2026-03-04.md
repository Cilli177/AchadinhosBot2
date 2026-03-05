# Fluxo de Sprint - Integracao OPAL (DEV)

Data: 2026-03-04
Escopo: planejar e executar integracao OPAL em DEV com rastreabilidade de cada push.
Premissa: PROD somente apos aprovacao explicita de backup.

## 1) Objetivo da sprint

Integrar geracao assistida de conteudo (OPAL) ao pipeline atual sem quebrar os gates de afiliacao, seguranca e aprovacao.

## 2) Itens da sprint (P1)

1. `P1-OPAL-01` Contrato de dados OPAL
- Definir schema unico de entrada para post/story/catalogo.
- DoD: schema versionado em doc + exemplo valido.

2. `P1-OPAL-02` Ingestao em DEV
- Criar servico de ingestao de fonte estruturada para drafts.
- DoD: import `dry-run` e `apply` funcionando.

3. `P1-OPAL-03` Quality gates no ingestor
- Reusar validacao de conversao afiliada e bloqueio anti-link-cru.
- DoD: item invalido nao publica e gera log de bloqueio com motivo.

4. `P1-OPAL-04` Dashboard operacional
- Exibir itens importados, status (draft/approved/rejected), motivos de bloqueio e fila de aprovacao.
- DoD: visao unica para triagem manual em DEV.

5. `P1-OPAL-05` Observabilidade e trilha
- Registrar import, validacao, aprovacao e publicacao.
- DoD: logs consultaveis por `source_id` e janela de tempo.

6. `P1-OPAL-06` Playbook de promocao
- Fechar checklist DEV -> backup -> PROD.
- DoD: processo documentado e reproduzivel.

## 3) Sequencia de execucao

1. Semana 1
- P1-OPAL-01
- P1-OPAL-02
- P1-OPAL-03

2. Semana 2
- P1-OPAL-04
- P1-OPAL-05
- P1-OPAL-06

## 4) Testes obrigatorios em DEV

1. Caso feliz
- item OPAL com link afiliado valido vira draft e passa para aprovacao.

2. Caso bloqueado
- item com link nao convertido/nao afiliado e bloqueado com motivo.

3. Caso dado incompleto
- item sem campos obrigatorios e rejeitado na ingestao.

4. Reprocessamento
- mesmo `source_id` nao duplica draft.

## 5) Evidencia por push (template)

Preencher a cada push:
- hash do commit;
- item da sprint afetado;
- arquivos alterados;
- testes DEV executados;
- resultado dos testes;
- risco residual;
- rollback sugerido.

Template rapido:

```
Data/Hora:
Commit:
Sprint Item:
Arquivos:
Teste DEV:
Resultado:
Risco:
Rollback:
```

## 6) Gate de aprovacao para PROD

1. DEV validado com evidencias.
2. Revisao tecnica aprovada.
3. Aprovacao explicita de backup.
4. Execucao de deploy/backup conforme runbook.
5. Monitoracao pos deploy (30-60 min).
