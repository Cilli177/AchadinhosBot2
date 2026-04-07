# Relatorio de Fases - Governanca Autonoma

## Status Geral
- Fase de implementacao e validacao: concluida para os componentes core (governance runtime + canary rollback + scheduler lock + endpoints admin + versionamento + anomalias).
- Resultado da bateria de testes automatizados (Release):
  - AchadinhosBot.Next.Tests: 53 aprovados, 5 ignorados, 0 falhas.
  - AchadinhosBot.Tests: 9 aprovados, 0 falhas.

## O que cada funcao nova/alterada faz

### 1. GovernanceRuleEngine
Arquivo: `AchadinhosBot.Next/Application/Services/GovernanceRuleEngine.cs`

- `EvaluateAsync(...)`
  - Objetivo: transformar sinais operacionais em decisoes de governanca.
  - Entradas: backlog de outbox, atividade de workers, snapshot de incidentes/falhas e regras de canario ativas.
  - Saidas: lista de `GovernanceDecision`.
  - Decisoes que pode gerar:
    - `force_outbox_replay`: backlog de fila acima do threshold.
    - `worker_recovery_attempt`: worker sem sucesso recente.
    - `canary_rollback`: canario ativo com threshold de falhas/incidentes excedido.
    - `auto_rollback`: degradacao critica recorrente de runtime.

### 2. GovernanceActionExecutor
Arquivo: `AchadinhosBot.Next/Application/Services/GovernanceActionExecutor.cs`

- `ExecuteAsync(decision, ...)`
  - Objetivo: executar a acao correspondente a cada decisao de governanca.
  - Regras de seguranca:
    - Circuit breaker por janela de tempo para limitar automacao excessiva.
    - Acoes destrutivas obedecem `AllowDestructiveActions`.

- `ExecuteForceOutboxReplayAsync(...)`
  - Reprocessa ate 50 itens por fila (bot, whatsapp, telegram, instagram).
  - Remove item do outbox apos publish bem-sucedido.

- `ExecuteWorkerRecoveryAsync(...)`
  - Recovery seguro via replay rapido de outbox.

- `ExecuteAutoRollbackAsync(...)`
  - Se destrutivo bloqueado: retorna `RequiresApproval=true`.
  - Se permitido: restaura snapshot mais recente de settings.

- `ExecuteCanaryRollbackAsync(...)` (novo)
  - Rollback instantaneo de canario.
  - Desativa todas as regras de canario (`Enabled=false`, `CanaryPercent=0`).

- `IsCircuitOpen()` e `RegisterAction()`
  - Mantem controle de taxa de acoes automaticas por janela.

### 3. GovernanceSchedulerWorker
Arquivo: `AchadinhosBot.Next/Infrastructure/Governance/GovernanceSchedulerWorker.cs`

- `ExecuteAsync(...)`
  - Loop periodico de orquestracao de governanca.

- `RunTickAsync(...)`
  - Pipeline do tick:
    1) `observe` (inicio do ciclo)
    2) `decide` (avalia regras)
    3) `act` (executa ou simula em shadow)
    4) `audit` (encerra ciclo com metadados)
  - Novo comportamento:
    - Lock `single-run` por processo: evita execucao concorrente de tick.
    - Quando concorrencia ocorre, emite evento `governance.tick.skipped_lock`.

- `ProcessOfferAnomaliesAsync(...)`
  - Converte anomalias detectadas em incidentes auditaveis e eventos `observe`.

### 4. Endpoints Admin de Governanca
Arquivo: `AchadinhosBot.Next/Endpoints/GovernanceAdminEndpointsExtensions.cs`

- `/api/admin/governance/status`
  - Snapshot geral + saude por skill.
- `/api/admin/governance/incidents`
  - Incidentes com filtro de abertos.
- `/api/admin/governance/anomalies`
  - Incidentes filtrados para `offer_anomaly`.
- `/api/admin/governance/actions`
  - Acoes automaticas executadas.
- `/api/admin/governance/tuning`
  - Mudancas de tuning aplicadas.
- `/api/admin/canary/rules` (GET/POST)
  - Consulta e atualizacao de regras de canario.
  - Normaliza `ruleId`, `actionType` e faz clamp de `canaryPercent` (0..100).

## Cobertura de Testes Adicionada nesta fase

### Unitarios
- `AchadinhosBot.Next.Tests/GovernanceRuleEngineTests.cs`
  - Backlog critico -> `force_outbox_replay`.
  - Degradacao critica -> `auto_rollback`.
  - Canary ativo + falhas -> `canary_rollback`.

- `AchadinhosBot.Next.Tests/GovernanceActionExecutorTests.cs`
  - `auto_rollback` sem aprovacao -> bloqueado com `RequiresApproval`.
  - `auto_rollback` com aprovacao -> restaura snapshot.
  - `force_outbox_replay` -> publica e limpa filas.
  - Circuit breaker -> bloqueia segunda acao na janela.
  - `canary_rollback` -> desativa todas as regras.

- `AchadinhosBot.Next.Tests/GovernanceSchedulerWorkerTests.cs`
  - Tick completo `observe -> decide -> act -> audit`.
  - `shadow mode` simula acao sem executar executor real.
  - Lock de concorrencia gera `governance.tick.skipped_lock`.

### Integracao
- `AchadinhosBot.Tests/IntegrationTests/GovernanceAdminEndpointsTests.cs`
  - Sem login admin -> `401`.
  - Com login admin -> status de governanca `200` com snapshot.
  - Canary rules POST/GET -> persistencia + normalizacao esperada.

## Observacoes de Operacao
- Testes ignorados continuam sendo os cenarios manuais que dependem de credenciais externas/rede real.
- O caminho para rollout seguro permanece: DEV -> Shadow PROD -> PROD, com validacao pelos endpoints e trilha auditavel no SQLite.
