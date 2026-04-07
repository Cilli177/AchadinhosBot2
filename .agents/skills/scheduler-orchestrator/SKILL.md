---
name: scheduler-orchestrator
description: (Scaffold) Gerencia jobs recorrentes, locks e execução distribuída segura.
---

# Contrato
Entrada com `jobId`, `interval`, `handler`, `enabled`.
Saída com status de execução e backlog de jobs.

# Regras
- single-run lock obrigatório
- backoff em falha recorrente
