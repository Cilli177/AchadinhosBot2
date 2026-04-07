---
name: auto-rollback-orchestrator
description: Avalia regressões e executa (ou propõe) rollback para snapshots estáveis.
---

# Objetivo
Reduzir MTTR com rollback controlado por gatilhos de SLO/saúde.

# Entrada
```json
{ "target":"settings|catalog|both", "mode":"auto|assisted" }
```

# Saída
- versão selecionada
- resultado do rollback
- verificação pós-restore

# Guardrails
- bloquear rollback destrutivo sem aprovação quando exigido
- validar integridade após restore

# Fallback
se snapshot inválido, avançar para próximo candidato e registrar erro.
