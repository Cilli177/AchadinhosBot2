---
name: auto-tuning-orchestrator
description: Ajusta parâmetros operacionais com base em métricas e registra before/after auditável.
---

# Objetivo
Otimizar thresholds e intervalos sem intervenção manual contínua.

# Entrada
```json
{ "windowHours":24, "dryRun":false }
```

# Saída
- mudanças aplicadas (before/after)
- justificativa e impacto esperado

# Guardrails
- respeitar limites mínimos/máximos
- manter reversibilidade por snapshot

# Fallback
se confiança baixa, emitir recomendação sem aplicar.
