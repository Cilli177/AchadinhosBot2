---
name: diagnostics-troubleshooter
description: Diagnostica falhas operacionais, identifica causa provável e executa mitigação segura com trilha auditável.
---

# Objetivo
Diagnosticar e mitigar incidentes de webhook, fila, outbox, dependências e workers.

# Entrada
```json
{ "scope":"webhook|queue|outbox|worker|full", "mode":"automatic|assisted" }
```

# Saída
- resumo com causa provável, impacto e status
- JSON com checks, evidências e ações

# Guardrails
- não inventar endpoint/credencial
- ações destrutivas exigem aprovação
- registrar toda ação em trilha de auditoria

# Fallback
se não houver evidência suficiente, retornar hipóteses priorizadas + próximos testes.
