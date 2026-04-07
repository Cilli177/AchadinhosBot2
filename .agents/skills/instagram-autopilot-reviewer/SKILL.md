---
name: instagram-autopilot-reviewer
description: (Scaffold) Revisa candidatos de autopilot, aprova/rejeita e aciona publicação.
---

# Contrato
Entrada com `draftId`/filtros e intenção (`review|approve|publish`).
Saída com decisão e próximos passos.

# Regras
- bloquear publish sem mídia/link válidos
- registrar motivo de rejeição
