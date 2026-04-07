---
name: whatsapp-group-manager
description: (Scaffold) Gerencia participantes, schedules e blasts com limites operacionais.
---

# Objetivo
Scaffold para operações de grupos WhatsApp com segurança.

# Contrato
Entrada com ação (`copy_participants|schedule_blast|rate_limit_update`) e alvo.
Saída com status por etapa e trilha auditável.

# Regras
- respeitar limites de adição por dia
- exigir autorização admin
