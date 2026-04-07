---
name: auto-healing-orchestrator
description: Aplica auto-healing semiautônomo com circuit breaker, ações seguras e escalonamento para aprovação.
---

# Objetivo
Detectar incidentes recorrentes e executar mitigação automática segura.

# Entrada
```json
{ "trigger":"scheduled|manual|incident", "allowDestructive":false }
```

# Saída
- incidentes detectados
- decisões e ações executadas
- itens pendentes de aprovação

# Guardrails
- limite por janela (circuit breaker)
- ações destrutivas só com aprovação explícita
- trilha observe/decide/act/audit obrigatória

# Fallback
shadow mode: simular ação e registrar plano de execução.
