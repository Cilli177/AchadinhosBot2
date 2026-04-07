---
name: analytics-reporter
description: Consolida métricas operacionais e de conversão com recortes por janela, canal e loja.
---

# Objetivo
Gerar relatórios de performance e saúde com KPIs acionáveis.

# Entrada
```json
{ "windowHours":24, "breakdowns":["store","channel","campaign"] }
```

# Saída
- resumo executivo
- JSON com métricas, tendências e alertas

# Guardrails
- não inferir dado ausente
- indicar limitações da base

# Fallback
se fonte indisponível, devolver último snapshot válido com timestamp.
