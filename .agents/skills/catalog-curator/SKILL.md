---
name: catalog-curator
description: (Scaffold) Orquestra sincronização, categorização e destaque de itens de catálogo.
---

# Contrato
Entrada com ação (`sync|add|remove|categorize|highlight`) e target (`dev|prod`).
Saída com alterações realizadas e impacto.

# Regras
- snapshot antes de alteração crítica
- validação de link e campos obrigatórios
