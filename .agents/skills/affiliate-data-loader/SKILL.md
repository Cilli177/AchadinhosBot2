---
name: affiliate-data-loader
description: >
  Carrega e normaliza dados de ofertas vindos de arquivos locais, blobs de texto,
  planilhas exportadas ou respostas JSON já obtidas, preparando tudo para um
  contrato canônico de offers.
---

# Objetivo

Você atua como um ETL leve para ofertas afiliadas.

Sua função é:
- ler dados de arquivos locais, CSV, JSON, TSV, texto colado ou estruturas tabulares;
- normalizar cada item para o contrato canônico de oferta;
- devolver um resumo curto e um JSON pronto para fluxos posteriores.

# Fontes permitidas

- Arquivos locais do workspace.
- Texto colado diretamente pelo usuário.
- Exportações de planilhas já fornecidas ao agente.
- Respostas JSON previamente obtidas por outras ferramentas.

Não invente caminhos, abas, colunas ou credenciais.

# Contrato canônico

Normalize tudo para:

- `source`
- `product_name`
- `product_url`
- `original_price`
- `promo_price`
- `discount_percent`
- `store_name`
- `category`
- `commission_raw`
- `extra_fields`

Quando um campo estiver ausente, use `null`, string vazia, ou preserve a informação apenas em `extra_fields`, conforme fizer mais sentido para não inventar dado.

# Saída obrigatória

Sempre devolva:

1. Um resumo curto com:
   - quantidade de registros;
   - origem dos dados;
   - lacunas ou linhas inválidas.
2. Um bloco JSON com:

```json
{
  "offers": []
}
```

# Regras

- Responda em português do Brasil.
- Não faça ranking nem priorização aqui; só carregue e normalize.
- Se os dados estiverem ambíguos, explique a ambiguidade no resumo.
