# Runbook: Nichos WhatsApp

Data: 2026-05-16

## Verificacoes rapidas

1. Abrir a aba de nichos no dashboard.
2. Confirmar se os grupos ativos estao habilitados e com `groupId`.
3. Verificar o bloco `Operacao dos nichos`.
4. Ler alertas ativos, resumo diario e fila de revisao.

## Sinais saudaveis

- Envios aparecem nos nichos esperados.
- `cliques por envio` ajuda a comparar eficiencia, nao apenas volume.
- Eventos novos exibem `motivo` e `confianca`.
- Ofertas ambiguas ficam em revisao.
- Repeticoes do mesmo produto sao bloqueadas por 3 dias.

## Sinais de atencao

- `LK detectado em roteamento recente`
  - revisar origem e tracking antes de ampliar automacao.
- Nicho com `nenhum envio nas ultimas 24h`
  - confirmar se houve oferta elegivel ou se a regra ficou estreita demais.
- `envio(s) sem imagem`
  - revisar URL de midia e resolucao de imagem da oferta.
- Revisoes acumuladas
  - aprovar em lote quando varias ofertas forem claramente do mesmo nicho.

## Fluxo de aprovacao

1. Abrir `Revisar nicho`.
2. Para um item isolado, usar o botao do nicho correto.
3. Para varios itens semelhantes, marcar os checkboxes, escolher o nicho e usar `Aprovar selecionadas`.

## Overrides

Use override quando um produto fizer sentido em mais de um grupo ou quando a regra automatica recorrente estiver boa demais para depender de revisao manual.

Exemplos:

- `lixeira inteligente -> casa, tech`
- `cadeira gamer -> casa, tech`

## Endpoints uteis

- Historico: `GET /api/admin/whatsapp/niche-routes`
- Revisao: `GET /api/admin/whatsapp/niche-reviews`
- Metricas: `GET /api/admin/whatsapp/niche-metrics`
- Overrides: `GET /api/admin/whatsapp/niche-overrides`

