# Smoke Test Release 2026-03-11

Branch candidata:

- `release/prod-2026-03-11-merged`

## Links PROD

- Health: `https://achadinhos.reidasofertas.ia.br/health`
- Dashboard: `https://achadinhos.reidasofertas.ia.br/dashboard`
- Conversor: `https://achadinhos.reidasofertas.ia.br/conversor`
- Admin: `https://achadinhos.reidasofertas.ia.br/conversor-admin`
- Catalogo: `https://achadinhos.reidasofertas.ia.br/catalogo`
- Bio: `https://bio.reidasofertas.ia.br`
- Bio fallback: `https://achadinhos.reidasofertas.ia.br/bio`
- Links fallback: `https://achadinhos.reidasofertas.ia.br/links`
- Analytics summary: `https://achadinhos.reidasofertas.ia.br/api/analytics/summary`
- Analytics hot deals: `https://achadinhos.reidasofertas.ia.br/api/analytics/hot-deals`

## Links DEV

- Health: `https://achadinhos-dev.reidasofertas.ia.br/health`
- Dashboard: `https://achadinhos-dev.reidasofertas.ia.br/dashboard`
- Conversor: `https://achadinhos-dev.reidasofertas.ia.br/conversor`
- Admin: `https://achadinhos-dev.reidasofertas.ia.br/conversor-admin`
- Catalogo: `https://achadinhos-dev.reidasofertas.ia.br/catalogo`
- Bio: `https://achadinhos-dev.reidasofertas.ia.br/bio`
- Analytics summary: `https://achadinhos-dev.reidasofertas.ia.br/api/analytics/summary`
- Analytics hot deals: `https://achadinhos-dev.reidasofertas.ia.br/api/analytics/hot-deals`

## Checklist

- [ ] `PROD /health` responde `status=ok`
- [ ] `PROD /dashboard` abre sem erro visual
- [ ] `PROD /conversor` abre sem erro visual
- [ ] `PROD /conversor-admin` abre sem erro visual
- [ ] Login no admin funciona
- [ ] No admin, testar 1 link Amazon curto
- [ ] No admin, testar 1 link Amazon longo
- [ ] No admin, testar 1 link Shopee
- [ ] No admin, testar 1 link Mercado Livre
- [ ] Titulo, preco e imagem aparecem corretamente
- [ ] Geracao de legenda IA responde
- [ ] Selecao de opcoes de legenda funciona
- [ ] `MODELO 1` aplica fallback corretamente
- [ ] `MODELO 2` aplica fallback corretamente
- [ ] Upload de imagem funciona
- [ ] Upload de video funciona
- [ ] Preview da imagem nao fica esbranquicado
- [ ] Trim/capa/musica salvam no draft
- [ ] Draft sem catalogo permanece com `catalogTarget=none`
- [ ] Draft com catalogo usa o target escolhido
- [ ] Agendamento mostra horario local corretamente
- [ ] Draft agendado muda de status corretamente
- [ ] Publicacao real controlada retorna `mediaId`
- [ ] Item publicado aparece no catalogo esperado
- [ ] `PROD /catalogo` retorna itens
- [ ] `PROD bio.reidasofertas.ia.br` abre corretamente
- [ ] `PROD /bio` abre corretamente
- [ ] `PROD /links` redireciona corretamente
- [ ] `PROD /api/analytics/summary` retorna `200`
- [ ] `PROD /api/analytics/hot-deals` retorna `200`
- [ ] Reinicio do container nao perde midia do admin
- [ ] Drafts apos restart continuam com seus arquivos

## Casos De Teste Sugeridos

Amazon curto:

- `https://amzn.to/4uu02mm`

Amazon longo:

- `https://www.amazon.com.br/Monitor-Gamer-Samsung-HDMI-Preto/dp/B0FBRZ1ZPB/ref=dp_prsubs_d_sccl_1/141-0501938-1361739?pd_rd_w=PGARe&content-id=amzn1.sym.a492cda4-feae-4866-b390-3d39b58dcb26&pf_rd_p=a492cda4-feae-4866-b390-3d39b58dcb26&pf_rd_r=TQHDJJ5JVFAE5E1Y73FJ&pd_rd_wg=1Deyw&pd_rd_r=71ef5b24-f571-41b0-9ba7-f15d41442a74&pd_rd_i=B0FBRZ1ZPB&psc=1`

Shopee:

- `https://s.shopee.com.br/9pZSW7w2iq`

Mercado Livre:

- use um link real atual que ja esteja funcionando no seu fluxo operacional

## Resultado Esperado

Se todos os itens acima forem marcados, a release candidata esta apta para deploy em producao.
