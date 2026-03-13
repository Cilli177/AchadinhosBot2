# Smoke Test Guiado Release 2026-03-11

Objetivo:

- validar a release candidata em ordem operacional
- evitar testes fora de sequência
- reduzir risco de falso negativo

Branch candidata:

- `release/prod-2026-03-11-merged`

## Etapa 1. Disponibilidade Basica

1. Abrir:
   - `https://achadinhos.reidasofertas.ia.br/health`
   - `https://achadinhos-dev.reidasofertas.ia.br/health`
2. Confirmar:
   - resposta `status=ok`
   - sem erro de tunnel

## Etapa 2. Acesso Web Basico

1. Abrir em `PROD`:
   - `https://achadinhos.reidasofertas.ia.br/dashboard`
   - `https://achadinhos.reidasofertas.ia.br/conversor`
   - `https://achadinhos.reidasofertas.ia.br/conversor-admin`
   - `https://achadinhos.reidasofertas.ia.br/catalogo`
2. Abrir em `DEV`:
   - `https://achadinhos-dev.reidasofertas.ia.br/conversor`
   - `https://achadinhos-dev.reidasofertas.ia.br/conversor-admin`
   - `https://achadinhos-dev.reidasofertas.ia.br/catalogo`
3. Confirmar:
   - paginas carregam
   - sem erro visual grave
   - sem texto quebrado

## Etapa 3. Login Admin

1. Entrar no admin:
   - `https://achadinhos-dev.reidasofertas.ia.br/conversor-admin`
2. Confirmar:
   - login funciona
   - painel abre
   - sem popup com caracteres estranhos

## Etapa 4. Conversor De Links

Executar no `DEV`:

1. Amazon curto:
   - `https://amzn.to/4uu02mm`
2. Amazon longo:
   - `https://www.amazon.com.br/Monitor-Gamer-Samsung-HDMI-Preto/dp/B0FBRZ1ZPB/ref=dp_prsubs_d_sccl_1/141-0501938-1361739?pd_rd_w=PGARe&content-id=amzn1.sym.a492cda4-feae-4866-b390-3d39b58dcb26&pf_rd_p=a492cda4-feae-4866-b390-3d39b58dcb26&pf_rd_r=TQHDJJ5JVFAE5E1Y73FJ&pd_rd_wg=1Deyw&pd_rd_r=71ef5b24-f571-41b0-9ba7-f15d41442a74&pd_rd_i=B0FBRZ1ZPB&psc=1`
3. Shopee:
   - `https://s.shopee.com.br/9pZSW7w2iq`
4. Mercado Livre:
   - usar um link real atual do seu fluxo

Confirmar em cada caso:

- titulo preenchido
- preco preenchido
- imagem preenchida
- loja correta
- sem fallback vazio

## Etapa 5. Legendas

No `DEV admin`:

1. Gerar legenda IA
2. Selecionar opcao 1
3. Selecionar opcao 2
4. Aplicar `MODELO 1`
5. Aplicar `MODELO 2`

Confirmar:

- selecao funciona
- legenda entra no textarea
- contador atualiza
- CTA e hashtags aparecem corretos

## Etapa 6. Midia

No `DEV admin`:

1. Fazer upload de imagem
2. Fazer upload de video
3. Ajustar crop/preset
4. Ajustar trim do video
5. Capturar capa
6. Preencher trilha/musica

Confirmar:

- upload funciona
- preview nao fica esbranquicado
- capa salva
- trim salva
- draft guarda os metadados

## Etapa 7. Draft Sem Catalogo

No `DEV admin`:

1. Criar draft com `catalogTarget=none`
2. Salvar
3. Reabrir o draft

Confirmar:

- continua `none`
- nao herda `prod`

## Etapa 8. Draft Com Catalogo

No `DEV admin`:

1. Criar draft com `catalogTarget=dev`
2. Salvar
3. Reabrir

Confirmar:

- target permanece `dev`
- nao muda para `prod`

## Etapa 9. Agendamento

No `DEV admin`:

1. Agendar um post alguns minutos a frente
2. Observar o historico

Confirmar:

- horario aparece no horario local do navegador
- status passa por `Agendado`
- depois `Publicando` ou `Publicado`
- se falhar, erro legivel

## Etapa 10. Publicacao Real Controlada

No `DEV admin`:

1. Fazer uma publicacao real controlada
2. Observar retorno e historico

Confirmar:

- `mediaId` aparece
- reel nao falha por container nao pronto
- historico mostra status correto

## Etapa 11. Catalogo

Abrir:

- `https://achadinhos-dev.reidasofertas.ia.br/catalogo`
- `https://achadinhos.reidasofertas.ia.br/catalogo`

Confirmar:

- item vai para o catalogo esperado
- nao mistura `dev` e `prod`
- item abre corretamente

## Etapa 12. Bio Hub

Abrir em `PROD`:

- `https://bio.reidasofertas.ia.br`
- `https://achadinhos.reidasofertas.ia.br/bio`
- `https://achadinhos.reidasofertas.ia.br/links`

Confirmar:

- Bio Hub dinamico abre
- `/links` redireciona corretamente
- sem landing estatica quebrada

## Etapa 13. Analytics

Abrir:

- `https://achadinhos.reidasofertas.ia.br/api/analytics/summary`
- `https://achadinhos.reidasofertas.ia.br/api/analytics/hot-deals`

Confirmar:

- `200 OK`
- payload valido

## Etapa 14. Persistencia

1. Reiniciar o container do ambiente testado
2. Reabrir o admin
3. Reabrir um draft com midia

Confirmar:

- arquivos continuam disponiveis
- draft nao perde video/imagem

## Fechamento

Se todas as etapas acima passarem:

- a release candidata esta pronta para aprovacao operacional
- o deploy para producao pode seguir com risco controlado
