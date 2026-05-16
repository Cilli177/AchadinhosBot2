# Entrega: Segmentacao de Nichos WhatsApp

Data: 2026-05-16

## Objetivo

Evoluir a fase de testes dos grupos por nicho sem alterar a funcao atual do grupo principal `REI DAS OFERTAS VIP`, adicionando seguranca operacional, rastreabilidade e leitura de performance para decidir a expansao futura.

## Nichos ativos em teste

- `casa`
- `beleza`
- `moda`
- `tech`
- `fitness_health`

Nichos ainda adiados:

- `mercado_livre`
- `ate_50`

## O que foi entregue

### Roteamento e seguranca

- Roteamento automatico das ofertas que chegam aos grupos fonte para os grupos de nicho.
- Regras deterministicas por termos antes de IA.
- Suporte a classificacao hibrida por override manual, por exemplo `lixeira inteligente -> casa + tech`.
- Janela de repeticao de 3 dias por produto e nicho.
- Identidade de produto mais forte com prioridade para IDs de marketplace e fallback normalizado por loja + titulo.
- Fila persistente para ofertas ambiguas, em vez de envio amplo.

### Operacao e revisao

- Historico de roteamentos por nicho.
- Motivo da classificacao salvo em cada evento.
- Score de confianca da classificacao:
  - `100`: nicho explicito ou override manual;
  - `95`: Mercado Livre com sinal de comissao;
  - `90`: termo forte de nicho;
  - `80`: regra de preco ate R$50;
  - `70`: Mercado Livre sem sinal explicito de comissao;
  - `20`: oferta ambigua enviada para revisao.
- Aprovacao individual e aprovacao em lote da fila de revisao.
- Alertas operacionais para:
  - nicho sem envio nas ultimas 24h;
  - revisoes acumuladas;
  - envio sem imagem;
  - reaparecimento de tracking `LK`.

### Dashboard

- Aba de nichos com:
  - grupos configurados;
  - operacao das ultimas 24h;
  - resumo diario;
  - top produtos por clique;
  - fila de revisao;
  - overrides manuais;
  - ultimos roteamentos com motivo e confianca.
- Metricas por nicho:
  - envios;
  - repeticoes bloqueadas;
  - revisoes;
  - cliques;
  - cliques por envio;
  - ofertas rastreadas unicas.

## Endpoints administrativos

- `GET /api/admin/whatsapp/niche-groups`
- `POST /api/admin/whatsapp/niche-groups/create`
- `PUT /api/admin/whatsapp/niche-groups/{slug}`
- `POST /api/admin/whatsapp/niche-groups/{slug}/invite-campaign`
- `POST /api/admin/offers/route-by-niche`
- `GET /api/admin/whatsapp/niche-routes`
- `GET /api/admin/whatsapp/niche-reviews`
- `POST /api/admin/whatsapp/niche-reviews/{id}/approve`
- `POST /api/admin/whatsapp/niche-reviews/approve-batch`
- `GET /api/admin/whatsapp/niche-overrides`
- `PUT /api/admin/whatsapp/niche-overrides`
- `DELETE /api/admin/whatsapp/niche-overrides/{id}`
- `GET /api/admin/whatsapp/niche-metrics`

## Arquivos de operacao

- `data/whatsapp-niche-route-events.jsonl`
- `data/whatsapp-niche-reviews.json`
- `data/whatsapp-niche-auto-route-seen.json`

## Validacoes executadas

- Build local de `AchadinhosBot.Next`.
- Deploy em PROD via Docker Compose.
- Healthcheck do servico.
- Criacao de item ambiguo e confirmacao de persistencia na fila de revisao.
- Cadastro de override multi-nicho.
- Consulta das metricas por nicho.
- Confirmacao do bloqueio de repeticao recente.

## Pendencias conscientes

- Medir os grupos por mais dias antes de abrir novos nichos comerciais.
- Definir quando `mercado_livre` e `ate_50` entram na operacao ativa.
- Continuar acompanhando `LK` ate zerar reincidencias em rotas antigas.

