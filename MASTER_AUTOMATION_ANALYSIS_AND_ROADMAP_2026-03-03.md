# Master Analysis and Roadmap - Sistema Autonomo de Afiliados

Data: 2026-03-03
Escopo: Telegram, WhatsApp (Evolution), Instagram, conversor web, afiliacao multi-loja, IA para enriquecimento e descoberta de melhores ofertas.

## 1. Resumo executivo

O sistema evoluiu bem em funcionalidades, mas hoje opera com alto acoplamento e alguns gargalos de confiabilidade que afetam escalabilidade e previsibilidade.

Principais conclusoes:
- A base funcional existe e cobre grande parte do funil (captura -> conversao -> distribuicao).
- O principal risco tecnico atual e arquitetural: concentracao excessiva em `Program.cs` e processamento misto (orquestracao + regra + transporte no mesmo fluxo).
- O principal risco operacional atual e webhook/infra: `POST /webhook/bot-conversor` com 401 e dependencia de RabbitMQ com disponibilidade instavel.
- O principal risco de negocio atual e qualidade de afiliacao: necessidade de bloqueio estrito para impedir envio de link nao convertido/nao afiliado (ja corrigido no fluxo TelegramUserbot, deve virar regra global).

Direcao recomendada:
- Consolidar um "core autonomo" orientado a eventos, com politicas de qualidade de link obrigatorias, observabilidade fim-a-fim e mecanismos anti-falha em todos os canais.

## 2. Consolidacao do que foi feito / desfeito / pendente

Fontes analisadas:
- `STABLE_RELEASE_2026-03-03.md`
- `AchadinhosBot.Next/README.md`
- `AchadinhosBot.Next/ROADMAP_NATIVE_INTEGRATIONS.md`
- `AchadinhosBot.Next/TASKS_FUTURE_INSIGHTS.md`
- `AchadinhosBot.Next/ORACLE_CLOUD_DEPLOY.md`
- `SETUP_INTEGRASCOES.md`

### 2.1 Ja implementado (estado atual)
- Fluxos multi-canal ativos (Telegram bot/userbot, WhatsApp via Evolution, webhooks, conversor web).
- Bloqueio estrito no TelegramUserbot para conversao invalida/nao afiliada (sem fallback para link cru).
- Tolerancia no gateway WhatsApp quando `connectionState` oscila (tenta envio mesmo com probe instavel).
- Fallback no webhook principal quando publish em fila falha (degrada para processamento interno).
- Camadas de log e trilha (conversion logs, media failures, audit).
- Recursos de conteudo/Instagram autopilot e geracao com IA.

### 2.2 Foi desfeito/corrigido
- Fallback que encaminhava texto original em caso de falha de conversao (risco de link nao afiliado passar).

### 2.3 Pendente critico (curto prazo)
- Resolver 401 recorrente em `/webhook/bot-conversor` (alinhamento de assinatura/chave entre Evolution e app).
- Estabilizar dependencia de fila (RabbitMQ local esta frequentemente indisponivel).
- Padronizar regra de bloqueio estrito em TODOS os fluxos automaticos (nao apenas TelegramUserbot).

## 3. Diagnostico tecnico profundo

## 3.1 Acoplamento e complexidade
- `Program.cs` possui ~9461 linhas e concentra:
  - composicao de servicos
  - dezenas de endpoints
  - regras de dominio
  - logica de orquestracao e fallback
- Isso eleva risco de regressao, dificulta testes e limita evolucao de performance por modulo.

## 3.2 Escalabilidade de estado e armazenamento
- Uso forte de stores em JSON/JSONL locais e `MemoryIdempotencyStore`.
- Bom para bootstrap, ruim para escala horizontal:
  - idempotencia e locks nao sobrevivem a multiplas instancias.
  - risco de duplicidade e inconsistencias sob carga.

## 3.3 Confiabilidade de integrações
- Evolution/Telegram/Instagram dependem de rede e autenticacao sensivel.
- Existem sinais operacionais de:
  - fila indisponivel
  - webhooks com 401
  - oscilacao de checks de estado

## 3.4 Performance potencialmente limitada por fluxo sincronizado
- Partes do processamento ainda executam inline no request/webhook.
- Em picos (varios grupos simultaneos), tende a formar "cadencia" perceptivel no repasse.

## 3.5 Seguranca e governanca
- Existem logs e auditoria, mas ainda faltam:
  - padrao unico de secret management
  - controles de rotacao e validade de credenciais
  - segregacao clara de ambientes (dev/stage/prod) com politicas distintas

## 4. Pontos de correcao imediata (prioridade P0/P1)

## P0 - Deve corrigir agora
1. Webhook 401:
- Criar checklist de assinatura/chave entre Evolution e app.
- Expor endpoint de diagnostico de auth de webhook (somente admin) com causa detalhada.

2. Regra anti-link-cru global:
- Reusar criterio estrito de "link realmente convertido e afiliado" para todos os canais automaticos.
- Se falhar: bloquear envio + registrar motivo estruturado.

3. Idempotencia distribuida:
- Migrar de memoria para Redis (TTL + chave por canal/messageId).
- Garantir deduplicacao consistente entre instancias.

## P1 - Alta prioridade (proxima sprint)
4. Fila resiliente:
- Definir modo operacional oficial:
  - RabbitMQ gerenciado/estavel, ou
  - fallback definitivo para fila Redis Streams/Kafka-lite.
- Implementar retry/backoff com dead-letter por tipo de evento.

5. Reducao de acoplamento:
- Extrair handlers por dominio (WebhookIngress, Routing, ConversionPolicy, Dispatch).
- `Program.cs` deve ficar apenas com composicao e roteamento de endpoint.

## 5. Plano para manter uma versao sempre ativa (Always-On)

Objetivo: zero parada perceptivel e degradacao controlada.

1. Deployment strategy:
- Blue/Green ou Rolling com health gate.
- Warm-up de integracoes antes de liberar trafego.

2. Health em niveis:
- `liveness`: processo no ar.
- `readiness`: dependencias criticas operacionais (fila, Evolution, armazenamento, credenciais).
- `degraded`: respostas com modo de operacao reduzida, sem perder eventos.

3. Persistencia de eventos de entrada:
- Todo webhook recebido deve ter persistencia inicial (ingress log/event store) antes de qualquer processamento.
- Reprocessamento idempotente por cursor.

4. Feature flags operacionais:
- Toggle por canal/modulo (TelegramUserbot, Instagram autopilot, recomendador IA etc).
- Kill-switch rapido por risco de custo/erro.

5. SLOs e alertas:
- Exemplo:
  - Disponibilidade de roteamento > 99.5%
  - Latencia p95 de conversao < 3s
  - Taxa de erro de webhook < 1%
- Alertas por degradacao de fila, 401 webhook, queda de provider, explosao de retries.

## 6. Performance e escalabilidade - melhorias propostas

## 6.1 Arquitetura alvo (macro)
- Camada 1: Ingress (webhooks, polling, comandos).
- Camada 2: Event Bus + Work Queues (desacoplada).
- Camada 3: Policy Engine (quality gates, compliance, anti-duplicidade).
- Camada 4: Conversion + Enrichment + Recommendation.
- Camada 5: Dispatchers por canal.
- Camada 6: Observability + Audit + BI.

## 6.2 Otimizacoes tecnicas
1. Cache de metadados de produto:
- Cache por URL canonica/ID de produto com TTL curto.
- Evita refetch repetitivo em rajadas.

2. Pooling e limites de concorrencia:
- Limitar concorrencia por provider externo.
- Bulkhead por loja/canal para evitar cascata.

3. Persistencia escalavel:
- Migrar stores criticas para Postgres (configs, eventos, aprovacoes, drafts).
- Manter JSONL apenas para log auxiliar/offline.

4. Processamento orientado a eventos:
- Webhook recebe e enfileira rapido.
- Workers especializados processam por tipo.

5. Compensacao/reprocessamento:
- Tabela de "failed deliveries" com retry manual e automatico.
- Replayer por faixa de tempo e canal.

## 7. Novas funcionalidades para automacao completa (afiliados)

## 7.1 IA para "melhor oferta" baseada no produto convertido
Objetivo: dado um link convertido/produto identificado, buscar alternativas com melhor custo-beneficio.

Fluxo sugerido:
1. Extrair fingerprint de produto:
- titulo normalizado, marca, modelo, GTIN/sku, categoria.

2. Buscar candidatos:
- fontes por loja (APIs oficiais quando possivel).
- matching semantico e por atributos.

3. Rankear candidatos:
- score = preco + frete + prazo + reputacao + cashback + cupom + historico de conversao.

4. Guardrails:
- so recomendar se confianca minima.
- bloquear itens sem aderencia de produto.

5. Saida:
- "Oferta principal + alternativas melhores" com justificativa e score.

## 7.2 Cards com cupom e CTA inteligente
Objetivo: elevar CTR e conversao no WhatsApp/Instagram/site.

Componentes:
- motor de template de card (marca, selo de desconto, urgencia, validade).
- enriquecimento com cupom oficial ativo.
- CTA por canal:
  - WhatsApp: mensagem curta + link trackeado
  - Instagram: legenda + CTA comentario/DM
  - Site: cards comparativos e selo "melhor valor"

## 7.3 Motor autonomo de campanhas
- Janela inteligente por horario/canal.
- Deteccao de saturacao (evitar spam em grupo).
- Repost automatico com variacao de copy.
- A/B testing continuo (headline, CTA, formato card).

## 7.4 Agente de compliance e qualidade
- Regras por loja e parceiro.
- Lista de hosts proibidos/nao afiliaveis.
- Bloqueio automatico com explicacao auditavel.
- Workflow de aprovacao manual para casos limítrofes.

## 8. Backlog priorizado (implementacao futura)

## Fase 1 - Fundacao confiavel (2-4 semanas)
1. Resolver 401 webhook (Evolution auth parity).
2. Redis para idempotencia e locks.
3. Unificar quality gates em todos os fluxos automáticos.
4. Extrair handlers de `Program.cs` por dominio.

## Fase 2 - Escala operacional (4-8 semanas)
5. Persistencia de eventos + retry manager + dead-letter.
6. Workers por canal com controle de throughput.
7. Observabilidade completa (traces, metricas, dashboards, alertas).
8. Painel de operacao com fila, falhas, replay e aprovacoes.

## Fase 3 - Automacao inteligente (6-12 semanas)
9. Motor de recomendacao de melhor oferta.
10. Geracao de cards/cupom por IA com templates aprovados.
11. Scheduler autonomo multicanal com A/B testing.
12. Scorecard de performance por loja/canal/campanha.

## 9. KPIs de sucesso (produto e engenharia)

Negocio:
- Taxa de links afiliados validos enviados > 99%.
- Aumento de CTR (meta inicial +20%).
- Aumento de conversao final (meta inicial +10%).

Engenharia:
- p95 de processamento webhook < 500ms no ingresso.
- p95 de pipeline completo < 5s.
- Erro de entrega por canal < 1%.
- Duplicidade de processamento ~0 (idempotencia distribuida).

Operacao:
- MTTD < 5 min, MTTR < 30 min em incidentes comuns.
- Zero perda silenciosa de eventos (todos ingressados auditavelmente).

## 10. Riscos e mitigacoes

1. Dependencia de APIs externas instaveis:
- Mitigar com retry, circuit breaker, fallback e cache.

2. Custo de IA crescer sem controle:
- Budget guardrails por canal/tenant e cache de inferencia.

3. Recomendacao errada de produto:
- Regras de confianca minima + revisao manual opcional.

4. Complexidade de manutencao:
- Modularizacao por bounded context + testes de contrato.

## 11. Proposta de documento operacional complementar

Apos validacao deste master plan, criar:
1. `IMPLEMENTATION_PHASE_1.md` (tarefas tecnicas detalhadas, dono, prazo).
2. `RUNBOOK_OPERATIONS.md` (incidentes, fallback, replay, checklist deploy).
3. `KPI_DASHBOARD_SPEC.md` (metricas, fontes e consultas).

---

Este documento consolida o estado atual e o caminho recomendado para transformar a plataforma em um sistema autonomo, resiliente e escalavel para afiliados.

