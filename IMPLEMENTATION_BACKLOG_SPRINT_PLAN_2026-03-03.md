# Implementation Backlog and Sprint Plan - 2026-03-03

Base: `MASTER_AUTOMATION_ANALYSIS_AND_ROADMAP_2026-03-03.md`
Objetivo: transformar o plano estratégico em execução prática por sprint.

## 1. Regras de execução

- Cada item deve ter: prioridade, dono, estimativa, dependências, DoD.
- Nenhuma feature nova entra sem observabilidade mínima e rollback.
- Fluxos de afiliado devem manter regra "no raw link on auto flow".
- Todo deploy com health gate e validação de logs críticos pós-release.

## 2. Legenda

- Prioridade: `P0` (critico), `P1` (alto), `P2` (médio), `P3` (evolutivo).
- Estimativa: `S` (<=1 dia), `M` (2-3 dias), `L` (4-7 dias), `XL` (>1 semana).
- Tipo: `Infra`, `Backend`, `Data`, `AI`, `Product`, `Ops`.

## 3. Backlog priorizado

## Sprint 0 - Estabilizacao operacional imediata (3-5 dias)

1. `P0` Resolver 401 em `/webhook/bot-conversor`  
Tipo: Backend/Ops | Estimativa: M  
Dependências: acesso à config Evolution e app  
DoD:
- assinatura/chave alinhadas e documentadas;
- 0 ocorrências de 401 por 24h em tráfego real;
- endpoint de diagnóstico admin retornando motivo detalhado.

2. `P0` Quality gate global anti-link-cru em todos os auto fluxos  
Tipo: Backend | Estimativa: M  
Dependências: mapeamento de todos os fluxos de dispatch  
DoD:
- regra unificada aplicada em Telegram/WhatsApp/Instagram automáticos;
- testes cobrindo: convertido, não convertido, não afiliado;
- log padronizado com motivo de bloqueio.

3. `P0` Runbook de incidentes de webhook/fila  
Tipo: Ops | Estimativa: S  
Dependências: nenhuma  
DoD:
- arquivo operacional com passos de diagnóstico, mitigação e validação;
- checklist de pós-incidente.

## Sprint 1 - Fundacao de escala e confiabilidade (1-2 semanas)

4. `P0` Idempotência distribuída em Redis  
Tipo: Infra/Backend | Estimativa: L  
Dependências: Redis provisionado  
DoD:
- substituição do `MemoryIdempotencyStore` por Redis;
- chaves por canal/messageId com TTL configurável;
- validação em cenário com instâncias múltiplas.

5. `P1` Fila resiliente com retry + dead-letter  
Tipo: Infra/Backend | Estimativa: XL  
Dependências: decisão de tecnologia (RabbitMQ estável ou Redis Streams)  
DoD:
- retries exponenciais configuráveis;
- DLQ com reprocessamento manual;
- dashboard básico de backlog/failures.

6. `P1` Persistência de ingress de eventos  
Tipo: Data/Backend | Estimativa: L  
Dependências: banco relacional (Postgres recomendado)  
DoD:
- todo webhook persistido antes do processamento;
- trilha de status (received, queued, processed, failed);
- replay por janela de tempo.

## Sprint 2 - Refatoracao estrutural (1-2 semanas)

7. `P1` Fatiar `Program.cs` por bounded context  
Tipo: Backend | Estimativa: XL  
Dependências: Sprint 0 concluída  
DoD:
- endpoints extraídos para módulos por domínio:
  - Auth/Admin
  - Webhooks
  - Conversion
  - Instagram
  - Logs/Diagnostics
- `Program.cs` restrito a composição/bootstrapping.

8. `P1` Orquestrador de mensagens por pipeline  
Tipo: Backend | Estimativa: L  
Dependências: item 7  
DoD:
- pipeline explícito: normalize -> policy -> convert -> enrich -> dispatch;
- contratos/interfaces por etapa;
- testes de integração do pipeline.

## Sprint 3 - Observabilidade e SLO (1 semana)

9. `P1` Métricas e tracing fim-a-fim  
Tipo: Infra/Ops | Estimativa: L  
Dependências: pipeline modular  
DoD:
- OpenTelemetry + logs estruturados com correlation-id;
- métricas por canal/provedor;
- dashboards de latência, erro e throughput.

10. `P1` Alertas operacionais  
Tipo: Ops | Estimativa: M  
Dependências: item 9  
DoD:
- alertas para:
  - webhook 401
  - fila indisponível
  - erro de conversão acima de limiar
  - falha de dispatch por canal
- playbook associado por alerta.

## Sprint 4 - IA de recomendacao e automacao avançada (2-3 semanas)

11. `P2` Product fingerprinting engine  
Tipo: AI/Backend | Estimativa: L  
Dependências: catálogo e metadados consistentes  
DoD:
- fingerprint por marca/modelo/GTIN/categoria;
- score de confiança de matching.

12. `P2` Buscador de alternativas (melhor valor)  
Tipo: AI/Backend | Estimativa: XL  
Dependências: item 11, conectores de lojas  
DoD:
- ranking com preço/frete/prazo/reputação/cupom;
- bloqueio quando confiança baixa;
- resposta explicável por score.

13. `P2` Cards automáticos com cupom e CTA  
Tipo: Product/Backend | Estimativa: L  
Dependências: item 12, gerador de assets  
DoD:
- templates aprovados por canal;
- geração com tracking e cupom válido;
- fallback para texto em caso de falha.

## Sprint 5 - Growth e autonomia completa (2 semanas)

14. `P2` Scheduler inteligente multicanal  
Tipo: Product/Backend | Estimativa: L  
Dependências: observabilidade + score de performance  
DoD:
- janelas por canal;
- prevenção de spam/saturação;
- política de repost com variação de copy.

15. `P3` A/B testing automático de copy/CTA  
Tipo: Product/AI | Estimativa: L  
Dependências: item 14  
DoD:
- experimento configurável;
- coleta de CTR/conversão por variante;
- escolha automática de vencedor.

## 4. Quadro de ownership (preencher)

- Tech Lead: `<nome>`
- Backend Lead: `<nome>`
- Infra/SRE: `<nome>`
- Data/AI: `<nome>`
- Product/Operação afiliados: `<nome>`

## 5. Definicao de pronto (DoD) global

- Código com testes unitários/integrados mínimos.
- Logs estruturados com contexto de canal/mensagem.
- Métrica e alerta para o componente alterado.
- Feature flag para desligamento seguro.
- Documentação de operação atualizada.

## 6. Checklist de release por sprint

1. Build + smoke tests.
2. Deploy em staging.
3. Teste com mensagens reais controladas.
4. Verificação de:
- bloqueio de não afiliado;
- taxa de erro de webhook;
- latência de processamento.
5. Deploy em produção com monitoramento intensivo (30-60 min).

## 7. KPI gate para avançar de fase

- Gate A (fim Sprint 1):
  - webhook 401 resolvido;
  - idempotência distribuída ativa;
  - perda de evento = 0 em teste de carga controlado.

- Gate B (fim Sprint 3):
  - dashboards/alertas ativos;
  - p95 pipeline < 5s;
  - erro por canal < 1%.

- Gate C (fim Sprint 5):
  - recomendador IA ativo com confiança mínima;
  - aumento de CTR >= 15% em 30 dias;
  - operação com baixa intervenção manual.

