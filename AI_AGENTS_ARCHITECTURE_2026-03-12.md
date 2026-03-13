# AI Agents Architecture - 2026-03-12

Objetivo: introduzir agentes de IA no AchadinhosBot.Next sem repetir os erros de acoplamento, baixa observabilidade ou automacao sem controle.

## 1. Principios

- Agentes nao publicam sozinhos na primeira fase.
- Toda acao proposta deve ser explicavel e auditavel.
- O agente produz um plano; o sistema executa ferramentas controladas.
- O estado oficial continua no dominio atual: drafts, catalogo, analytics, logs e settings.
- Feature flags e modo degradado continuam obrigatorios.

## 2. Arquitetura alvo

Camadas:

1. Context Builder
- coleta contexto do dominio;
- exemplos: drafts, cliques, catalogo, historico de publish, score da IA.

2. Agent Policy Layer
- aplica guardrails antes de qualquer recomendacao;
- exemplos:
  - nunca sugerir raw link;
  - nao sugerir catalogo PROD fora de ambiente/processo permitido;
  - bloquear automacao sem midia, legenda ou link.

3. Agent Reasoning Layer
- gera recomendacoes com base no contexto;
- pode usar heuristica deterministica, IA generativa ou modelo hibrido.

4. Action Planner
- transforma recomendacoes em acoes controladas;
- exemplos:
  - adicionar ao catalogo;
  - destacar na bio;
  - revisar legenda;
  - agendar repost.

5. Human Approval / Execution
- operador aprova ou rejeita;
- execucao sempre via endpoints/servicos ja existentes.

## 3. Fases de rollout

### Fase A - Suggestion Only
- agente apenas sugere;
- sem side effects;
- foco: curadoria de ofertas e analise de performance.

### Fase B - Assisted Execution
- agente monta plano de acao;
- operador aprova no dashboard/admin;
- execucao usa servicos existentes.

### Fase C - Limited Autonomy
- apenas para rotinas de baixo risco e reversiveis;
- exemplos:
  - sincronizacao de catalogo DEV;
  - marcacao de destaque interno;
  - geracao de rascunho.

## 4. Primeiros agentes recomendados

### 4.1 Agente Curador de Ofertas
Responsabilidade:
- analisar drafts publicados, rascunhos e catalogo;
- identificar o que vale entrar no catalogo;
- sugerir destaque na bio;
- apontar rascunhos prontos para revisao/publicacao.

Entradas:
- drafts;
- catalogo DEV/PROD;
- logs de clique;
- janela de tempo.

Saidas:
- score por draft;
- acao recomendada;
- razoes;
- riscos;
- target sugerido do catalogo.

### 4.2 Agente de Performance
Responsabilidade:
- ler eventos, funil e CTR;
- recomendar horario, CTA, formato e canal para as proximas ofertas.

### 4.3 Agente de Recuperacao
Responsabilidade:
- detectar falhas recorrentes em publish/schedule;
- sugerir reprocessamento seguro e causa provavel.

## 5. Guardrails

- suggestion-only por default;
- toda recomendacao deve incluir:
  - score;
  - razoes;
  - riscos;
  - timestamp;
  - nome/versao do agente;
- toda invocacao autenticada deve gerar audit trail;
- nenhum agente grava em PROD sem endpoint/acao explicita separada;
- nenhum agente deve depender diretamente de Infrastructure onde houver abstracao de Application.

## 6. Contratos iniciais

Servico inicial:
- `IOfferCurationAgentService`

Endpoint inicial:
- `POST /api/agents/offers/curate`

Modo inicial:
- `suggestion_only`

## 7. Backlog da fase

### Etapa 1
- documentacao da arquitetura;
- modelos de request/result;
- servico `OfferCurationAgentService`;
- endpoint autenticado de preview.

### Etapa 2
- UI no dashboard/admin para inspecionar recomendacoes;
- filtros por status, score e target;
- acao manual "aplicar recomendacao".

### Etapa 3
- usar provider de IA para justificar recomendacoes de performance;
- score combinado heuristica + IA;
- benchmark dos providers no IA Lab.

## 8. Criterios de pronto

- build limpo;
- logs/audit da execucao do agente;
- sem side effect em producao na primeira fase;
- resposta explicavel e consistente para drafts reais do sistema.
