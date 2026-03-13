# Handoff - Agentes de IA - 2026-03-12

## Estado atual

Foi iniciada a estrutura de agentes de IA no projeto com foco em operacao assistida e baixo risco.

### Base implementada

- Arquitetura e guardrails documentados em:
  - [AI_AGENTS_ARCHITECTURE_2026-03-12.md](C:/AchadinhoBot2/AchadinhosBot2/AI_AGENTS_ARCHITECTURE_2026-03-12.md)
- Modelos de dominio do agente:
  - [OfferCurationModels.cs](C:/AchadinhoBot2/AchadinhoBot2/AchadinhosBot.Next/Domain/Agents/OfferCurationModels.cs)
- Contrato do servico:
  - [IOfferCurationAgentService.cs](C:/AchadinhoBot2/AchadinhoBot2/AchadinhosBot.Next/Application/Abstractions/IOfferCurationAgentService.cs)
- Implementacao do primeiro agente:
  - [OfferCurationAgentService.cs](C:/AchadinhoBot2/AchadinhoBot2/AchadinhosBot.Next/Application/Services/OfferCurationAgentService.cs)
- Registro e endpoint autenticado:
  - [Program.cs](C:/AchadinhoBot2/AchadinhoBot2/AchadinhosBot.Next/Program.cs)
  - endpoint: `POST /api/agents/offers/curate`

### UI implementada

- Nova aba `Agentes` no dashboard:
  - [dashboard.html](C:/AchadinhoBot2/AchadinhoBot2/AchadinhosBot.Next/wwwroot/dashboard.html)
  - [dashboard.js](C:/AchadinhoBot2/AchadinhoBot2/AchadinhosBot.Next/wwwroot/dashboard.js)

### Comportamento atual do agente

Modo:
- `suggestion_only`

Acoes sugeridas hoje:
- `add_to_catalog`
- `highlight_on_bio`
- `review_and_publish`
- `review`

Regras atuais:
- avalia drafts, agendados e publicados;
- usa drafts + catalogo + click logs;
- nao executa publish sozinho;
- a unica acao manual ligada na UI hoje e `Adicionar ao catalogo`.

## Correcoes feitas durante a implementacao

### 1. Janela muito restritiva

Problema:
- o agente podia voltar vazio em janelas curtas.

Correcao:
- fallback automatico para 30 dias quando nao ha sinais recentes.

### 2. Drafts reais do conversor-admin sem `OfferUrl`

Problema:
- drafts do fluxo real guardavam o destino em `CTAs` e `AutoReplyLink`;
- o agente lia apenas `OfferUrl`;
- isso fazia os drafts parecerem incompletos.

Correcao:
- `OfferCurationAgentService` agora resolve o link efetivo por:
  - `OfferUrl`
  - primeiro `CTA.Link`
  - `AutoReplyLink`

### 3. Regra final conservadora demais

Problema:
- mesmo com draft util, a recomendacao podia virar `none`.

Correcao:
- drafts com link/midia/status util agora podem ao menos virar `review`.

## Validacao mais recente

Build:
- `dotnet build .\AchadinhosBot.Next\AchadinhosBot.Next.csproj --no-restore`
- resultado: `0 warnings / 0 errors`

DEV:
- `docker compose -f docker-compose.yml -f docker-compose.dev.override.yml up -d --build achadinhos-next`
- health:
  - `http://127.0.0.1:8083/health`
  - status: `ok`

Resposta atual do agente no DEV:
- `evaluatedDrafts: 3`
- `suggestedActions: 3`
- acao dominante:
  - `review_and_publish`

## Onde testar

Dashboard DEV:
- `https://achadinhos-dev.reidasofertas.ia.br/dashboard`

Passos:
1. entrar no dashboard;
2. abrir aba `Agentes`;
3. ajustar janela e quantidade;
4. clicar em `Atualizar recomendacoes`.

Esperado:
- resumo da analise;
- cards de highlights;
- tabela com score, razoes, riscos e acao sugerida.

## Pendencias imediatas

1. Ligar mais acoes manuais na aba `Agentes`
- por exemplo:
  - abrir draft no admin;
  - marcar para bio;
  - reagendar;
  - publicar agora.

2. Criar endpoint/acao real para `highlight_on_bio`
- hoje a recomendacao aparece, mas nao existe aplicacao operacional dedicada.

3. Melhorar o scoring
- incluir mais peso para:
  - clicks por janela
  - status `published`
  - presença em catalogo
  - CTR por oferta
  - qualidade da legenda/midia

4. Levar a aba para `prod` depois do smoke test no `dev`.

## Como retomar comigo

Quando voltar, use algo direto assim:

```text
Retomar a fase de agentes de IA no AchadinhosBot.Next. Leia HANDOFF_AGENTES_2026-03-12.md e continue da aba Agentes no dashboard DEV. Prioridade: [diga aqui a prioridade].
```

Exemplos:

```text
Retomar a fase de agentes de IA no AchadinhosBot.Next. Leia HANDOFF_AGENTES_2026-03-12.md e continue da aba Agentes no dashboard DEV. Prioridade: ligar a ação highlight_on_bio.
```

```text
Retomar a fase de agentes de IA no AchadinhosBot.Next. Leia HANDOFF_AGENTES_2026-03-12.md e continue da aba Agentes no dashboard DEV. Prioridade: subir a funcionalidade para produção com smoke test.
```

```text
Retomar a fase de agentes de IA no AchadinhosBot.Next. Leia HANDOFF_AGENTES_2026-03-12.md e continue da aba Agentes no dashboard DEV. Prioridade: melhorar o score usando analytics.
```

## Observacao operacional

No `dev`, o `docker compose` ainda mostra warnings de interpolacao por variaveis com `$` no ambiente local. Isso nao bloqueou a subida do app, mas continua sendo uma limpeza tecnica pendente.
