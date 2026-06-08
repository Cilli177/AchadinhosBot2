# Entrega: Hardening da Automacao de Afiliados

Data: 2026-05-28

## Objetivo

Endurecer o fluxo principal `captura -> conversao -> tracking -> nichos -> draft/postagem`, mantendo o padrao de tracking curto e evitando que alteracoes temporarias ou artefatos locais entrem em `dev`.

## Branch e commits publicados

Destino publicado: `origin/dev`

- `2694ca9` `Hardening affiliate automation flow`
- `3f03526` `feat: add AI assisted WhatsApp niche routing`
- `8d1ed21` `fix: dedupe official WhatsApp sends by target url`
- `ca8b434` `chore: prune storage backups and jsonl logs`
- `71c2960` `chore: remove local build check artifacts`
- `04df417` `fix: improve health probes and WhatsApp QR visibility`

## O que foi entregue

### Seguranca e tracking

- Remocao da copia de `.env` para output do projeto.
- Sanitizacao reforcada para tokens, secrets, cookies e chaves de API.
- Limpeza de artefatos locais versionados em `_build_check`, incluindo `.env`, DLLs e saidas de validacao.
- `.gitignore` atualizado para bloquear:
  - `_build_check/`
  - `.build-check/`
  - `conversion_audit*.json`
  - `conversion_audit*.csv`
- Padrao curto de tracking preservado, por exemplo `AM-W000001`.
- Letras de origem/nicho mantidas compactas:
  - `W`: WhatsApp VIP
  - `M`: Moda
  - `C`: Casa
  - `B`: Beleza
  - `F`: Fitness/Health
  - `T`: Tech
  - `A`: Ate R$50

### Nichos WhatsApp

- Mantidos 5 nichos ativos mais VIP:
  - `casa`
  - `beleza`
  - `fitness_health`
  - `moda`
  - `tech`
  - VIP recebe todas as ofertas validas.
- Suporte a produto em mais de um nicho.
  - Exemplo: TV, projetor, soundbar e smart home podem ir para `casa` e `tech`.
- Classificacao por IA adicionada como apoio quando as regras deterministicas nao conseguem resolver produto/nicho com seguranca.
- Revisao por IA adicionada para itens pendentes, com modo dry-run e limite por lote.
- Campanhas amplas, como cupons genericos e Copa/figurinhas, podem ser liberadas para todos os nichos ativos quando forem usadas como chamariz.

### WhatsApp oficial e dedupe

- Deduplicacao de envio oficial passou a considerar a URL final rastreada.
- Dois links curtos diferentes que apontam para o mesmo produto final podem ser tratados como o mesmo item no grupo oficial.
- Lookup de tracking continua bloqueando entradas expiradas.
- `LK-*` continua tratado como tracking generico bloqueado no fluxo oficial.

### Resiliencia e storage

- Backups antigos de settings, catalogo e tracking agora sao podados por politica de retencao.
- Logs JSONL tem trimming com intervalo minimo para reduzir custo de I/O.
- Falhas de poda nao bloqueiam escrita operacional.

### Health e QR Code

- Endpoints `/health`, `/health/live` e `/health/ready` aceitam `HEAD`, alem de `GET`.
- QR Code do WhatsApp no dashboard agora fica visivel por pelo menos 10 segundos antes de ser ocultado pelo polling.
- Isso evita que o QR pisque ou suma antes do operador conseguir escanear.

## Alteracoes deixadas fora de proposito

Estas alteracoes estavam no worktree local e nao foram publicadas:

- `AchadinhosBot.Next/Application/Services/TrackingLinkShortenerService.cs`
  - Continha bypass temporario que devolve o link afiliado cru e desliga o encurtador/tracking.
  - Nao deve entrar em `dev`, pois quebra o padrao `AM-W000001` e prejudica relatorios.
- `docker-compose.prod.yml`
  - Continha mudanca com fallback real de grupo oficial.
  - Nao deve entrar sem revisao, pois default de destino oficial pode causar envio em grupo errado.
- `.release-prod` e `.release-prod-merged`
  - Submodulos/trees marcados como dirty.
  - Devem ser tratados separadamente, sem misturar com feature de aplicacao.

## Guardrails para nao repetir o problema

Antes de qualquer commit/push para `dev`:

1. Rodar `git status -sb`.
2. Nao usar `git add -A` quando houver worktree misto.
3. Conferir se nao existe bypass temporario de tracking/shortener:
   - procurar por `TEMPORARY BYPASS`;
   - procurar por `bypassShortening`;
   - confirmar que links oficiais continuam usando `/r/{trackingId}`.
4. Confirmar que nenhum artefato local sera versionado:
   - `_build_check/`
   - `.build-check/`
   - `conversion_audit*.json`
   - `conversion_audit*.csv`
   - DLLs, EXEs e outputs de validacao.
5. Confirmar que `docker-compose.prod.yml` nao adiciona default real de grupo, chat, token ou destino oficial.
6. Confirmar que `.env`, cookies, tokens e session files nao aparecem no diff.
7. Rodar testes focados do fluxo alterado antes do commit.
8. Registrar no documento de entrega qualquer alteracao deixada fora de proposito.

## Validacoes executadas

- `dotnet test AchadinhosBot.Next.Tests/AchadinhosBot.Next.Tests.csproj --no-restore --filter "WhatsAppNicheGroupServiceTests|InstagramPhase2Tests"`
  - Resultado: 20/20 aprovados.
- `dotnet test AchadinhosBot.Next.Tests/AchadinhosBot.Next.Tests.csproj --no-restore --filter "WhatsAppOutboundDedupeKeyBuilderTests|LinkTrackingStoreTests"`
  - Resultado: 9/9 aprovados.
- `dotnet test AchadinhosBot.Next.Tests/AchadinhosBot.Next.Tests.csproj --no-restore --filter "VersionRetentionPolicyTests"`
  - Resultado: 1/1 aprovado.

## Observacoes

- Um teste amplo com filtro `OperationalReadinessServiceTests|WhatsApp` excedeu o timeout local de 124 segundos.
- O teste de catalogo falha enquanto o bypass temporario do encurtador estiver ativo no worktree local, pois ele espera metadados de tracking e o bypass devolve URL crua.
- O bypass temporario deve ser removido ou isolado fora de `dev` antes de uma validacao completa.
