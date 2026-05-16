# Stabilization Release Handoff

## What This Release Delivers
- Background worker failures stop the host instead of being ignored silently.
- Readiness reflects RabbitMQ, Evolution, Telegram userbot requirements, and local outbox pressure.
- Replay workers for outbound resilience are explicitly part of the runtime.
- Audit records can be correlated with request and operation identifiers.
- Admins have a compact operational snapshot at `/api/admin/ops/status`.
- Runtime smoke validation is scriptable and repeatable.

## Evidence Checklist
- Attach build output.
- Attach both test outputs.
- Attach smoke output.
- Attach one `ops-status.json` snapshot from the candidate environment.
- Record one controlled `/converter` validation with timestamp and result.

## PR Summary Template
Title:
`stabilization: operational readiness, replay continuity and release gates`

Suggested body:

```md
## Summary
- hardens worker failure behavior to prevent silent outages
- exposes operational readiness and admin status snapshot
- registers replay/heartbeat services required for outbound continuity
- adds release checklist and smoke/evidence scripts

## Included
- readiness and health wiring
- replay worker registration and worker tracking
- request correlation and audit enrichment
- admin ops snapshot endpoints
- release checklist, handoff and smoke automation

## Validation
- [ ] dotnet build AchadinhosBot.Next/AchadinhosBot.Next.csproj -c Debug --no-restore
- [ ] dotnet test AchadinhosBot.Next.Tests/AchadinhosBot.Next.Tests.csproj --no-restore
- [ ] dotnet test AchadinhosBot.Tests/AchadinhosBot.Tests.csproj --no-restore
- [ ] scripts/smoke-runtime.ps1
- [ ] controlled POST /converter with valid x-api-key

## Risks
- current repository has unrelated local changes; this PR must stay limited to the stabilization manifest
- smoke still depends on a configured runtime with valid environment secrets

## Rollback
- redeploy previous image/tag
- verify /health/live and /health/ready
- confirm outbox backlog did not increase during rollback window
```

## Slack Update Draft
```text
Pacote de estabilizacao pronto para release candidate.

Inclui:
- readiness operacional real
- replay workers registrados
- correlation/audit no runtime
- snapshot admin em /api/admin/ops/status
- checklist + smoke script para validacao

Gates executados:
- dotnet build
- dotnet test (2 suites)
- smoke/runtime checklist pendente no ambiente candidato

Proximo passo:
- promover para ambiente candidato
- anexar evidencias do smoke e do /converter controlado
- abrir PR limpo apenas com o escopo do manifesto
```

## Notion / Runbook Seed
- Context: stabilization release for safe production promotion.
- Scope: readiness, replay continuity, audit correlation, operational snapshot, smoke evidence.
- Status: candidate package prepared locally.
- Blocking item: worktree must be isolated before PR promotion.
- Next technical step after release: simple admin view for operational snapshot.

## Operator Notes
- Use `scripts/collect-stabilization-evidence.ps1` in the candidate environment to generate a timestamped evidence bundle.
- If `/api/admin/ops/status` requires `X-Admin-Key`, pass it explicitly during smoke and evidence capture.
- If smoke fails because the app is not running, the release gate is incomplete rather than green.
