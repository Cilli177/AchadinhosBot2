# Stabilization Package Manifest

## Goal
This package isolates the operational hardening work that should move to production before the next structural refactor. The promotion target is a safe, observable release with explicit readiness, replay protection, audit correlation, and repeatable smoke validation.

## Release Scope
- Operational readiness and health gates
  - `OperationalReadinessService.cs`
  - `HealthEndpointsExtensions.cs`
  - `Configuration/OperationalReadinessOptions.cs`
- Worker continuity and tracking
  - `WorkerActivityTracker.cs`
  - `Infrastructure/Resilience/WhatsAppOutboundReplayWorker.cs`
  - `Infrastructure/Resilience/TelegramOutboundReplayWorker.cs`
  - `Infrastructure/Resilience/BotConversorOutboxReplayWorker.cs`
  - `Infrastructure/Instagram/InstagramOutboundReplayService.cs`
  - `Infrastructure/Monitoring/UptimeHeartbeatService.cs`
- Correlation and audit trail
  - `RequestCorrelationMiddleware.cs`
  - `Infrastructure/Audit/FileAuditTrail.cs`
- Operational snapshot and admin surface
  - `OperationalStatusService.cs`
  - `OperationalAdminEndpointsExtensions.cs`
- Bootstrap extraction for safer composition
  - `StartupServiceRegistrationExtensions.cs`
  - `AuthEndpointsExtensions.cs`
  - `Program.cs`
- Release operations
  - `STABILIZATION_RELEASE_CHECKLIST.md`
  - `OPERATIONS_RUNBOOK.md`
  - `SECURITY_NOTES.md`
  - `scripts/smoke-runtime.ps1`
  - `scripts/collect-stabilization-evidence.ps1`
  - `.github/pull_request_template.md`
  - `RELEASE_HANDOFF.md`

## Release Gates
- `dotnet build AchadinhosBot.Next/AchadinhosBot.Next.csproj -c Debug --no-restore`
- `dotnet test AchadinhosBot.Next.Tests/AchadinhosBot.Next.Tests.csproj --no-restore`
- `dotnet test AchadinhosBot.Tests/AchadinhosBot.Tests.csproj --no-restore`
- `scripts/smoke-runtime.ps1`
- Controlled validation:
  - `GET /health/live`
  - `GET /health/ready`
  - `GET /api/admin/ops/status`
  - `POST /converter` with valid `x-api-key`

## Isolation Guidance
- Do not promote the full current worktree as-is. The repository currently contains unrelated tracked and untracked changes.
- Create a dedicated branch only after staging the files in this manifest.
- If needed, use file-scoped cherry-picks or a patch generated from only the files listed above.
- Keep admin/ops stabilization separate from upcoming pipeline refactors.

## Explicit Exclusions
- UI redesigns and dashboard visual polish.
- Catalog and WhatsApp admin automation expansion that is unrelated to stabilization.
- Storage migration to Redis/Postgres.
- Structural extraction of the ingest/process/outbound pipeline.
- New business features beyond release safety and observability.

## Promotion Outcome
The expected result of this package is simple: production can fail loudly instead of silently, readiness reflects real dependency health, replay workers are visible, smoke validation is repeatable, and the team can communicate release state with evidence instead of assumptions.
