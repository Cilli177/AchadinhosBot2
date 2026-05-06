# Stabilization Release Checklist

## Before deploy
- `dotnet build` green.
- `dotnet test` green for both test projects.
- `docker-compose.prod.yml` using environment-provided RabbitMQ credentials.
- No real secret left in `appsettings*.json`.

## Deploy gate
- `/health/live` returns `ok`.
- `/health/ready` returns `ok`.
- `/api/admin/ops/status` returns readiness snapshot and no critical alerts.
- Outbox backlog stays below critical threshold.

## Post deploy
- Run `scripts/smoke-runtime.ps1`.
- Validate one controlled conversion request with valid API key.
- Confirm replay workers are reporting healthy status.
- Confirm audit log is receiving `requestId` / `correlationId`.
