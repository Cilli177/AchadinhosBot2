# Operations Runbook

## Health
1. Check `/health/live`.
2. Check `/health/ready`.
3. Confirm `rabbitMqReachable`, `evolutionReady` and worker health.

## Queue Stalled
1. Inspect readiness outbox backlog.
2. Validate RabbitMQ connectivity and replay workers.
3. Avoid deploy until backlog stops growing.

## Media Failure
1. Inspect `media-failure` and outbound logs.
2. Confirm text fallback happened.
3. Validate media URL reachability and Evolution connectivity.

## Post Deploy
1. Validate `/health`.
2. Send a controlled test message.
3. Confirm no unexpected outbox growth.
4. Confirm audit entries and correlation IDs.
