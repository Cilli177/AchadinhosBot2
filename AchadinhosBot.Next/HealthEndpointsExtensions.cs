using AchadinhosBot.Next.Endpoints;

namespace AchadinhosBot.Next;

public static class HealthEndpointsExtensions
{
    public static void MapOperationalHealthEndpoints(this WebApplication app, bool startTelegramBotWorker, bool startTelegramUserbotWorker)
    {
        app.MapGet("/health", async (OperationalReadinessService readiness, CancellationToken ct) =>
        {
            var report = await readiness.EvaluateAsync(startTelegramBotWorker, startTelegramUserbotWorker, ct);
            var statusCode = report.Ready ? StatusCodes.Status200OK : StatusCodes.Status503ServiceUnavailable;

            return Results.Json(new
            {
                status = report.Ready ? "ok" : "degraded",
                service = "AchadinhosBot.Next",
                kind = "health",
                ts = DateTimeOffset.UtcNow,
                issues = report.Issues,
                checks = report.Checks
            }, statusCode: statusCode);
        });

        app.MapGet("/health/live", () => Results.Ok(new
        {
            status = "ok",
            service = "AchadinhosBot.Next",
            kind = "liveness",
            ts = DateTimeOffset.UtcNow
        }));

        app.MapGet("/health/ready", async (OperationalReadinessService readiness, CancellationToken ct) =>
        {
            var report = await readiness.EvaluateAsync(startTelegramBotWorker, startTelegramUserbotWorker, ct);

            if (!report.Ready)
            {
                return Results.Json(new
                {
                    status = "degraded",
                    kind = "readiness",
                    issues = report.Issues,
                    checks = report.Checks,
                    ts = DateTimeOffset.UtcNow
                }, statusCode: StatusCodes.Status503ServiceUnavailable);
            }

            return Results.Ok(new
            {
                status = "ok",
                kind = "readiness",
                checks = report.Checks,
                ts = DateTimeOffset.UtcNow
            });
        });
    }
}
