using AchadinhosBot.Next.Configuration;
using AchadinhosBot.Next.Infrastructure.Security;
using Microsoft.Extensions.Options;

namespace AchadinhosBot.Next;

public static class OperationalAdminEndpointsExtensions
{
    public static void MapOperationalAdminEndpoints(
        this WebApplication app,
        bool startTelegramBotWorker,
        bool startTelegramUserbotWorker)
    {
        app.MapGet("/api/admin/ops/status", async (
            HttpContext context,
            OperationalStatusService statusService,
            IOptions<WebhookOptions> webhookOptions,
            CancellationToken ct) =>
        {
            if (!AdminAuthorizationHelper.IsAdminAuthorized(context, webhookOptions.Value.ApiKey))
            {
                return Results.Unauthorized();
            }

            var snapshot = await statusService.GetSnapshotAsync(startTelegramBotWorker, startTelegramUserbotWorker, ct);
            return Results.Ok(snapshot);
        });

        app.MapGet("/api/admin/ops/alerts", async (
            HttpContext context,
            OperationalStatusService statusService,
            IOptions<WebhookOptions> webhookOptions,
            CancellationToken ct) =>
        {
            if (!AdminAuthorizationHelper.IsAdminAuthorized(context, webhookOptions.Value.ApiKey))
            {
                return Results.Unauthorized();
            }

            var snapshot = await statusService.GetSnapshotAsync(startTelegramBotWorker, startTelegramUserbotWorker, ct);
            return Results.Ok(snapshot.Alerts);
        });
    }
}
