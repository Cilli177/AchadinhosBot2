using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Infrastructure.Storage;

namespace AchadinhosBot.Next.Endpoints;

public static class LogsMaintenanceEndpoints
{
    private const string ClearConfirmation = "CLEAR_LOGS";
    private const string RestoreConfirmation = "RESTORE_SNAPSHOT";

    public static void MapLogsMaintenanceEndpoints(this RouteGroupBuilder api)
    {
        api.MapPost("/logs/clicks/clear", (LogClearConfirmationRequest request, IClickLogStore store, LogSnapshotService snapshots, IAuditTrail audit, HttpContext context, CancellationToken ct) => ClearAsync(request, store, "logs.clicks.clear", snapshots, audit, context, ct)).RequireAuthorization("AdminOnly");
        api.MapPost("/logs/instagram-ai/clear", (LogClearConfirmationRequest request, IInstagramAiLogStore store, LogSnapshotService snapshots, IAuditTrail audit, HttpContext context, CancellationToken ct) => ClearAsync(request, store, "logs.instagram_ai.clear", snapshots, audit, context, ct)).RequireAuthorization("AdminOnly");
        api.MapPost("/logs/instagram-publish/clear", (LogClearConfirmationRequest request, IInstagramPublishLogStore store, LogSnapshotService snapshots, IAuditTrail audit, HttpContext context, CancellationToken ct) => ClearAsync(request, store, "logs.instagram_publish.clear", snapshots, audit, context, ct)).RequireAuthorization("AdminOnly");
        api.MapPost("/logs/conversions/clear", (LogClearConfirmationRequest request, IConversionLogStore store, LogSnapshotService snapshots, IAuditTrail audit, HttpContext context, CancellationToken ct) => ClearAsync(request, store, "logs.conversions.clear", snapshots, audit, context, ct)).RequireAuthorization("AdminOnly");
        api.MapPost("/logs/media/clear", (LogClearConfirmationRequest request, IMediaFailureLogStore store, LogSnapshotService snapshots, IAuditTrail audit, HttpContext context, CancellationToken ct) => ClearAsync(request, store, "logs.media.clear", snapshots, audit, context, ct)).RequireAuthorization("AdminOnly");
        api.MapPost("/logs/whatsapp-official-blocked/clear", (LogClearConfirmationRequest request, IOfficialWhatsAppBlockedOfferStore store, LogSnapshotService snapshots, IAuditTrail audit, HttpContext context, CancellationToken ct) => ClearAsync(request, store, "logs.whatsapp_official_blocked.clear", snapshots, audit, context, ct)).RequireAuthorization("AdminOnly");

        MapSnapshots(api, "clicks", sp => sp.GetRequiredService<IClickLogStore>(), "logs.clicks");
        MapSnapshots(api, "instagram-ai", sp => sp.GetRequiredService<IInstagramAiLogStore>(), "logs.instagram_ai");
        MapSnapshots(api, "instagram-publish", sp => sp.GetRequiredService<IInstagramPublishLogStore>(), "logs.instagram_publish");
        MapSnapshots(api, "conversions", sp => sp.GetRequiredService<IConversionLogStore>(), "logs.conversions");
        MapSnapshots(api, "media", sp => sp.GetRequiredService<IMediaFailureLogStore>(), "logs.media");
        MapSnapshots(api, "whatsapp-official-blocked", sp => sp.GetRequiredService<IOfficialWhatsAppBlockedOfferStore>(), "logs.whatsapp_official_blocked");
    }

    private static void MapSnapshots(RouteGroupBuilder api, string routeName, Func<IServiceProvider, object> resolveStore, string auditPrefix)
    {
        api.MapGet($"/logs/{routeName}/snapshots", async (IServiceProvider services, LogSnapshotService snapshots, CancellationToken ct) =>
        {
            var scope = RequireScope(resolveStore(services));
            var items = await snapshots.ListAsync(scope, ct);
            return Results.Ok(new { items = items.Select(item => new { item.SnapshotId, item.CreatedAtUtc, item.State, files = item.Files.Count, bytes = item.Files.Sum(file => file.Bytes), lines = item.Files.Sum(file => file.Lines) }) });
        }).RequireAuthorization("AdminOnly");

        api.MapPost($"/logs/{routeName}/restore/{{snapshotId}}", async (string snapshotId, LogRestoreConfirmationRequest request, IServiceProvider services, LogSnapshotService snapshots, IAuditTrail audit, HttpContext context, CancellationToken ct) =>
        {
            if (!string.Equals(request.Confirmation, RestoreConfirmation, StringComparison.Ordinal))
                return Results.BadRequest(new { error = "A confirmação RESTORE_SNAPSHOT é obrigatória." });
            var scope = RequireScope(resolveStore(services));
            var actor = context.User.Identity?.Name ?? "unknown";
            await audit.WriteAsync($"{auditPrefix}.restore.requested", actor, new { scope = scope.ScopeId, snapshotId }, ct);
            var preRestore = await snapshots.RestoreAsync(scope, snapshotId, ct);
            await audit.WriteAsync($"{auditPrefix}.restore", actor, new { scope = scope.ScopeId, snapshotId, preRestoreSnapshotId = preRestore.SnapshotId }, CancellationToken.None);
            return Results.Ok(new { success = true, preRestoreSnapshotId = preRestore.SnapshotId });
        }).RequireAuthorization("AdminOnly");
    }

    private static async Task<IResult> ClearAsync(LogClearConfirmationRequest request, object store, string auditAction, LogSnapshotService snapshots, IAuditTrail audit, HttpContext context, CancellationToken cancellationToken)
    {
        if (!string.Equals(request.Confirmation, ClearConfirmation, StringComparison.Ordinal))
            return Results.BadRequest(new { error = "A confirmação CLEAR_LOGS é obrigatória." });
        var scope = RequireScope(store);

        var actor = context.User.Identity?.Name ?? "unknown";
        await audit.WriteAsync($"{auditAction}.requested", actor, new { scope = scope.ScopeId }, cancellationToken);
        SnapshotManifest? snapshot = null;
        try
        {
            snapshot = await snapshots.ClearWithSnapshotAsync(scope, cancellationToken);
            await audit.WriteAsync(auditAction, actor, new { scope = snapshot.ScopeId, snapshotId = snapshot.SnapshotId, files = snapshot.Files.Count }, CancellationToken.None);
            return Results.Ok(new { success = true, snapshotId = snapshot.SnapshotId });
        }
        catch
        {
            if (snapshot is not null)
            {
                try { await snapshots.RestoreAsync(scope, snapshot.SnapshotId, CancellationToken.None); }
                catch { /* Preserve the primary failure; the audit event below records recovery was attempted. */ }
            }
            try { await audit.WriteAsync($"{auditAction}.failed", actor, new { scope = scope.ScopeId, snapshotId = snapshot?.SnapshotId, recoveryAttempted = snapshot is not null }, CancellationToken.None); }
            catch { /* Never replace the maintenance failure with a secondary audit failure. */ }
            throw;
        }
    }

    public sealed record LogClearConfirmationRequest(string? Confirmation);
    public sealed record LogRestoreConfirmationRequest(string? Confirmation);

    private static ILogMaintenanceScope RequireScope(object store) => store as ILogMaintenanceScope
        ?? throw new InvalidOperationException("The selected log store does not support protected maintenance.");
}
