using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Application.Services;

namespace AchadinhosBot.Next.Endpoints;

/// <summary>Administrative membership history and synchronization operations.</summary>
public static class WhatsAppMembershipEndpoints
{
    public static void MapWhatsAppMembershipEndpoints(this WebApplication app)
    {
        app.MapGet("/api/admin/whatsapp/membership-events", async (
            IWhatsAppGroupMembershipStore store,
            CancellationToken ct) =>
        {
            var events = await store.ListAsync(ct);
            return Results.Ok(events.OrderByDescending(x => x.Timestamp).Take(1000));
        }).RequireAuthorization("AdminOnly");

        app.MapPost("/api/admin/whatsapp/membership-events/sync", async (
            WhatsAppMembershipSyncService syncService,
            CancellationToken ct) =>
        {
            await syncService.SynchronizeAllGroupsNowAsync(ct);
            return Results.Ok(new { success = true });
        }).RequireAuthorization("AdminOnly");
    }
}
