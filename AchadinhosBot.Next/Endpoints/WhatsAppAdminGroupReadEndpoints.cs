using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Application.Services;
using AchadinhosBot.Next.Configuration;
using AchadinhosBot.Next.Infrastructure.Security;
using Microsoft.Extensions.Options;

namespace AchadinhosBot.Next.Endpoints;

/// <summary>Read-only WhatsApp group discovery operations. Preserves legacy authorization behavior.</summary>
public static class WhatsAppAdminGroupReadEndpoints
{
    public static void MapWhatsAppAdminGroupReadEndpoints(this WebApplication app)
    {
        // Legacy clients authorize this route with the webhook API key rather than the AdminOnly policy.
        app.MapGet("/api/admin/whatsapp/groups", async (
            HttpContext context,
            string? instanceName,
            IWhatsAppGateway gateway,
            IOptions<WebhookOptions> webhookOptions,
            CancellationToken ct) =>
        {
            if (!AdminAuthorizationHelper.IsAdminAuthorized(context, webhookOptions.Value.ApiKey))
                return Results.Unauthorized();

            var effectiveInstanceName = WhatsAppInstanceRoutingPolicy.ResolveParticipantOpsInstance(instanceName);
            var groups = await gateway.GetGroupsAsync(effectiveInstanceName, ct);
            return Results.Ok(groups);
        });

        app.MapGet("/api/admin/whatsapp/groups/participants", async (
            string groupId,
            string? instanceName,
            IWhatsAppGateway gateway,
            CancellationToken ct) =>
        {
            if (string.IsNullOrWhiteSpace(groupId))
                return Results.BadRequest(new { error = "GroupId ÃƒÆ’Ã‚Â© obrigatÃƒÆ’Ã‚Â³rio." });

            var effectiveInstanceName = WhatsAppInstanceRoutingPolicy.ResolveParticipantOpsInstance(instanceName);
            var participants = await gateway.GetGroupParticipantsAsync(effectiveInstanceName, groupId, ct);
            return Results.Ok(participants);
        }).RequireAuthorization("AdminOnly");
    }
}
