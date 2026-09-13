using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Application.Services;
using AchadinhosBot.Next.Domain.Settings;

namespace AchadinhosBot.Next.Endpoints;

/// <summary>Persists participant-add safety limits without executing any automation work.</summary>
public static class WhatsAppAdminSafetyEndpoints
{
    public static void MapWhatsAppAdminSafetyEndpoints(this WebApplication app)
    {
        app.MapPut("/api/admin/whatsapp/automation/safety", async (
            UpdateWhatsAppParticipantSafetyRequest request,
            ISettingsStore settingsStore,
            CancellationToken ct) =>
        {
            if (request.MaxParticipantsAddedPerDay <= 0)
                return Results.BadRequest(new { error = "O limite diÃƒÂ¡rio deve ser maior que zero." });
            if (request.MinMinutesBetweenParticipantAdds <= 0)
                return Results.BadRequest(new { error = "O cooldown mÃƒÂ­nimo deve ser maior que zero." });

            var settings = await settingsStore.GetAsync(ct);
            var automation = settings.WhatsAppAdminAutomation ??= new WhatsAppAdminAutomationSettings();
            automation.MaxParticipantsAddedPerDay = request.MaxParticipantsAddedPerDay;
            automation.MinMinutesBetweenParticipantAdds = request.MinMinutesBetweenParticipantAdds;
            automation.ParticipantCopyAutomationEnabled = request.ParticipantCopyAutomationEnabled;
            var now = DateTimeOffset.UtcNow;
            WhatsAppParticipantAddSafety.Normalize(automation, now);
            if (!string.IsNullOrWhiteSpace(request.InstanceName))
                WhatsAppParticipantAddSafety.UpdateConfiguredLimits(automation, request.InstanceName, request.MaxParticipantsAddedPerDay, request.MinMinutesBetweenParticipantAdds, now);
            await settingsStore.SaveAsync(settings, ct);

            var remainingQuota = WhatsAppParticipantAddSafety.GetRemainingQuota(automation, request.InstanceName);
            var cooldownActive = WhatsAppParticipantAddSafety.TryGetCooldownBlock(automation, request.InstanceName, now, out var nextAllowedAt, out var cooldownMessage);
            return Results.Ok(new
            {
                success = true, maxParticipantsAddedPerDay = automation.MaxParticipantsAddedPerDay,
                minMinutesBetweenParticipantAdds = automation.MinMinutesBetweenParticipantAdds,
                participantCopyAutomationEnabled = automation.ParticipantCopyAutomationEnabled,
                participantsAddedToday = automation.ParticipantsAddedToday, remainingQuota,
                nextAllowedAt = cooldownActive ? nextAllowedAt : (DateTimeOffset?)null,
                message = cooldownActive ? cooldownMessage : "Travas de seguranÃƒÂ§a atualizadas com sucesso."
            });
        }).RequireAuthorization("AdminOnly");
    }
}

internal sealed record UpdateWhatsAppParticipantSafetyRequest(
    int MaxParticipantsAddedPerDay,
    int MinMinutesBetweenParticipantAdds,
    bool ParticipantCopyAutomationEnabled,
    string? InstanceName = null);
