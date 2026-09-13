using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Application.Services;
using AchadinhosBot.Next.Domain.Settings;

namespace AchadinhosBot.Next.Endpoints;

/// <summary>Persists scheduled group-message configuration; execution stays in the queue worker.</summary>
public static class WhatsAppScheduledMessageEndpoints
{
    public static void MapWhatsAppScheduledMessageEndpoints(this WebApplication app)
    {
        app.MapPost("/api/admin/whatsapp/message-schedules", async (CreateScheduledGroupMessageRequest request, ISettingsStore settingsStore, CancellationToken ct) =>
        {
            if (string.IsNullOrWhiteSpace(request.TargetGroupId)) return Results.BadRequest(new { error = "TargetGroupId ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â© obrigatÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â³rio." });
            if (string.IsNullOrWhiteSpace(request.Text)) return Results.BadRequest(new { error = "Texto da mensagem ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â© obrigatÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â³rio." });
            if (!IsPublicImageUrl(request.ImageUrl)) return Results.BadRequest(new { error = "ImageUrl deve ser uma URL publica absoluta valida." });
            var now = DateTimeOffset.UtcNow;
            var settings = await settingsStore.GetAsync(ct);
            var automation = settings.WhatsAppAdminAutomation ??= new WhatsAppAdminAutomationSettings();
            var schedule = new WhatsAppScheduledGroupMessage { Id = Guid.NewGuid().ToString("N"), Name = string.IsNullOrWhiteSpace(request.Name) ? $"Mensagem {request.TargetGroupId}" : request.Name.Trim(), Enabled = true, InstanceName = WhatsAppInstanceRoutingPolicy.ResolveParticipantOpsInstance(request.InstanceName), TargetGroupId = request.TargetGroupId.Trim(), Text = request.Text.Trim(), ImageUrl = string.IsNullOrWhiteSpace(request.ImageUrl) ? null : request.ImageUrl.Trim(), IntervalMinutes = Math.Max(1, request.IntervalMinutes), CreatedAt = now, NextRunAt = request.StartAt ?? now, LastResultMessage = "Agendamento criado." };
            automation.ScheduledGroupMessages.Insert(0, schedule);
            await settingsStore.SaveAsync(settings, ct);
            return Results.Ok(new { success = true, scheduleId = schedule.Id, nextRunAt = schedule.NextRunAt });
        }).RequireAuthorization("AdminOnly");

        app.MapPut("/api/admin/whatsapp/message-schedules/{id}", async (string id, UpdateScheduledGroupMessageRequest request, ISettingsStore settingsStore, CancellationToken ct) =>
        {
            if (string.IsNullOrWhiteSpace(id)) return Results.BadRequest(new { error = "Id ÃƒÂ© obrigatÃƒÂ³rio." });
            if (string.IsNullOrWhiteSpace(request.TargetGroupId)) return Results.BadRequest(new { error = "TargetGroupId ÃƒÂ© obrigatÃƒÂ³rio." });
            if (string.IsNullOrWhiteSpace(request.Text)) return Results.BadRequest(new { error = "Texto da mensagem ÃƒÂ© obrigatÃƒÂ³rio." });
            if (!IsPublicImageUrl(request.ImageUrl)) return Results.BadRequest(new { error = "ImageUrl deve ser uma URL publica absoluta valida." });
            var settings = await settingsStore.GetAsync(ct);
            var automation = settings.WhatsAppAdminAutomation ??= new WhatsAppAdminAutomationSettings();
            var schedule = automation.ScheduledGroupMessages.FirstOrDefault(x => string.Equals(x.Id, id, StringComparison.OrdinalIgnoreCase));
            if (schedule is null) return Results.NotFound(new { error = "Agendamento nÃƒÂ£o encontrado." });
            var now = DateTimeOffset.UtcNow;
            schedule.Name = string.IsNullOrWhiteSpace(request.Name) ? schedule.Name : request.Name.Trim(); schedule.Enabled = request.Enabled; schedule.InstanceName = WhatsAppInstanceRoutingPolicy.ResolveParticipantOpsInstance(request.InstanceName); schedule.TargetGroupId = request.TargetGroupId.Trim(); schedule.Text = request.Text.Trim(); schedule.ImageUrl = string.IsNullOrWhiteSpace(request.ImageUrl) ? null : request.ImageUrl.Trim(); schedule.IntervalMinutes = Math.Max(1, request.IntervalMinutes); schedule.NextRunAt = request.StartAt ?? (request.Enabled ? (schedule.NextRunAt < now ? now : schedule.NextRunAt) : schedule.NextRunAt);
            if (request.Enabled && schedule.NextRunAt < now) schedule.NextRunAt = now;
            schedule.LastResultMessage = "Agendamento atualizado.";
            await settingsStore.SaveAsync(settings, ct);
            return Results.Ok(new { success = true, scheduleId = schedule.Id, enabled = schedule.Enabled, nextRunAt = schedule.NextRunAt, message = schedule.LastResultMessage });
        }).RequireAuthorization("AdminOnly");

        app.MapDelete("/api/admin/whatsapp/message-schedules/{id}", async (string id, ISettingsStore settingsStore, CancellationToken ct) =>
        {
            if (string.IsNullOrWhiteSpace(id)) return Results.BadRequest(new { error = "Id ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â© obrigatÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â³rio." });
            var settings = await settingsStore.GetAsync(ct);
            var automation = settings.WhatsAppAdminAutomation ??= new WhatsAppAdminAutomationSettings();
            var removed = automation.ScheduledGroupMessages.RemoveAll(x => string.Equals(x.Id, id, StringComparison.OrdinalIgnoreCase));
            if (removed == 0) return Results.NotFound(new { error = "Agendamento nÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â£o encontrado." });
            await settingsStore.SaveAsync(settings, ct);
            return Results.Ok(new { success = true });
        }).RequireAuthorization("AdminOnly");
    }

    private static bool IsPublicImageUrl(string? imageUrl)
    {
        if (string.IsNullOrWhiteSpace(imageUrl)) return true;
        return Uri.TryCreate(imageUrl, UriKind.Absolute, out var uri)
            && !uri.Host.Equals("localhost", StringComparison.OrdinalIgnoreCase)
            && !uri.Host.Equals("127.0.0.1", StringComparison.OrdinalIgnoreCase)
            && !uri.Host.Equals("0.0.0.0", StringComparison.OrdinalIgnoreCase)
            && !uri.Host.Equals("host.docker.internal", StringComparison.OrdinalIgnoreCase)
            && !uri.Host.EndsWith(".local", StringComparison.OrdinalIgnoreCase)
            && !uri.Host.EndsWith(".internal", StringComparison.OrdinalIgnoreCase);
    }
}

internal sealed record CreateScheduledGroupMessageRequest(string TargetGroupId, string Text, int IntervalMinutes, string? Name = null, string? ImageUrl = null, DateTimeOffset? StartAt = null, string? InstanceName = null);
internal sealed record UpdateScheduledGroupMessageRequest(string TargetGroupId, string Text, int IntervalMinutes, bool Enabled, string? Name = null, string? ImageUrl = null, DateTimeOffset? StartAt = null, string? InstanceName = null);
