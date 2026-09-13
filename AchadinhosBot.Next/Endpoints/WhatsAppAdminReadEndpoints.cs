using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Application.Services;
using AchadinhosBot.Next.Domain.Settings;
using Microsoft.AspNetCore.Mvc;

namespace AchadinhosBot.Next.Endpoints;

/// <summary>Read-only operational views for WhatsApp administration.</summary>
public static class WhatsAppAdminReadEndpoints
{
    public static void MapWhatsAppAdminReadEndpoints(this WebApplication app)
    {
        app.MapGet("/api/admin/whatsapp/automation", async (
            ISettingsStore settingsStore,
            CancellationToken ct) =>
        {
            var settings = await settingsStore.GetAsync(ct);
            var automation = settings.WhatsAppAdminAutomation ??= new WhatsAppAdminAutomationSettings();
            var changed = WhatsAppParticipantAddSafety.Normalize(automation, DateTimeOffset.UtcNow);
            if (changed) await settingsStore.SaveAsync(settings, ct);
            return Results.Ok(automation);
        }).RequireAuthorization("AdminOnly");

        app.MapGet("/api/admin/whatsapp/automation/queue", (WhatsAppAutomationQueueService queueService) =>
        {
            var state = queueService.GetState();
            return Results.Ok(new { currentJobId = state.CurrentJobId, pendingCount = state.PendingCount, items = state.Items });
        }).RequireAuthorization("AdminOnly");

        app.MapGet("/api/admin/whatsapp/groups/blast-participants/schedules", async (ISettingsStore settingsStore, CancellationToken ct) =>
        {
            var settings = await settingsStore.GetAsync(ct);
            var automation = settings.WhatsAppAdminAutomation ??= new WhatsAppAdminAutomationSettings();
            var schedules = automation.ParticipantBlastSchedules.OrderByDescending(x => x.CreatedAt).Select(x => new
            {
                id = x.Id, name = x.Name, status = x.Status, enabled = x.Enabled, instanceName = x.InstanceName,
                totalParticipants = x.TotalParticipants, processedParticipants = x.ProcessedParticipants,
                successParticipants = x.SuccessParticipants, failedParticipants = x.FailedParticipants,
                sentParticipants = x.SentParticipantIds.Count, linksSent = x.LinksSent, lastResultMessage = x.LastResultMessage,
                createdAt = x.CreatedAt, lastRunAt = x.LastRunAt, lastProgressAt = x.LastProgressAt, completedAt = x.CompletedAt
            }).ToArray();
            return Results.Ok(new { schedules });
        }).RequireAuthorization("AdminOnly");

        app.MapGet("/api/admin/whatsapp/groups/blast-participants/logs", async (
            [FromQuery] string? operationId, [FromQuery] int? limit, WhatsAppAdminAutomationService automationService, CancellationToken ct) =>
        {
            var items = await automationService.GetBlastLogsAsync(operationId, Math.Clamp(limit ?? 200, 1, 2000), ct);
            return Results.Ok(new { operationId = string.IsNullOrWhiteSpace(operationId) ? items.FirstOrDefault()?.OperationId : operationId.Trim(), items });
        }).RequireAuthorization("AdminOnly");

        app.MapGet("/api/admin/whatsapp/groups/blast-participants/conversion", async (
            [FromQuery] string? scheduleId, [FromQuery] string? groupId, WhatsAppAdminAutomationService automationService, CancellationToken ct) =>
        {
            if (string.IsNullOrWhiteSpace(scheduleId)) return Results.BadRequest(new { error = "scheduleId ÃƒÂ© obrigatÃƒÂ³rio." });
            var snapshot = await automationService.GetBlastConversionAsync(scheduleId.Trim(), groupId, ct);
            if (snapshot is null) return Results.NotFound(new { error = "Disparo nÃƒÂ£o encontrado." });
            return Results.Ok(new { scheduleId = snapshot.ScheduleId, scheduleName = snapshot.ScheduleName, totalSent = snapshot.TotalSent, converted = snapshot.Converted, conversionRate = snapshot.ConversionRate, totalJoinEvents = snapshot.TotalJoinEvents, converters = snapshot.Converters });
        }).RequireAuthorization("AdminOnly");
    }
}
