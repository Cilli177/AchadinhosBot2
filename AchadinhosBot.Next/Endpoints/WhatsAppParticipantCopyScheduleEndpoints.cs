using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Application.Services;
using AchadinhosBot.Next.Domain.Settings;

namespace AchadinhosBot.Next.Endpoints;

/// <summary>Manages participant-copy schedules. These routes only persist configuration; execution remains in the automation worker.</summary>
public static class WhatsAppParticipantCopyScheduleEndpoints
{
    public static void MapWhatsAppParticipantCopyScheduleEndpoints(this WebApplication app)
    {
        app.MapPost("/api/admin/whatsapp/copy-schedules", async (CreateParticipantCopyScheduleRequest request, ISettingsStore settingsStore, IWhatsAppGateway gateway, CancellationToken ct) =>
        {
            if (string.IsNullOrWhiteSpace(request.SourceGroupId) || string.IsNullOrWhiteSpace(request.TargetGroupId))
                return Results.BadRequest(new { error = "SourceGroupId e TargetGroupId sÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â£o obrigatÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â³rios." });
            if (request.SourceGroupId == request.TargetGroupId)
                return Results.BadRequest(new { error = "Grupo de origem e destino nÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â£o podem ser o mesmo." });

            var batchSize = Math.Max(1, request.BatchSize);
            var participantIds = request.ParticipantIds?.Where(x => !string.IsNullOrWhiteSpace(x)).Select(x => x.Trim()).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
            if (participantIds is null || participantIds.Count == 0)
                participantIds = (await gateway.GetGroupParticipantsAsync(null, request.SourceGroupId, ct)).Where(x => !string.IsNullOrWhiteSpace(x)).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
            if (participantIds.Count == 0)
                return Results.BadRequest(new { error = "Nenhum participante disponÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â­vel para agendar." });

            var targetParticipants = await gateway.GetGroupParticipantsAsync(null, request.TargetGroupId, ct);
            var targetSet = new HashSet<string>(targetParticipants, StringComparer.OrdinalIgnoreCase);
            var eligibleParticipants = participantIds.Where(x => !targetSet.Contains(x)).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
            var skippedParticipants = participantIds.Count - eligibleParticipants.Count;
            var settings = await settingsStore.GetAsync(ct);
            var automation = settings.WhatsAppAdminAutomation ??= new WhatsAppAdminAutomationSettings();
            if (!automation.ParticipantCopyAutomationEnabled)
                return Results.BadRequest(new { error = "CÃƒÂ³pia de participantes estÃƒÂ¡ pausada globalmente no momento." });

            var now = DateTimeOffset.UtcNow;
            WhatsAppParticipantAddSafety.Normalize(automation, now);
            var effectiveInstanceName = WhatsAppInstanceRoutingPolicy.ResolveParticipantOpsInstance(request.InstanceName);
            var minIntervalMinutes = automation.ParticipantAddSafetyEnabled ? WhatsAppParticipantAddSafety.GetMinimumIntervalMinutes(automation, effectiveInstanceName) : 1;
            var intervalMinutes = Math.Max(Math.Max(1, request.IntervalMinutes), minIntervalMinutes);
            var schedule = new WhatsAppParticipantCopySchedule
            {
                Id = Guid.NewGuid().ToString("N"),
                Name = string.IsNullOrWhiteSpace(request.Name) ? $"CÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â³pia {request.SourceGroupId} -> {request.TargetGroupId}" : request.Name.Trim(),
                Enabled = true, InstanceName = effectiveInstanceName, SourceGroupId = request.SourceGroupId.Trim(), TargetGroupId = request.TargetGroupId.Trim(),
                PendingParticipantIds = eligibleParticipants, TotalParticipants = eligibleParticipants.Count, ProcessedParticipants = 0, SkippedParticipants = skippedParticipants,
                BatchSize = batchSize, IntervalMinutes = intervalMinutes, CreatedAt = now, NextRunAt = request.StartAt ?? now,
                LastResultMessage = $"Agendamento criado com {eligibleParticipants.Count} participante(s). Repetidos ignorados: {skippedParticipants}."
            };
            automation.ParticipantCopySchedules.Insert(0, schedule);
            await settingsStore.SaveAsync(settings, ct);
            return Results.Ok(new { success = true, scheduleId = schedule.Id, totalParticipants = schedule.TotalParticipants, skippedParticipants, nextRunAt = schedule.NextRunAt, message = schedule.LastResultMessage });
        }).RequireAuthorization("AdminOnly");

        app.MapPut("/api/admin/whatsapp/copy-schedules/{id}", async (string id, UpdateParticipantCopyScheduleRequest request, ISettingsStore settingsStore, IWhatsAppGateway gateway, CancellationToken ct) =>
        {
            if (string.IsNullOrWhiteSpace(id)) return Results.BadRequest(new { error = "Id ÃƒÂ© obrigatÃƒÂ³rio." });
            if (string.IsNullOrWhiteSpace(request.SourceGroupId) || string.IsNullOrWhiteSpace(request.TargetGroupId)) return Results.BadRequest(new { error = "SourceGroupId e TargetGroupId sÃƒÂ£o obrigatÃƒÂ³rios." });
            if (request.SourceGroupId == request.TargetGroupId) return Results.BadRequest(new { error = "Grupo de origem e destino nÃƒÂ£o podem ser o mesmo." });

            var settings = await settingsStore.GetAsync(ct);
            var automation = settings.WhatsAppAdminAutomation ??= new WhatsAppAdminAutomationSettings();
            if (!automation.ParticipantCopyAutomationEnabled) return Results.BadRequest(new { error = "CÃƒÂ³pia de participantes estÃƒÂ¡ pausada globalmente no momento." });
            var schedule = automation.ParticipantCopySchedules.FirstOrDefault(x => string.Equals(x.Id, id, StringComparison.OrdinalIgnoreCase));
            if (schedule is null) return Results.NotFound(new { error = "Agendamento nÃƒÂ£o encontrado." });

            var now = DateTimeOffset.UtcNow;
            WhatsAppParticipantAddSafety.Normalize(automation, now);
            var batchSize = Math.Max(1, request.BatchSize);
            var effectiveInstanceName = WhatsAppInstanceRoutingPolicy.ResolveParticipantOpsInstance(request.InstanceName);
            var minIntervalMinutes = automation.ParticipantAddSafetyEnabled ? WhatsAppParticipantAddSafety.GetMinimumIntervalMinutes(automation, effectiveInstanceName) : 1;
            var intervalMinutes = Math.Max(Math.Max(1, request.IntervalMinutes), minIntervalMinutes);
            var shouldRefreshQueue = request.RefreshQueue || !string.Equals(schedule.SourceGroupId, request.SourceGroupId.Trim(), StringComparison.OrdinalIgnoreCase) || !string.Equals(schedule.TargetGroupId, request.TargetGroupId.Trim(), StringComparison.OrdinalIgnoreCase);
            if (shouldRefreshQueue)
            {
                var participantIds = request.ParticipantIds?.Where(x => !string.IsNullOrWhiteSpace(x)).Select(x => x.Trim()).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
                if (participantIds is null || participantIds.Count == 0)
                    participantIds = (await gateway.GetGroupParticipantsAsync(null, request.SourceGroupId, ct)).Where(x => !string.IsNullOrWhiteSpace(x)).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
                var targetParticipants = await gateway.GetGroupParticipantsAsync(null, request.TargetGroupId, ct);
                var targetSet = new HashSet<string>(targetParticipants, StringComparer.OrdinalIgnoreCase);
                var eligibleParticipants = participantIds.Where(x => !targetSet.Contains(x)).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
                var skippedParticipants = participantIds.Count - eligibleParticipants.Count;
                schedule.PendingParticipantIds = eligibleParticipants; schedule.TotalParticipants = eligibleParticipants.Count; schedule.ProcessedParticipants = 0; schedule.SkippedParticipants = skippedParticipants;
                schedule.CompletedAt = null; schedule.LastRunAt = null; schedule.NextRunAt = request.StartAt ?? now;
                schedule.LastResultMessage = eligibleParticipants.Count == 0 ? "Fila recarregada, mas nenhum participante ficou elegÃƒÂ­vel." : $"Fila recarregada com {eligibleParticipants.Count} participante(s). Repetidos ignorados: {skippedParticipants}.";
            }
            else schedule.NextRunAt = request.StartAt ?? schedule.NextRunAt;

            schedule.Name = string.IsNullOrWhiteSpace(request.Name) ? schedule.Name : request.Name.Trim();
            schedule.Enabled = request.Enabled; schedule.InstanceName = effectiveInstanceName; schedule.SourceGroupId = request.SourceGroupId.Trim(); schedule.TargetGroupId = request.TargetGroupId.Trim(); schedule.BatchSize = batchSize; schedule.IntervalMinutes = intervalMinutes;
            if (request.Enabled && schedule.NextRunAt < now) schedule.NextRunAt = now;
            await settingsStore.SaveAsync(settings, ct);
            return Results.Ok(new { success = true, scheduleId = schedule.Id, enabled = schedule.Enabled, nextRunAt = schedule.NextRunAt, message = schedule.LastResultMessage });
        }).RequireAuthorization("AdminOnly");

        app.MapDelete("/api/admin/whatsapp/copy-schedules/{id}", async (string id, ISettingsStore settingsStore, CancellationToken ct) =>
        {
            if (string.IsNullOrWhiteSpace(id)) return Results.BadRequest(new { error = "Id ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â© obrigatÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â³rio." });
            var settings = await settingsStore.GetAsync(ct);
            var automation = settings.WhatsAppAdminAutomation ??= new WhatsAppAdminAutomationSettings();
            var removed = automation.ParticipantCopySchedules.RemoveAll(x => string.Equals(x.Id, id, StringComparison.OrdinalIgnoreCase));
            if (removed == 0) return Results.NotFound(new { error = "Agendamento nÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â£o encontrado." });
            await settingsStore.SaveAsync(settings, ct);
            return Results.Ok(new { success = true });
        }).RequireAuthorization("AdminOnly");
    }
}

internal sealed record CreateParticipantCopyScheduleRequest(string SourceGroupId, string TargetGroupId, int BatchSize, int IntervalMinutes, string? Name = null, List<string>? ParticipantIds = null, DateTimeOffset? StartAt = null, string? InstanceName = null);
internal sealed record UpdateParticipantCopyScheduleRequest(string SourceGroupId, string TargetGroupId, int BatchSize, int IntervalMinutes, bool Enabled, string? Name = null, List<string>? ParticipantIds = null, DateTimeOffset? StartAt = null, bool RefreshQueue = false, string? InstanceName = null);
