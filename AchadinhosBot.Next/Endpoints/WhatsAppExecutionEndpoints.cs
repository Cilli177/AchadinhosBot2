using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Application.Services;
using AchadinhosBot.Next.Domain.Settings;

namespace AchadinhosBot.Next.Endpoints;

/// <summary>Queues explicit WhatsApp execution requests. No transport action occurs during the HTTP request.</summary>
public static class WhatsAppExecutionEndpoints
{
    public static void MapWhatsAppExecutionEndpoints(this WebApplication app)
    {
        app.MapPost("/api/admin/whatsapp/groups/copy-participants", async (CopyParticipantsRequest request, IWhatsAppTransport transport, WhatsAppAutomationQueueService queueService, ISettingsStore settingsStore, ILogger<Program> logger, CancellationToken ct) =>
        {
            const int maxManualCopyParticipants = 50;
            var effectiveInstanceName = WhatsAppInstanceRoutingPolicy.ResolveParticipantOpsInstance(request.InstanceName);
            if (string.IsNullOrWhiteSpace(request.SourceGroupId) || string.IsNullOrWhiteSpace(request.TargetGroupId)) return Results.BadRequest(new { error = "SourceGroupId e TargetGroupId sÃƒÆ’Ã‚Â£o obrigatÃƒÆ’Ã‚Â³rios." });
            if (request.SourceGroupId == request.TargetGroupId) return Results.BadRequest(new { error = "Grupo de origem e destino nÃƒÆ’Ã‚Â£o podem ser o mesmo." });
            var participantsToCopy = request.ParticipantIds?.Where(x => !string.IsNullOrWhiteSpace(x)).Select(x => x.Trim()).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
            if (participantsToCopy is null || participantsToCopy.Count == 0) return Results.BadRequest(new { error = "Selecione explicitamente os participantes antes de copiar." });
            if (participantsToCopy.Count > maxManualCopyParticipants) return Results.BadRequest(new { error = $"A cÃƒÆ’Ã‚Â³pia manual permite no mÃƒÆ’Ã‚Â¡ximo {maxManualCopyParticipants} participantes por vez." });

            var targetParticipants = await transport.GetGroupParticipantsAsync(effectiveInstanceName, request.TargetGroupId, ct);
            var targetSet = new HashSet<string>(targetParticipants, StringComparer.OrdinalIgnoreCase);
            var filteredParticipants = participantsToCopy.Where(x => !string.IsNullOrWhiteSpace(x) && !targetSet.Contains(x)).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
            var skippedParticipants = participantsToCopy.Count - filteredParticipants.Count;
            if (filteredParticipants.Count == 0) return Results.Ok(new { success = true, message = "Todos os participantes selecionados jÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¡ estÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â£o no grupo de destino.", count = 0, skipped = skippedParticipants });

            var settings = await settingsStore.GetAsync(ct);
            var automation = settings.WhatsAppAdminAutomation ??= new WhatsAppAdminAutomationSettings();
            if (!automation.ParticipantCopyAutomationEnabled) return Results.BadRequest(new { error = "CÃƒÂ³pia de participantes estÃƒÂ¡ pausada globalmente no momento." });
            var now = DateTimeOffset.UtcNow;
            WhatsAppParticipantAddSafety.Normalize(automation, now);
            if (WhatsAppParticipantAddSafety.TryGetCooldownBlock(automation, effectiveInstanceName, now, out var nextAllowedAt, out var cooldownMessage))
            {
                logger.LogWarning("Copia manual bloqueada por cooldown. GrupoDestino={TargetGroupId}, ProximaLiberacao={NextAllowedAt}", request.TargetGroupId, nextAllowedAt);
                return Results.BadRequest(new { error = cooldownMessage, nextAllowedAt });
            }
            var remainingQuota = WhatsAppParticipantAddSafety.GetRemainingQuota(automation, effectiveInstanceName);
            if (remainingQuota <= 0) return Results.BadRequest(new { error = "Limite diÃƒÂ¡rio de adiÃƒÂ§ÃƒÂµes atingido para esta conta.", nextAllowedAt = WhatsAppParticipantAddSafety.GetNextQuotaResetAt(now) });
            if (filteredParticipants.Count > remainingQuota) return Results.BadRequest(new { error = $"Restam apenas {remainingQuota} adiÃƒÂ§ÃƒÂµes disponÃƒÂ­veis hoje para esta conta. Reduza a seleÃƒÂ§ÃƒÂ£o.", remainingQuota });

            async Task<(bool Success, string Message)> ExecuteCopyAsync(CancellationToken jobCt)
            {
                var latestSettings = await settingsStore.GetAsync(jobCt);
                var latestAutomation = latestSettings.WhatsAppAdminAutomation ??= new WhatsAppAdminAutomationSettings();
                if (!latestAutomation.ParticipantCopyAutomationEnabled) return (false, "CÃƒÂ³pia de participantes estÃƒÂ¡ pausada globalmente no momento.");
                var jobNow = DateTimeOffset.UtcNow;
                WhatsAppParticipantAddSafety.Normalize(latestAutomation, jobNow);
                if (WhatsAppParticipantAddSafety.TryGetCooldownBlock(latestAutomation, effectiveInstanceName, jobNow, out _, out var jobCooldownMessage)) return (false, jobCooldownMessage);
                var jobRemainingQuota = WhatsAppParticipantAddSafety.GetRemainingQuota(latestAutomation, effectiveInstanceName);
                if (jobRemainingQuota <= 0) return (false, "Limite diÃƒÂ¡rio de adiÃƒÂ§ÃƒÂµes atingido para esta conta.");
                if (filteredParticipants.Count > jobRemainingQuota) return (false, $"Restam apenas {jobRemainingQuota} adiÃƒÂ§ÃƒÂµes disponÃƒÂ­veis hoje para esta conta.");
                var result = await transport.AddParticipantsAsync(effectiveInstanceName, request.TargetGroupId, filteredParticipants, jobCt);
                if (result.Success) { WhatsAppParticipantAddSafety.RegisterSuccessfulAdd(latestAutomation, effectiveInstanceName, filteredParticipants.Count, jobNow); await settingsStore.SaveAsync(latestSettings, jobCt); }
                return (result.Success, result.Message ?? "OperaÃƒÂ§ÃƒÂ£o concluÃƒÂ­da");
            }

            var queued = await queueService.EnqueueAsync("manual-copy", $"CÃƒÂ³pia manual {request.SourceGroupId} -> {request.TargetGroupId}", ExecuteCopyAsync, ct);
            return Results.Json(new { success = true, queued = true, queueId = queued.Id, message = $"CÃƒÂ³pia enfileirada com {filteredParticipants.Count} participante(s).", count = filteredParticipants.Count, skipped = skippedParticipants }, statusCode: StatusCodes.Status202Accepted);
        }).RequireAuthorization("AdminOnly");

        MapRunNow(app, "/api/admin/whatsapp/copy-schedules/{id}/run-now", "copy-schedule-now", "CÃƒÂ³pia agendada", "CÃƒÂ³pia enfileirada para execuÃƒÂ§ÃƒÂ£o.", static (service, id, ct) => service.RunCopyScheduleNowAsync(id, ct));
        MapRunNow(app, "/api/admin/whatsapp/message-schedules/{id}/run-now", "message-schedule-now", "Mensagem agendada", "Mensagem enfileirada para envio.", static (service, id, ct) => service.RunMessageScheduleNowAsync(id, ct));
    }

    private static void MapRunNow(WebApplication app, string pattern, string kind, string labelPrefix, string message, Func<WhatsAppAdminAutomationService, string, CancellationToken, Task<(bool Success, string Message)>> execute)
    {
        app.MapPost(pattern, async (string id, WhatsAppAutomationQueueService queueService, WhatsAppAdminAutomationService automationService, CancellationToken ct) =>
        {
            if (string.IsNullOrWhiteSpace(id)) return Results.BadRequest(new { error = "Id ÃƒÂ© obrigatÃƒÂ³rio." });
            var job = await queueService.EnqueueAsync(kind, $"{labelPrefix} {id}", token => execute(automationService, id, token), ct);
            return Results.Json(new { success = true, queued = true, queueId = job.Id, message }, statusCode: StatusCodes.Status202Accepted);
        }).RequireAuthorization("AdminOnly");
    }
}

internal sealed record CopyParticipantsRequest(string SourceGroupId, string TargetGroupId, List<string>? ParticipantIds = null, string? InstanceName = null);
