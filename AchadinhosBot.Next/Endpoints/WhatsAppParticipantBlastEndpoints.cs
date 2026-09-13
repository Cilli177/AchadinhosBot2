using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Application.Services;
using AchadinhosBot.Next.Domain.Settings;
using Microsoft.AspNetCore.Mvc;

namespace AchadinhosBot.Next.Endpoints;

/// <summary>Validates and queues participant blasts; delivery is performed only by the queue worker.</summary>
public static class WhatsAppParticipantBlastEndpoints
{
    public static void MapWhatsAppParticipantBlastEndpoints(this WebApplication app)
    {
        app.MapPost("/api/admin/whatsapp/groups/blast-participants/scheduled", async (CreateParticipantBlastScheduleRequest request, [FromServices] ISettingsStore settingsStore, [FromServices] IWhatsAppGroupMembershipStore membershipStore, [FromServices] WhatsAppAutomationQueueService queueService, [FromServices] WhatsAppAdminAutomationService automationService, CancellationToken ct) =>
        {
            var sourceGroupIds = (request.SourceGroupIds ?? new List<string>()).Append(request.SourceGroupId ?? string.Empty).Where(x => !string.IsNullOrWhiteSpace(x)).Select(x => x.Trim()).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
            if (sourceGroupIds.Count == 0) return Results.BadRequest(new { error = "Informe ao menos um grupo de origem." });
            if (string.IsNullOrWhiteSpace(request.LinkUrl)) return Results.BadRequest(new { error = "Informe o link oficial do grupo." });
            if (!Uri.TryCreate(request.LinkUrl.Trim(), UriKind.Absolute, out var inviteUri) || !inviteUri.Host.Equals("chat.whatsapp.com", StringComparison.OrdinalIgnoreCase)) return Results.BadRequest(new { error = "Use um link oficial do chat.whatsapp.com." });
            var inviteCode = inviteUri.AbsolutePath.Trim('/').Trim();
            var expectedConfirmation = string.IsNullOrWhiteSpace(inviteCode) ? request.LinkUrl.Trim() : inviteCode;
            if (!string.Equals((request.LinkConfirmation ?? string.Empty).Trim(), expectedConfirmation, StringComparison.Ordinal)) return Results.BadRequest(new { error = "ConfirmaÃƒÂ§ÃƒÂ£o do link nÃƒÂ£o confere com o convite oficial." });
            var pitch = string.IsNullOrWhiteSpace(request.SecurityPitch) ? request.Message : request.SecurityPitch;
            if (string.IsNullOrWhiteSpace(pitch)) return Results.BadRequest(new { error = "Informe o pitch de seguranÃƒÂ§a do disparo." });

            var effectiveInstanceName = WhatsAppInstanceRoutingPolicy.ResolveParticipantOpsInstance(request.InstanceName);
            var participantIds = (request.ParticipantIds ?? new List<string>()).Where(x => !string.IsNullOrWhiteSpace(x)).Select(x => x.Trim()).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
            if (request.UseAllParticipantsFromSources)
            {
                var allParticipants = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                foreach (var sourceGroupId in sourceGroupIds)
                    foreach (var participantId in await membershipStore.GetParticipantsAsync(sourceGroupId, effectiveInstanceName, ct))
                        if (!string.IsNullOrWhiteSpace(participantId)) allParticipants.Add(participantId.Trim());
                participantIds = allParticipants.ToList();
            }
            if (participantIds.Count == 0) return Results.BadRequest(new { error = "Nenhum participante elegÃƒÂ­vel encontrado para o disparo." });

            var now = DateTimeOffset.UtcNow;
            var settings = await settingsStore.GetAsync(ct);
            var automation = settings.WhatsAppAdminAutomation ??= new WhatsAppAdminAutomationSettings();
            var schedule = new WhatsAppParticipantBlastSchedule
            {
                Id = Guid.NewGuid().ToString("N"), Name = string.IsNullOrWhiteSpace(request.Name) ? $"Disparo {now:yyyyMMdd-HHmmss}" : request.Name.Trim(), Enabled = true, Status = "queued", InstanceName = effectiveInstanceName,
                SourceGroupIds = sourceGroupIds, UseAllParticipantsFromSources = request.UseAllParticipantsFromSources, PendingParticipantIds = participantIds, SentParticipantIds = new List<string>(), TotalParticipants = participantIds.Count, ProcessedParticipants = 0, SuccessParticipants = 0, FailedParticipants = 0, RepliedParticipants = 0, LinksSent = 0,
                Message = request.Message?.Trim(), LinkUrl = request.LinkUrl.Trim(), UseAiDialogue = request.UseAiDialogue, IntervalMs = request.IntervalMs, MinUserIntervalMs = request.MinUserIntervalMs, MaxUserIntervalMs = request.MaxUserIntervalMs, BatchSize = request.BatchSize, BatchPauseSeconds = request.BatchPauseSeconds, PreLinkMessages = request.PreLinkMessages, WaitMode = string.IsNullOrWhiteSpace(request.WaitMode) ? "response-or-timeout" : request.WaitMode.Trim(), WaitTimeoutSeconds = request.WaitTimeoutSeconds, SendLinkOnTimeout = request.SendLinkOnTimeout, SecurityPitch = pitch.Trim(), CreatedAt = now, QueuedAt = now, LastResultMessage = $"Disparo criado com {participantIds.Count} participante(s)."
            };
            automation.ParticipantBlastSchedules.Insert(0, schedule);
            await settingsStore.SaveAsync(settings, ct);
            var job = await queueService.EnqueueAsync("participant-blast-now", $"Disparo agendado {schedule.Id}", token => automationService.RunBlastScheduleNowAsync(schedule.Id, token), ct);
            return Results.Json(new { success = true, queued = true, queueId = job.Id, operationId = schedule.Id, scheduleId = schedule.Id, count = participantIds.Count, message = schedule.LastResultMessage }, statusCode: StatusCodes.Status202Accepted);
        }).RequireAuthorization("AdminOnly");
    }
}

internal sealed record CreateParticipantBlastScheduleRequest(string? SourceGroupId, List<string>? SourceGroupIds, List<string>? ParticipantIds, bool UseAllParticipantsFromSources, string? Message, string LinkUrl, int IntervalMs = 1500, int MinUserIntervalMs = 1200, int MaxUserIntervalMs = 2600, int BatchSize = 25, int BatchPauseSeconds = 90, bool UseAiDialogue = true, int PreLinkMessages = 3, string WaitMode = "response-or-timeout", int WaitTimeoutSeconds = 120, bool SendLinkOnTimeout = true, string? SecurityPitch = null, string? LinkConfirmation = null, string? InstanceName = null, string? Name = null);
