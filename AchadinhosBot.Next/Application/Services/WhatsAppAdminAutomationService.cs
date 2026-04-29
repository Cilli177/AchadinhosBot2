using System.Text.RegularExpressions;
using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Domain.Logs;
using AchadinhosBot.Next.Domain.Models;
using AchadinhosBot.Next.Domain.Settings;
using Microsoft.Extensions.Logging;

namespace AchadinhosBot.Next.Application.Services;

public sealed class WhatsAppAdminAutomationService
{
    private const int BlastMinUserIntervalMs = 90_000;
    private const int BlastMaxUserIntervalMs = 300_000;
    private const int BlastMaxBatchSize = 20;
    private const int BlastMinBatchPauseSeconds = 60;
    private const int BlastMaxBatchPauseSeconds = 900;

    private readonly ISettingsStore _settingsStore;
    private readonly IWhatsAppTransport _transport;
    private readonly TrackingLinkShortenerService _trackingLinkShortener;
    private readonly IWhatsAppParticipantBlastProgressStore _blastProgressStore;
    private readonly IWhatsAppGroupMembershipStore _membershipStore;
    private readonly ILogger<WhatsAppAdminAutomationService> _logger;
    private readonly SemaphoreSlim _mutex = new(1, 1);

    public WhatsAppAdminAutomationService(
        ISettingsStore settingsStore,
        IWhatsAppTransport transport,
        TrackingLinkShortenerService trackingLinkShortener,
        IWhatsAppParticipantBlastProgressStore blastProgressStore,
        IWhatsAppGroupMembershipStore membershipStore,
        ILogger<WhatsAppAdminAutomationService> logger)
    {
        _settingsStore = settingsStore;
        _transport = transport;
        _trackingLinkShortener = trackingLinkShortener;
        _blastProgressStore = blastProgressStore;
        _membershipStore = membershipStore;
        _logger = logger;
    }

    public async Task<int> ProcessDueSchedulesAsync(CancellationToken ct)
    {
        if (!await _mutex.WaitAsync(0, ct))
        {
            return 0;
        }

        try
        {
            var settings = await _settingsStore.GetAsync(ct);
            var automation = settings.WhatsAppAdminAutomation ??= new WhatsAppAdminAutomationSettings();
            var now = DateTimeOffset.UtcNow;
            var changed = WhatsAppParticipantAddSafety.Normalize(automation, now);
            var processedCount = 0;

            if (automation.ParticipantCopyAutomationEnabled)
            {
                foreach (var schedule in automation.ParticipantCopySchedules)
                {
                    if (!schedule.Enabled || schedule.NextRunAt > now)
                    {
                        continue;
                    }

                    changed |= await ProcessParticipantCopyScheduleAsync(schedule, automation, now, ct);
                    processedCount++;
                }
            }

            foreach (var schedule in automation.ScheduledGroupMessages)
            {
                if (!schedule.Enabled || schedule.NextRunAt > now)
                {
                    continue;
                }

                changed |= await ProcessScheduledMessageAsync(schedule, now, ct);
                processedCount++;
            }

            foreach (var schedule in automation.ParticipantBlastSchedules)
            {
                if (!schedule.Enabled || string.Equals(schedule.Status, "completed", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                if (schedule.QueuedAt is not null && schedule.QueuedAt > now)
                {
                    continue;
                }

                changed |= await ProcessParticipantBlastScheduleAsync(schedule, now, ct);
                processedCount++;
            }

            if (changed)
            {
                await _settingsStore.SaveAsync(settings, ct);
            }

            return processedCount;
        }
        finally
        {
            _mutex.Release();
        }
    }

    public async Task<(bool Success, string Message)> RunCopyScheduleNowAsync(string id, CancellationToken ct)
    {
        if (!await _mutex.WaitAsync(0, ct))
        {
            return (false, "Processamento em andamento. Tente novamente em instantes.");
        }

        try
        {
            var settings = await _settingsStore.GetAsync(ct);
            var automation = settings.WhatsAppAdminAutomation ??= new WhatsAppAdminAutomationSettings();
            var now = DateTimeOffset.UtcNow;
            WhatsAppParticipantAddSafety.Normalize(automation, now);

            if (!automation.ParticipantCopyAutomationEnabled)
            {
                return (false, "Cópia de participantes está pausada globalmente no momento.");
            }

            var schedule = automation.ParticipantCopySchedules.FirstOrDefault(x => string.Equals(x.Id, id, StringComparison.OrdinalIgnoreCase));
            if (schedule is null)
            {
                return (false, "Agendamento não encontrado.");
            }

            var ok = await ProcessParticipantCopyScheduleAsync(schedule, automation, now, ct);
            await _settingsStore.SaveAsync(settings, ct);
            return (ok, schedule.LastResultMessage ?? "Agendamento executado.");
        }
        finally
        {
            _mutex.Release();
        }
    }

    public async Task<(bool Success, string Message)> RunMessageScheduleNowAsync(string id, CancellationToken ct)
    {
        if (!await _mutex.WaitAsync(0, ct))
        {
            return (false, "Processamento em andamento. Tente novamente em instantes.");
        }

        try
        {
            var settings = await _settingsStore.GetAsync(ct);
            var automation = settings.WhatsAppAdminAutomation ??= new WhatsAppAdminAutomationSettings();
            var now = DateTimeOffset.UtcNow;
            WhatsAppParticipantAddSafety.Normalize(automation, now);

            var schedule = automation.ScheduledGroupMessages.FirstOrDefault(x => string.Equals(x.Id, id, StringComparison.OrdinalIgnoreCase));
            if (schedule is null)
            {
                return (false, "Agendamento não encontrado.");
            }

            var ok = await ProcessScheduledMessageAsync(schedule, now, ct);
            await _settingsStore.SaveAsync(settings, ct);
            return (ok, schedule.LastResultMessage ?? "Mensagem executada.");
        }
        finally
        {
            _mutex.Release();
        }
    }

    public async Task<(bool Success, string Message)> RunBlastScheduleNowAsync(string id, CancellationToken ct)
    {
        if (!await _mutex.WaitAsync(0, ct))
        {
            return (false, "Processamento em andamento. Tente novamente em instantes.");
        }

        try
        {
            var settings = await _settingsStore.GetAsync(ct);
            var automation = settings.WhatsAppAdminAutomation ??= new WhatsAppAdminAutomationSettings();
            var now = DateTimeOffset.UtcNow;
            WhatsAppParticipantAddSafety.Normalize(automation, now);

            var schedule = automation.ParticipantBlastSchedules.FirstOrDefault(x => string.Equals(x.Id, id, StringComparison.OrdinalIgnoreCase));
            if (schedule is null)
            {
                return (false, "Disparo não encontrado.");
            }

            schedule.QueuedAt = now;
            var ok = await ProcessParticipantBlastScheduleAsync(schedule, now, ct);
            await _settingsStore.SaveAsync(settings, ct);
            return (ok, schedule.LastResultMessage ?? "Disparo executado.");
        }
        finally
        {
            _mutex.Release();
        }
    }

    public Task<IReadOnlyList<WhatsAppParticipantBlastProgressEntry>> GetBlastLogsAsync(string? operationId, int limit, CancellationToken ct)
        => _blastProgressStore.ListAsync(operationId, limit, ct);

    public async Task<WhatsAppParticipantBlastConversionSnapshot?> GetBlastConversionAsync(string scheduleId, string? groupId, CancellationToken ct)
    {
        var settings = await _settingsStore.GetAsync(ct);
        var automation = settings.WhatsAppAdminAutomation ??= new WhatsAppAdminAutomationSettings();
        var schedule = automation.ParticipantBlastSchedules.FirstOrDefault(x => string.Equals(x.Id, scheduleId, StringComparison.OrdinalIgnoreCase));
        if (schedule is null)
        {
            return null;
        }

        var sentIds = schedule.SentParticipantIds
            .Where(x => !string.IsNullOrWhiteSpace(x))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        var allEvents = await _membershipStore.ListAsync(ct);
        var joinEvents = allEvents
            .Where(x => sentIds.Contains(x.ParticipantId))
            .Where(x => x.Timestamp >= schedule.CreatedAt)
            .Where(x => string.Equals(x.Action, "join", StringComparison.OrdinalIgnoreCase)
                     || string.Equals(x.Action, "add", StringComparison.OrdinalIgnoreCase))
            .Where(x => string.IsNullOrWhiteSpace(groupId) || string.Equals(x.GroupId, groupId.Trim(), StringComparison.OrdinalIgnoreCase))
            .OrderByDescending(x => x.Timestamp)
            .ToList();

        var converters = joinEvents
            .GroupBy(x => x.ParticipantId, StringComparer.OrdinalIgnoreCase)
            .Select(g => g.OrderByDescending(x => x.Timestamp).First())
            .Select(x => new WhatsAppParticipantBlastConverter
            {
                ParticipantId = x.ParticipantId,
                GroupId = x.GroupId,
                GroupName = x.GroupName,
                Action = x.Action,
                JoinedAt = x.Timestamp
            })
            .OrderByDescending(x => x.JoinedAt)
            .ToArray();

        var totalSent = sentIds.Count;
        var converted = converters.Length;
        var rate = totalSent == 0 ? 0m : Math.Round((decimal)converted * 100m / totalSent, 2, MidpointRounding.AwayFromZero);

        return new WhatsAppParticipantBlastConversionSnapshot
        {
            ScheduleId = schedule.Id,
            ScheduleName = schedule.Name,
            TotalSent = totalSent,
            Converted = converted,
            ConversionRate = rate,
            TotalJoinEvents = joinEvents.Count,
            Converters = converters
        };
    }

    private async Task<bool> ProcessParticipantCopyScheduleAsync(
        WhatsAppParticipantCopySchedule schedule,
        WhatsAppAdminAutomationSettings automation,
        DateTimeOffset now,
        CancellationToken ct)
    {
        schedule.Name = AutomationSettingsSanitizer.Normalize(schedule.Name);
        schedule.LastResultMessage = AutomationSettingsSanitizer.NormalizeNullable(schedule.LastResultMessage);

        var interval = NormalizeInterval(schedule.IntervalMinutes);
        var batchSize = NormalizeBatchSize(schedule.BatchSize);
        var minimumInterval = automation.ParticipantAddSafetyEnabled
            ? WhatsAppParticipantAddSafety.GetMinimumIntervalMinutes(automation, schedule.InstanceName)
            : interval;
        interval = Math.Max(interval, minimumInterval);

        schedule.IntervalMinutes = interval;
        schedule.BatchSize = batchSize;
        schedule.LastRunAt = now;
        var effectiveInstanceName = WhatsAppInstanceRoutingPolicy.ResolveParticipantOpsInstance(schedule.InstanceName);
        schedule.InstanceName = effectiveInstanceName;

        var targetParticipants = await _transport.GetGroupParticipantsAsync(effectiveInstanceName, schedule.TargetGroupId, ct);
        var targetSet = new HashSet<string>(targetParticipants, StringComparer.OrdinalIgnoreCase);
        var pendingBeforeFilter = schedule.PendingParticipantIds.Count;
        schedule.PendingParticipantIds = schedule.PendingParticipantIds
            .Where(id => !string.IsNullOrWhiteSpace(id) && !targetSet.Contains(id))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
        var skippedNow = Math.Max(0, pendingBeforeFilter - schedule.PendingParticipantIds.Count);
        if (skippedNow > 0)
        {
            schedule.SkippedParticipants += skippedNow;
            schedule.ProcessedParticipants = Math.Min(
                schedule.TotalParticipants,
                schedule.ProcessedParticipants + skippedNow);
        }

        if (schedule.PendingParticipantIds.Count == 0)
        {
            schedule.Enabled = false;
            schedule.CompletedAt ??= now;
            schedule.NextRunAt = now;
            schedule.LastResultMessage = $"Concluído: todos processados. Repetidos ignorados: {schedule.SkippedParticipants}.";
            return true;
        }

        if (WhatsAppParticipantAddSafety.TryGetCooldownBlock(automation, effectiveInstanceName, now, out var nextAllowedAt, out var cooldownMessage))
        {
            schedule.NextRunAt = nextAllowedAt;
            schedule.LastResultMessage = AutomationSettingsSanitizer.NormalizeNullable(cooldownMessage);
            return true;
        }

        var remainingQuota = WhatsAppParticipantAddSafety.GetRemainingQuota(automation, effectiveInstanceName);
        if (remainingQuota <= 0)
        {
            var nextQuotaReset = WhatsAppParticipantAddSafety.GetNextQuotaResetAt(now);
            schedule.NextRunAt = nextQuotaReset;
            schedule.LastResultMessage = "Limite diário de adições atingido. Agendamento reagendado para a próxima janela.";
            return true;
        }

        var effectiveBatchSize = Math.Min(batchSize, remainingQuota);
        var batchWasLimitedByQuota = effectiveBatchSize < batchSize;
        var batch = schedule.PendingParticipantIds.Take(effectiveBatchSize).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        if (batch.Count == 0)
        {
            schedule.Enabled = false;
            schedule.CompletedAt ??= now;
            schedule.NextRunAt = now;
            schedule.LastResultMessage = "Concluído: lista pendente vazia após deduplicação.";
            return true;
        }

        try
        {
            var result = await _transport.AddParticipantsAsync(effectiveInstanceName, schedule.TargetGroupId, batch, ct);
            if (result.Success)
            {
                schedule.PendingParticipantIds = schedule.PendingParticipantIds
                    .Where(id => !batch.Contains(id, StringComparer.OrdinalIgnoreCase))
                    .ToList();
                WhatsAppParticipantAddSafety.RegisterSuccessfulAdd(automation, effectiveInstanceName, batch.Count, now);
                schedule.ProcessedParticipants = Math.Min(
                    schedule.TotalParticipants,
                    schedule.ProcessedParticipants + batch.Count);
                schedule.NextRunAt = now.AddMinutes(interval);
                schedule.LastResultMessage = batchWasLimitedByQuota
                    ? $"Lote reduzido por limite diário: configurado {batchSize}, enviado {batch.Count}. Ignorados repetidos: {schedule.SkippedParticipants}."
                    : (AutomationSettingsSanitizer.NormalizeNullable(result.Message) ?? $"Lote enviado com {batch.Count} participantes. Ignorados repetidos: {schedule.SkippedParticipants}.");

                if (schedule.PendingParticipantIds.Count == 0)
                {
                    schedule.Enabled = false;
                    schedule.CompletedAt = now;
                    schedule.LastResultMessage = $"Concluído: {schedule.ProcessedParticipants} participantes processados. Repetidos ignorados: {schedule.SkippedParticipants}.";
                }
            }
            else
            {
                schedule.NextRunAt = now.AddMinutes(interval);
                schedule.LastResultMessage = AutomationSettingsSanitizer.NormalizeNullable(result.Message) ?? "Falha ao adicionar participantes.";
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            schedule.NextRunAt = now.AddMinutes(interval);
            schedule.LastResultMessage = AutomationSettingsSanitizer.NormalizeNullable(ex.Message);
            _logger.LogWarning(ex,
                "Falha ao processar agendamento de cópia gradual {ScheduleId} para grupo {TargetGroupId}",
                schedule.Id,
                schedule.TargetGroupId);
        }

        return true;
    }

    private async Task<bool> ProcessParticipantBlastScheduleAsync(
        WhatsAppParticipantBlastSchedule schedule,
        DateTimeOffset now,
        CancellationToken ct)
    {
        schedule.Name = AutomationSettingsSanitizer.Normalize(schedule.Name);
        schedule.Status = string.IsNullOrWhiteSpace(schedule.Status) ? "queued" : schedule.Status.Trim().ToLowerInvariant();
        schedule.Message = AutomationSettingsSanitizer.NormalizeNullable(schedule.Message);
        schedule.SecurityPitch = AutomationSettingsSanitizer.NormalizeNullable(schedule.SecurityPitch);
        schedule.LinkUrl = AutomationSettingsSanitizer.NormalizeNullable(schedule.LinkUrl);
        schedule.LastResultMessage = AutomationSettingsSanitizer.NormalizeNullable(schedule.LastResultMessage);
        schedule.InstanceName = WhatsAppInstanceRoutingPolicy.ResolveParticipantOpsInstance(schedule.InstanceName);
        schedule.IntervalMs = NormalizeBlastIntervalMs(schedule.IntervalMs);
        schedule.MinUserIntervalMs = NormalizeBlastIntervalMs(schedule.MinUserIntervalMs);
        schedule.MaxUserIntervalMs = Math.Max(schedule.MinUserIntervalMs, NormalizeBlastIntervalMs(schedule.MaxUserIntervalMs));
        schedule.BatchSize = NormalizeBlastBatchSize(schedule.BatchSize);
        schedule.BatchPauseSeconds = NormalizeBlastBatchPauseSeconds(schedule.BatchPauseSeconds);
        schedule.PreLinkMessages = Math.Clamp(schedule.PreLinkMessages, 1, 4);
        schedule.WaitTimeoutSeconds = Math.Clamp(schedule.WaitTimeoutSeconds, 30, 600);

        if (string.IsNullOrWhiteSpace(schedule.LinkUrl))
        {
            schedule.Enabled = false;
            schedule.Status = "failed";
            schedule.CompletedAt = now;
            schedule.LastResultMessage = "Link oficial do grupo não informado.";
            await AppendBlastProgressAsync(schedule, "validation-failed", "error", null, schedule.LastResultMessage, ct);
            return true;
        }

        schedule.LastRunAt = now;
        schedule.LastProgressAt = now;
        schedule.Status = "running";
        await AppendBlastProgressAsync(schedule, "schedule-started", "info", null, $"Disparo iniciado com {schedule.PendingParticipantIds.Count} participante(s) pendente(s).", ct);

        if (schedule.PendingParticipantIds.Count == 0)
        {
            schedule.Enabled = false;
            schedule.Status = "completed";
            schedule.CompletedAt = now;
            schedule.LastResultMessage = "Disparo concluído sem participantes pendentes.";
            await AppendBlastProgressAsync(schedule, "schedule-completed", "info", null, schedule.LastResultMessage, ct);
            return true;
        }

        var consecutiveFailures = 0;
        while (schedule.Enabled && schedule.PendingParticipantIds.Count > 0 && !ct.IsCancellationRequested)
        {
            var batch = schedule.PendingParticipantIds
                .Where(x => !string.IsNullOrWhiteSpace(x))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Take(schedule.BatchSize)
                .ToList();
            if (batch.Count == 0)
            {
                break;
            }

            foreach (var participantId in batch)
            {
                ct.ThrowIfCancellationRequested();
                var outboundText = BuildBlastOutboundText(schedule);

                try
                {
                    var result = await _transport.SendTextAsync(schedule.InstanceName, participantId, outboundText, ct);
                    schedule.ProcessedParticipants = Math.Min(schedule.TotalParticipants, schedule.ProcessedParticipants + 1);
                    schedule.LastProgressAt = DateTimeOffset.UtcNow;

                    if (result.Success)
                    {
                        consecutiveFailures = 0;
                        schedule.SuccessParticipants++;
                        schedule.LinksSent++;
                        schedule.SentParticipantIds.Add(participantId);
                        schedule.PendingParticipantIds.RemoveAll(x => string.Equals(x, participantId, StringComparison.OrdinalIgnoreCase));
                        schedule.LastResultMessage = result.Message ?? "Mensagem enviada.";
                        await AppendBlastProgressAsync(schedule, "participant-message-sent", "info", participantId, schedule.LastResultMessage, ct);
                    }
                    else
                    {
                        consecutiveFailures++;
                        schedule.FailedParticipants++;
                        schedule.PendingParticipantIds.RemoveAll(x => string.Equals(x, participantId, StringComparison.OrdinalIgnoreCase));
                        schedule.LastResultMessage = result.Message ?? "Falha ao enviar mensagem.";
                        await AppendBlastProgressAsync(schedule, "participant-message-failed", "warn", participantId, schedule.LastResultMessage, ct);
                    }
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    consecutiveFailures++;
                    schedule.FailedParticipants++;
                    schedule.ProcessedParticipants = Math.Min(schedule.TotalParticipants, schedule.ProcessedParticipants + 1);
                    schedule.PendingParticipantIds.RemoveAll(x => string.Equals(x, participantId, StringComparison.OrdinalIgnoreCase));
                    schedule.LastResultMessage = AutomationSettingsSanitizer.NormalizeNullable(ex.Message) ?? "Falha inesperada ao enviar mensagem.";
                    await AppendBlastProgressAsync(schedule, "participant-message-failed", "error", participantId, schedule.LastResultMessage, ct);
                    _logger.LogWarning(ex, "Falha ao disparar convite WhatsApp para participante {ParticipantId} no schedule {ScheduleId}", participantId, schedule.Id);
                }

                if (consecutiveFailures >= 5)
                {
                    schedule.Enabled = false;
                    schedule.Status = "paused";
                    schedule.LastResultMessage = "Disparo pausado automaticamente após 5 falhas consecutivas.";
                    await AppendBlastProgressAsync(schedule, "schedule-paused", "error", null, schedule.LastResultMessage, ct);
                    break;
                }

                var waitMs = Random.Shared.Next(schedule.MinUserIntervalMs, schedule.MaxUserIntervalMs + 1);
                await Task.Delay(waitMs, ct);
            }

            if (!schedule.Enabled || schedule.PendingParticipantIds.Count == 0)
            {
                break;
            }

            schedule.LastProgressAt = DateTimeOffset.UtcNow;
            schedule.LastResultMessage = $"Lote concluído. Restam {schedule.PendingParticipantIds.Count} participante(s). Pausa de {schedule.BatchPauseSeconds}s.";
            await AppendBlastProgressAsync(schedule, "batch-paused", "info", null, schedule.LastResultMessage, ct);
            await Task.Delay(TimeSpan.FromSeconds(schedule.BatchPauseSeconds), ct);
        }

        if (schedule.PendingParticipantIds.Count == 0)
        {
            schedule.Enabled = false;
            schedule.Status = "completed";
            schedule.CompletedAt = DateTimeOffset.UtcNow;
            schedule.LastResultMessage = $"Disparo concluído. {schedule.SuccessParticipants} envio(s) com sucesso e {schedule.FailedParticipants} falha(s).";
            await AppendBlastProgressAsync(schedule, "schedule-completed", "info", null, schedule.LastResultMessage, ct);
        }

        return true;
    }

    private async Task<bool> ProcessScheduledMessageAsync(
        WhatsAppScheduledGroupMessage schedule,
        DateTimeOffset now,
        CancellationToken ct)
    {
        schedule.Name = AutomationSettingsSanitizer.Normalize(schedule.Name);
        schedule.Text = AutomationSettingsSanitizer.Normalize(schedule.Text);
        schedule.LastResultMessage = AutomationSettingsSanitizer.NormalizeNullable(schedule.LastResultMessage);

        var interval = NormalizeInterval(schedule.IntervalMinutes);
        schedule.IntervalMinutes = interval;
        var effectiveInstanceName = string.IsNullOrWhiteSpace(schedule.InstanceName) ? null : schedule.InstanceName.Trim();

        try
        {
            var trackedText = NormalizeScheduledMessageLinks(schedule.Text);
            var result = string.IsNullOrWhiteSpace(schedule.ImageUrl)
                ? await _transport.SendTextAsync(effectiveInstanceName, schedule.TargetGroupId, trackedText, ct)
                : await _transport.SendImageUrlAsync(effectiveInstanceName, schedule.TargetGroupId, schedule.ImageUrl.Trim(), trackedText, null, "message.jpg", ct);
            schedule.LastSentAt = now;
            schedule.NextRunAt = now.AddMinutes(interval);
            schedule.LastResultMessage = AutomationSettingsSanitizer.NormalizeNullable(result.Message)
                ?? (result.Success ? "Mensagem enviada com sucesso." : "Falha ao enviar mensagem.");
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            schedule.NextRunAt = now.AddMinutes(interval);
            schedule.LastResultMessage = AutomationSettingsSanitizer.NormalizeNullable(ex.Message);
            _logger.LogWarning(ex,
                "Falha ao processar agendamento de mensagem {ScheduleId} para grupo {TargetGroupId}",
                schedule.Id,
                schedule.TargetGroupId);
        }

        return true;
    }

    private async Task AppendBlastProgressAsync(
        WhatsAppParticipantBlastSchedule schedule,
        string stage,
        string level,
        string? participantId,
        string? message,
        CancellationToken ct)
    {
        await _blastProgressStore.AppendAsync(new WhatsAppParticipantBlastProgressEntry
        {
            OperationId = schedule.Id,
            ScheduleId = schedule.Id,
            ScheduleName = schedule.Name,
            Stage = stage,
            Level = level,
            ParticipantId = participantId,
            Processed = schedule.ProcessedParticipants,
            Total = schedule.TotalParticipants,
            Message = message,
            Timestamp = DateTimeOffset.UtcNow,
            InstanceName = schedule.InstanceName
        }, ct);
    }

    private static int NormalizeInterval(int value) => value <= 0 ? 1 : value;

    private static int NormalizeBatchSize(int value) => value <= 0 ? 1 : value;

    private static int NormalizeBlastIntervalMs(int value)
        => Math.Clamp(value <= 0 ? BlastMinUserIntervalMs : value, BlastMinUserIntervalMs, BlastMaxUserIntervalMs);

    private static int NormalizeBlastBatchSize(int value)
        => Math.Clamp(value <= 0 ? 12 : value, 1, BlastMaxBatchSize);

    private static int NormalizeBlastBatchPauseSeconds(int value)
        => Math.Clamp(value <= 0 ? 120 : value, BlastMinBatchPauseSeconds, BlastMaxBatchPauseSeconds);

    private static string BuildBlastOutboundText(WhatsAppParticipantBlastSchedule schedule)
    {
        var baseText = !string.IsNullOrWhiteSpace(schedule.SecurityPitch)
            ? schedule.SecurityPitch!.Trim()
            : (schedule.Message ?? string.Empty).Trim();
        var normalizedLink = NormalizeScheduledMessageLinks(schedule.LinkUrl);
        var lines = new List<string>();
        if (!string.IsNullOrWhiteSpace(baseText))
        {
            lines.Add(baseText);
        }

        if (!string.IsNullOrWhiteSpace(normalizedLink))
        {
            lines.Add("Link oficial do grupo:");
            lines.Add(normalizedLink);
        }

        return string.Join("\n\n", lines.Where(x => !string.IsNullOrWhiteSpace(x)));
    }

    private static string NormalizeScheduledMessageLinks(string? text)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            return string.Empty;
        }

        var normalized = text.Trim();
        normalized = Regex.Replace(
            normalized,
            @"(?<!https?://)\bbio\.reidasofertas\.ia\.br\b",
            "https://bio.reidasofertas.ia.br",
            RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

        return normalized;
    }
}

public sealed class WhatsAppParticipantBlastConversionSnapshot
{
    public string ScheduleId { get; set; } = string.Empty;
    public string ScheduleName { get; set; } = string.Empty;
    public int TotalSent { get; set; }
    public int Converted { get; set; }
    public decimal ConversionRate { get; set; }
    public int TotalJoinEvents { get; set; }
    public IReadOnlyList<WhatsAppParticipantBlastConverter> Converters { get; set; } = Array.Empty<WhatsAppParticipantBlastConverter>();
}

public sealed class WhatsAppParticipantBlastConverter
{
    public string ParticipantId { get; set; } = string.Empty;
    public string? GroupId { get; set; }
    public string? GroupName { get; set; }
    public string Action { get; set; } = string.Empty;
    public DateTimeOffset JoinedAt { get; set; }
}
