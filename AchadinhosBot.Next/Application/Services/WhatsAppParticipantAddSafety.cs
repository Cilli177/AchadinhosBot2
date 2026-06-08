using AchadinhosBot.Next.Domain.Settings;

namespace AchadinhosBot.Next.Application.Services;

internal static class WhatsAppParticipantAddSafety
{
    public const int DefaultMaxParticipantsPerDay = 120;
    public const int DefaultMinMinutesBetweenAdds = 10;

    internal sealed record Snapshot(
        string? InstanceName,
        int MaxParticipantsAddedPerDay,
        int MinMinutesBetweenParticipantAdds,
        int ParticipantsAddedToday,
        DateTimeOffset? ParticipantAddQuotaDateUtc,
        DateTimeOffset? LastParticipantAddAt,
        bool UsesDefaultSettings);

    public static bool Normalize(WhatsAppAdminAutomationSettings automation, DateTimeOffset now)
    {
        var changed = false;

        changed |= NormalizeGlobalSettings(automation, now);

        var deduped = new List<WhatsAppInstanceParticipantAddSafetySettings>();
        foreach (var item in automation.InstanceParticipantAddSafety)
        {
            var normalizedName = NormalizeInstanceName(item.InstanceName);
            if (string.IsNullOrWhiteSpace(normalizedName))
            {
                changed = true;
                continue;
            }

            var existing = deduped.FirstOrDefault(x => string.Equals(x.InstanceName, normalizedName, StringComparison.OrdinalIgnoreCase));
            if (existing is null)
            {
                item.InstanceName = normalizedName;
                changed |= NormalizeInstanceSettings(item, now);
                deduped.Add(item);
                continue;
            }

            MergeInstanceState(existing, item);
            changed = true;
            changed |= NormalizeInstanceSettings(existing, now);
        }

        if (deduped.Count != automation.InstanceParticipantAddSafety.Count)
        {
            automation.InstanceParticipantAddSafety = deduped;
            changed = true;
        }

        return changed;
    }

    public static Snapshot GetSnapshot(WhatsAppAdminAutomationSettings automation, string? instanceName)
    {
        var normalizedInstanceName = NormalizeInstanceName(instanceName);
        var instanceSettings = FindInstanceSettings(automation, normalizedInstanceName);
        if (instanceSettings is not null)
        {
            return new Snapshot(
                instanceSettings.InstanceName,
                Math.Max(1, instanceSettings.MaxParticipantsAddedPerDay),
                Math.Max(1, instanceSettings.MinMinutesBetweenParticipantAdds),
                Math.Max(0, instanceSettings.ParticipantsAddedToday),
                instanceSettings.ParticipantAddQuotaDateUtc,
                instanceSettings.LastParticipantAddAt,
                false);
        }

        return new Snapshot(
            normalizedInstanceName,
            Math.Max(1, automation.MaxParticipantsAddedPerDay),
            Math.Max(1, automation.MinMinutesBetweenParticipantAdds),
            Math.Max(0, automation.ParticipantsAddedToday),
            automation.ParticipantAddQuotaDateUtc,
            automation.LastParticipantAddAt,
            true);
    }

    public static int GetRemainingQuota(WhatsAppAdminAutomationSettings automation, string? instanceName)
    {
        if (!automation.ParticipantAddSafetyEnabled)
        {
            return int.MaxValue;
        }

        var snapshot = GetSnapshot(automation, instanceName);
        return Math.Max(0, snapshot.MaxParticipantsAddedPerDay - snapshot.ParticipantsAddedToday);
    }

    public static int GetMinimumIntervalMinutes(WhatsAppAdminAutomationSettings automation, string? instanceName)
    {
        var snapshot = GetSnapshot(automation, instanceName);
        return Math.Max(1, snapshot.MinMinutesBetweenParticipantAdds);
    }

    public static bool TryGetCooldownBlock(
        WhatsAppAdminAutomationSettings automation,
        string? instanceName,
        DateTimeOffset now,
        out DateTimeOffset nextAllowedAt,
        out string message)
    {
        nextAllowedAt = now;
        message = string.Empty;

        if (!automation.ParticipantAddSafetyEnabled)
        {
            return false;
        }

        var snapshot = GetSnapshot(automation, instanceName);
        if (snapshot.LastParticipantAddAt is null)
        {
            return false;
        }

        nextAllowedAt = snapshot.LastParticipantAddAt.Value.AddMinutes(snapshot.MinMinutesBetweenParticipantAdds);
        if (nextAllowedAt <= now)
        {
            return false;
        }

        var remaining = nextAllowedAt - now;
        var remainingMinutes = Math.Max(1, (int)Math.Ceiling(remaining.TotalMinutes));
        var instanceLabel = string.IsNullOrWhiteSpace(snapshot.InstanceName)
            ? string.Empty
            : $" na instância {snapshot.InstanceName}";
        message = $"Aguarde {remainingMinutes} minuto(s) antes da próxima adição de participantes{instanceLabel}.";
        return true;
    }

    public static DateTimeOffset GetNextQuotaResetAt(DateTimeOffset now)
    {
        var nextDate = now.UtcDateTime.Date.AddDays(1);
        return new DateTimeOffset(nextDate, TimeSpan.Zero);
    }

    public static void RegisterSuccessfulAdd(
        WhatsAppAdminAutomationSettings automation,
        string? instanceName,
        int addedCount,
        DateTimeOffset now)
    {
        if (!automation.ParticipantAddSafetyEnabled || addedCount <= 0)
        {
            return;
        }

        Normalize(automation, now);

        var normalizedInstanceName = NormalizeInstanceName(instanceName);
        if (string.IsNullOrWhiteSpace(normalizedInstanceName))
        {
            automation.ParticipantsAddedToday += addedCount;
            automation.LastParticipantAddAt = now;
            return;
        }

        var target = FindInstanceSettings(automation, normalizedInstanceName, createIfMissing: true);
        target!.ParticipantsAddedToday += addedCount;
        target.LastParticipantAddAt = now;
    }

    public static void UpdateConfiguredLimits(
        WhatsAppAdminAutomationSettings automation,
        string? instanceName,
        int maxParticipantsAddedPerDay,
        int minMinutesBetweenParticipantAdds,
        DateTimeOffset now)
    {
        Normalize(automation, now);

        var safeDailyLimit = Math.Max(1, maxParticipantsAddedPerDay);
        var safeCooldown = Math.Max(1, minMinutesBetweenParticipantAdds);
        var normalizedInstanceName = NormalizeInstanceName(instanceName);

        if (string.IsNullOrWhiteSpace(normalizedInstanceName))
        {
            automation.MaxParticipantsAddedPerDay = safeDailyLimit;
            automation.MinMinutesBetweenParticipantAdds = safeCooldown;
            return;
        }

        var target = FindInstanceSettings(automation, normalizedInstanceName, createIfMissing: true);
        target!.MaxParticipantsAddedPerDay = safeDailyLimit;
        target.MinMinutesBetweenParticipantAdds = safeCooldown;
    }

    private static bool NormalizeGlobalSettings(WhatsAppAdminAutomationSettings automation, DateTimeOffset now)
    {
        var changed = false;

        if (automation.MaxParticipantsAddedPerDay <= 0)
        {
            automation.MaxParticipantsAddedPerDay = DefaultMaxParticipantsPerDay;
            changed = true;
        }

        if (automation.MinMinutesBetweenParticipantAdds <= 0)
        {
            automation.MinMinutesBetweenParticipantAdds = DefaultMinMinutesBetweenAdds;
            changed = true;
        }

        var quotaDate = automation.ParticipantAddQuotaDateUtc?.UtcDateTime.Date;
        var currentDate = now.UtcDateTime.Date;

        if (quotaDate != currentDate)
        {
            automation.ParticipantsAddedToday = 0;
            automation.ParticipantAddQuotaDateUtc = new DateTimeOffset(currentDate, TimeSpan.Zero);
            changed = true;
        }

        return changed;
    }

    private static bool NormalizeInstanceSettings(WhatsAppInstanceParticipantAddSafetySettings settings, DateTimeOffset now)
    {
        var changed = false;

        settings.InstanceName = NormalizeInstanceName(settings.InstanceName) ?? string.Empty;

        if (settings.MaxParticipantsAddedPerDay <= 0)
        {
            settings.MaxParticipantsAddedPerDay = DefaultMaxParticipantsPerDay;
            changed = true;
        }

        if (settings.MinMinutesBetweenParticipantAdds <= 0)
        {
            settings.MinMinutesBetweenParticipantAdds = DefaultMinMinutesBetweenAdds;
            changed = true;
        }

        var quotaDate = settings.ParticipantAddQuotaDateUtc?.UtcDateTime.Date;
        var currentDate = now.UtcDateTime.Date;
        if (quotaDate != currentDate)
        {
            settings.ParticipantsAddedToday = 0;
            settings.ParticipantAddQuotaDateUtc = new DateTimeOffset(currentDate, TimeSpan.Zero);
            changed = true;
        }

        return changed;
    }

    private static void MergeInstanceState(
        WhatsAppInstanceParticipantAddSafetySettings target,
        WhatsAppInstanceParticipantAddSafetySettings source)
    {
        target.MaxParticipantsAddedPerDay = source.MaxParticipantsAddedPerDay > 0
            ? source.MaxParticipantsAddedPerDay
            : target.MaxParticipantsAddedPerDay;
        target.MinMinutesBetweenParticipantAdds = source.MinMinutesBetweenParticipantAdds > 0
            ? source.MinMinutesBetweenParticipantAdds
            : target.MinMinutesBetweenParticipantAdds;
        target.ParticipantsAddedToday = Math.Max(target.ParticipantsAddedToday, source.ParticipantsAddedToday);
        target.ParticipantAddQuotaDateUtc = MaxDate(target.ParticipantAddQuotaDateUtc, source.ParticipantAddQuotaDateUtc);
        target.LastParticipantAddAt = MaxDate(target.LastParticipantAddAt, source.LastParticipantAddAt);
    }

    private static WhatsAppInstanceParticipantAddSafetySettings? FindInstanceSettings(
        WhatsAppAdminAutomationSettings automation,
        string? normalizedInstanceName,
        bool createIfMissing = false)
    {
        if (string.IsNullOrWhiteSpace(normalizedInstanceName))
        {
            return null;
        }

        var existing = automation.InstanceParticipantAddSafety
            .FirstOrDefault(x => string.Equals(x.InstanceName, normalizedInstanceName, StringComparison.OrdinalIgnoreCase));

        if (existing is not null || !createIfMissing)
        {
            return existing;
        }

        var created = new WhatsAppInstanceParticipantAddSafetySettings
        {
            InstanceName = normalizedInstanceName,
            MaxParticipantsAddedPerDay = Math.Max(1, automation.MaxParticipantsAddedPerDay),
            MinMinutesBetweenParticipantAdds = Math.Max(1, automation.MinMinutesBetweenParticipantAdds),
            ParticipantsAddedToday = 0,
            ParticipantAddQuotaDateUtc = automation.ParticipantAddQuotaDateUtc,
            LastParticipantAddAt = null
        };
        automation.InstanceParticipantAddSafety.Add(created);
        return created;
    }

    private static string? NormalizeInstanceName(string? instanceName)
    {
        return string.IsNullOrWhiteSpace(instanceName) ? null : instanceName.Trim();
    }

    private static DateTimeOffset? MaxDate(DateTimeOffset? left, DateTimeOffset? right)
    {
        if (left is null) return right;
        if (right is null) return left;
        return left >= right ? left : right;
    }
}
