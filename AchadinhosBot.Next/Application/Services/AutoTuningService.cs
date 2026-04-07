using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Domain.Governance;

namespace AchadinhosBot.Next.Application.Services;

public sealed class AutoTuningService : IAutoTuningService
{
    private readonly IOperationalAnalyticsService _analytics;
    private readonly ISettingsStore _settingsStore;

    public AutoTuningService(
        IOperationalAnalyticsService analytics,
        ISettingsStore settingsStore)
    {
        _analytics = analytics;
        _settingsStore = settingsStore;
    }

    public async Task<IReadOnlyList<TuningChangeRecord>> RunAsync(CancellationToken cancellationToken)
    {
        var changes = new List<TuningChangeRecord>();
        var summary24h = await _analytics.GetSummaryAsync(24, cancellationToken);
        var settings = await _settingsStore.GetAsync(cancellationToken);

        // Ajuste de poll do ContentCalendar baseado em pressão operacional.
        var currentPoll = settings.ContentCalendar.PollIntervalSeconds;
        var nextPoll = currentPoll;
        if (summary24h.Conversions.SuccessRate < 0.35 && currentPoll < 120)
        {
            nextPoll = currentPoll + 15;
        }
        else if (summary24h.Conversions.SuccessRate > 0.65 && currentPoll > 30)
        {
            nextPoll = currentPoll - 10;
        }

        nextPoll = Math.Clamp(nextPoll, 15, 300);
        if (nextPoll != currentPoll)
        {
            settings.ContentCalendar.PollIntervalSeconds = nextPoll;
            changes.Add(new TuningChangeRecord(
                Guid.NewGuid().ToString("N"),
                "content_calendar.poll_interval_seconds",
                "global",
                currentPoll.ToString(),
                nextPoll.ToString(),
                "Ajuste automático baseado na taxa de sucesso de conversões (24h).",
                "Equilibrar custo operacional e throughput de automação.",
                DateTimeOffset.UtcNow));
        }

        // Ajuste de auto-pilot do Instagram por taxa de publish com falha.
        var publishFailed = summary24h.InstagramPublish.Failed;
        var publishTotal = summary24h.InstagramPublish.Published + summary24h.InstagramPublish.Failed + summary24h.InstagramPublish.Queued;
        if (publishTotal > 0)
        {
            var failRate = (double)publishFailed / publishTotal;
            var currentThreshold = settings.InstagramPublish.AutoPilotMinimumImageMatchScore;
            var nextThreshold = currentThreshold;
            if (failRate > 0.30 && currentThreshold < 95)
            {
                nextThreshold += 5;
            }
            else if (failRate < 0.10 && currentThreshold > 70)
            {
                nextThreshold -= 3;
            }

            nextThreshold = Math.Clamp(nextThreshold, 60, 99);
            if (nextThreshold != currentThreshold)
            {
                settings.InstagramPublish.AutoPilotMinimumImageMatchScore = nextThreshold;
                changes.Add(new TuningChangeRecord(
                    Guid.NewGuid().ToString("N"),
                    "instagram_publish.autopilot_minimum_image_match_score",
                    "global",
                    currentThreshold.ToString(),
                    nextThreshold.ToString(),
                    "Ajuste automático pela taxa de falhas de publish (24h).",
                    "Reduzir erro de publicação e melhorar qualidade dos candidatos.",
                    DateTimeOffset.UtcNow));
            }
        }

        if (changes.Count > 0)
        {
            await _settingsStore.SaveAsync(settings, cancellationToken);
        }

        return changes;
    }
}
