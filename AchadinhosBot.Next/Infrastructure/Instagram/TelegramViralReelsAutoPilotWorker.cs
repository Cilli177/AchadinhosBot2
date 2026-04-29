using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Domain.Settings;

namespace AchadinhosBot.Next.Infrastructure.Instagram;

public sealed class TelegramViralReelsAutoPilotWorker : BackgroundService
{
    private readonly ISettingsStore _settingsStore;
    private readonly TelegramViralReelsAutoPilotService _service;
    private readonly ILogger<TelegramViralReelsAutoPilotWorker> _logger;

    public TelegramViralReelsAutoPilotWorker(
        ISettingsStore settingsStore,
        TelegramViralReelsAutoPilotService service,
        ILogger<TelegramViralReelsAutoPilotWorker> logger)
    {
        _settingsStore = settingsStore;
        _service = service;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var nextRun = DateTimeOffset.MinValue;

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                var now = DateTimeOffset.UtcNow;
                var settings = await _settingsStore.GetAsync(stoppingToken);
                var publish = settings.InstagramPublish ?? new InstagramPublishSettings();

                if (!publish.ViralReelsAutoPilotEnabled)
                {
                    nextRun = DateTimeOffset.MinValue;
                }
                else if (nextRun == DateTimeOffset.MinValue)
                {
                    nextRun = CalculateNextRunAt(now, publish);
                    _logger.LogInformation("Telegram viral reels autopilot next scheduled run: {NextRunUtc}", nextRun);
                }
                else if (now >= nextRun)
                {
                    var result = await _service.RunOnceAsync(stoppingToken);
                    _logger.LogInformation(
                        "Telegram viral reels autopilot run: success={Success} sourceKey={SourceKey} draftId={DraftId} approvalSent={ApprovalSent} target={ApprovalTarget} message={Message}",
                        result.Success,
                        result.SourceKey,
                        result.DraftId,
                        result.ApprovalSent,
                        result.ApprovalTarget,
                        result.Message);

                    nextRun = CalculateNextRunAt(DateTimeOffset.UtcNow.AddSeconds(1), publish);
                }

                await SafeDelay(TimeSpan.FromMinutes(1), stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Telegram viral reels autopilot worker iteration failed.");
                await SafeDelay(TimeSpan.FromMinutes(2), stoppingToken);
            }
        }
    }

    public static DateTimeOffset CalculateNextRunAt(DateTimeOffset nowUtc, InstagramPublishSettings publish)
    {
        var timeZone = ResolveScheduleTimeZone();
        var localNow = TimeZoneInfo.ConvertTime(nowUtc, timeZone);
        var scheduleTimes = (publish.ViralReelsScheduleTimes ?? new List<string>())
            .Select(ParseScheduleTime)
            .Where(x => x.HasValue)
            .Select(x => x!.Value)
            .OrderBy(x => x)
            .ToList();

        if (scheduleTimes.Count == 0)
        {
            var interval = TimeSpan.FromHours(Math.Clamp(publish.ViralReelsIntervalHours, 1, 72));
            return nowUtc.Add(interval);
        }

        foreach (var scheduleTime in scheduleTimes)
        {
            var candidateLocal = localNow.Date.Add(scheduleTime);
            if (candidateLocal > localNow.DateTime)
            {
                return ToUtc(candidateLocal, timeZone);
            }
        }

        return ToUtc(localNow.Date.AddDays(1).Add(scheduleTimes[0]), timeZone);
    }

    private static TimeSpan? ParseScheduleTime(string? value)
    {
        return TimeSpan.TryParse(value, out var parsed) && parsed >= TimeSpan.Zero && parsed < TimeSpan.FromDays(1)
            ? parsed
            : null;
    }

    private static DateTimeOffset ToUtc(DateTime localDateTime, TimeZoneInfo timeZone)
    {
        var offset = timeZone.GetUtcOffset(localDateTime);
        return new DateTimeOffset(localDateTime, offset).ToUniversalTime();
    }

    private static TimeZoneInfo ResolveScheduleTimeZone()
    {
        foreach (var id in new[] { "America/Sao_Paulo", "E. South America Standard Time" })
        {
            try
            {
                return TimeZoneInfo.FindSystemTimeZoneById(id);
            }
            catch (TimeZoneNotFoundException)
            {
            }
            catch (InvalidTimeZoneException)
            {
            }
        }

        return TimeZoneInfo.Local;
    }

    private static async Task SafeDelay(TimeSpan delay, CancellationToken ct)
    {
        try
        {
            await Task.Delay(delay, ct);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
        }
    }
}
