using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Configuration;
using AchadinhosBot.Next.Domain.Logs;
using Microsoft.Extensions.Options;

namespace AchadinhosBot.Next;

public sealed class OperationalStatusService
{
    private readonly OperationalReadinessService _readinessService;
    private readonly IMediaFailureLogStore _mediaFailureLogStore;
    private readonly IConversionLogStore _conversionLogStore;
    private readonly IWhatsAppOutboundLogStore _whatsAppOutboundLogStore;
    private readonly ITelegramOutboundLogStore _telegramOutboundLogStore;
    private readonly OperationalReadinessOptions _readinessOptions;

    public OperationalStatusService(
        OperationalReadinessService readinessService,
        IMediaFailureLogStore mediaFailureLogStore,
        IConversionLogStore conversionLogStore,
        IWhatsAppOutboundLogStore whatsAppOutboundLogStore,
        ITelegramOutboundLogStore telegramOutboundLogStore,
        IOptions<OperationalReadinessOptions> readinessOptions)
    {
        _readinessService = readinessService;
        _mediaFailureLogStore = mediaFailureLogStore;
        _conversionLogStore = conversionLogStore;
        _whatsAppOutboundLogStore = whatsAppOutboundLogStore;
        _telegramOutboundLogStore = telegramOutboundLogStore;
        _readinessOptions = readinessOptions.Value;
    }

    public async Task<OperationalStatusSnapshot> GetSnapshotAsync(
        bool startTelegramBotWorker,
        bool startTelegramUserbotWorker,
        CancellationToken cancellationToken)
    {
        var readiness = await _readinessService.EvaluateAsync(startTelegramBotWorker, startTelegramUserbotWorker, cancellationToken);
        var mediaFailures = await _mediaFailureLogStore.ListAsync(100, cancellationToken);
        var conversions = await _conversionLogStore.QueryAsync(new ConversionLogQuery { Limit = 200 }, cancellationToken);
        var whatsAppOutbound = await _whatsAppOutboundLogStore.ListRecentAsync(100, cancellationToken);
        var telegramOutbound = await _telegramOutboundLogStore.ListRecentAsync(100, cancellationToken);

        var since = DateTimeOffset.UtcNow.AddHours(-24);
        var recentMediaFailures = mediaFailures
            .Where(x => x.Timestamp >= since && IsActualMediaFailure(x))
            .OrderByDescending(x => x.Timestamp)
            .ToArray();
        var recentConversions = conversions.Where(x => x.Timestamp >= since).ToArray();
        var recentWhatsAppOutbound = whatsAppOutbound.Where(x => x.CreatedAtUtc >= since).ToArray();
        var recentTelegramOutbound = telegramOutbound.Where(x => x.CreatedAtUtc >= since).ToArray();

        var alerts = new List<OperationalAlert>();
        if (!readiness.Ready)
        {
            alerts.Add(new OperationalAlert("readiness", "critical", string.Join(" | ", readiness.Issues)));
        }

        if (recentMediaFailures.Length >= Math.Max(3, _readinessOptions.CriticalOutboxBacklog / 5))
        {
            alerts.Add(new OperationalAlert("media-failure", "warning", $"{recentMediaFailures.Length} falha(s) de midia nas ultimas 24h."));
        }

        return new OperationalStatusSnapshot(
            readiness,
            alerts,
            new OperationalVolumeSnapshot(
                recentConversions.Length,
                recentConversions.Count(x => x.Success),
                recentWhatsAppOutbound.Length,
                recentTelegramOutbound.Length,
                recentMediaFailures.Length),
            recentMediaFailures.Take(10).ToArray());
    }

    public static bool IsActualMediaFailure(MediaFailureEntry entry)
    {
        return entry is not null && !entry.Success;
    }
}

public sealed record OperationalStatusSnapshot(
    OperationalReadinessReport Readiness,
    IReadOnlyList<OperationalAlert> Alerts,
    OperationalVolumeSnapshot Volumes,
    IReadOnlyList<MediaFailureEntry> RecentMediaFailures);

public sealed record OperationalAlert(string Code, string Severity, string Message);

public sealed record OperationalVolumeSnapshot(
    int Conversions24h,
    int SuccessfulConversions24h,
    int WhatsAppOutbound24h,
    int TelegramOutbound24h,
    int MediaFailures24h);
