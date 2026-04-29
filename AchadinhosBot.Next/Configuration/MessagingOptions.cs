using System.ComponentModel.DataAnnotations;

namespace AchadinhosBot.Next.Configuration;

public sealed class MessagingOptions
{
    public string? DataDirectory { get; init; }

    public string BotConversorQueueName { get; init; } = "bot-conversor-webhook";

    public string WhatsAppOutboundQueueName { get; init; } = "whatsapp-outbound";

    public string TelegramOutboundQueueName { get; init; } = "telegram-outbound";

    [Range(5, 3600)]
    public int OutboxReplayIntervalSeconds { get; init; } = 30;

    [Range(1, 500)]
    public int OutboxBatchSize { get; init; } = 25;

    [Range(30, 86400)]
    public int OutboundDeduplicationWindowSeconds { get; init; } = 300;

    [Range(24, 720)]
    public int OfficialOfferRepeatWindowHours { get; init; } = 24;

    // Optional CSV list of fallback instances for outbound WhatsApp send attempts.
    // Example: "ZapOfertas2,ZapOfertasBackup"
    public string? WhatsAppFailoverInstancesCsv { get; init; }

    public string ResolveDataDirectory()
    {
        if (!string.IsNullOrWhiteSpace(DataDirectory))
        {
            return DataDirectory.Trim();
        }

        return Path.Combine(AppContext.BaseDirectory, "data", "messaging");
    }

    public IReadOnlyList<string> ResolveWhatsAppFailoverInstances()
    {
        if (string.IsNullOrWhiteSpace(WhatsAppFailoverInstancesCsv))
        {
            return Array.Empty<string>();
        }

        return WhatsAppFailoverInstancesCsv
            .Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }
}
