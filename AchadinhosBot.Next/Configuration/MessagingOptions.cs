using System.ComponentModel.DataAnnotations;

namespace AchadinhosBot.Next.Configuration;

public sealed class MessagingOptions
{
    public string? DataDirectory { get; init; }

    [Required]
    public string BotConversorQueueName { get; init; } = "bot-conversor-webhook";

    [Required]
    public string WhatsAppOutboundQueueName { get; init; } = "whatsapp-outbound";

    [Required]
    public string TelegramOutboundQueueName { get; init; } = "telegram-outbound";

    [Range(5, 3600)]
    public int OutboxReplayIntervalSeconds { get; init; } = 30;

    [Range(1, 500)]
    public int OutboxBatchSize { get; init; } = 25;

    [Range(30, 86400)]
    public int OutboundDeduplicationWindowSeconds { get; init; } = 300;

    public string ResolveDataDirectory()
    {
        if (!string.IsNullOrWhiteSpace(DataDirectory))
        {
            return DataDirectory.Trim();
        }

        return Path.Combine(AppContext.BaseDirectory, "data", "messaging");
    }
}
