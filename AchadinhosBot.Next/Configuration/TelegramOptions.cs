using System.ComponentModel.DataAnnotations;

namespace AchadinhosBot.Next.Configuration;

public sealed class TelegramOptions
{
    public int ApiId { get; init; }
    public string ApiHash { get; init; } = string.Empty;
    public string BotToken { get; init; } = string.Empty;
    public long DestinationChatId { get; init; }
    public long LogsChatId { get; init; }
    public string? UserbotPhone { get; init; }
}
