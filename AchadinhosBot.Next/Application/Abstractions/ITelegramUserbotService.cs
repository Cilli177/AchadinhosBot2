namespace AchadinhosBot.Next.Application.Abstractions;

public interface ITelegramUserbotService
{
    Task<IReadOnlyList<TelegramUserbotChat>> GetDialogsAsync(CancellationToken cancellationToken);
    Task<bool> RefreshDialogsAsync(CancellationToken cancellationToken);
    Task<TelegramUserbotReplayResult> ReplayRecentOffersToWhatsAppAsync(long sourceChatId, int count, CancellationToken cancellationToken);
    bool IsReady { get; }
}

public sealed record TelegramUserbotChat(long Id, string Title, string Type);
public sealed record TelegramUserbotReplayResult(
    bool Success,
    string Message,
    long SourceChatId,
    int Requested,
    int Loaded,
    int Replayed,
    int Failed);
