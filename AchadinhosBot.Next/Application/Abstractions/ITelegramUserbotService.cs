namespace AchadinhosBot.Next.Application.Abstractions;

public interface ITelegramUserbotService
{
    Task<IReadOnlyList<TelegramUserbotChat>> GetDialogsAsync(CancellationToken cancellationToken);
    Task<bool> RefreshDialogsAsync(CancellationToken cancellationToken);
    bool IsReady { get; }
}

public sealed record TelegramUserbotChat(long Id, string Title, string Type);
