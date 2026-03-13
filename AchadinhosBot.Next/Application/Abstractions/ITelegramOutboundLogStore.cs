using AchadinhosBot.Next.Domain.Logs;

namespace AchadinhosBot.Next.Application.Abstractions;

public interface ITelegramOutboundLogStore
{
    Task AppendAsync(TelegramOutboundLogEntry entry, CancellationToken cancellationToken);
    Task<IReadOnlyList<TelegramOutboundLogEntry>> ListRecentAsync(int limit, CancellationToken cancellationToken);
    Task<TelegramOutboundLogEntry?> GetAsync(string messageId, CancellationToken cancellationToken);
}
