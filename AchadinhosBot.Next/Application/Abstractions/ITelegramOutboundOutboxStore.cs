using AchadinhosBot.Next.Application.Consumers;

namespace AchadinhosBot.Next.Application.Abstractions;

public interface ITelegramOutboundOutboxStore
{
    Task SaveAsync(SendTelegramMessageCommand command, CancellationToken cancellationToken);
    Task<IReadOnlyList<SendTelegramMessageCommand>> ListPendingAsync(CancellationToken cancellationToken);
    Task DeleteAsync(string messageId, CancellationToken cancellationToken);
}
