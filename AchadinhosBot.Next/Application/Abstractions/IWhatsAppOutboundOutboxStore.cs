using AchadinhosBot.Next.Application.Consumers;

namespace AchadinhosBot.Next.Application.Abstractions;

public interface IWhatsAppOutboundOutboxStore
{
    Task SaveAsync(SendWhatsAppMessageCommand command, CancellationToken cancellationToken);
    Task<IReadOnlyList<SendWhatsAppMessageCommand>> ListPendingAsync(CancellationToken cancellationToken);
    Task DeleteAsync(string messageId, CancellationToken cancellationToken);
}
