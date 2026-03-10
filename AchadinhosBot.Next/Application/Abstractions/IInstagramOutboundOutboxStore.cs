using AchadinhosBot.Next.Application.Consumers;

namespace AchadinhosBot.Next.Application.Abstractions;

public interface IInstagramOutboundOutboxStore
{
    Task SaveAsync(InstagramOutboundEnvelope envelope, CancellationToken cancellationToken);
    Task<IReadOnlyList<InstagramOutboundEnvelope>> ListPendingAsync(CancellationToken cancellationToken);
    Task DeleteAsync(string messageId, CancellationToken cancellationToken);
}
