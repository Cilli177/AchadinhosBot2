using AchadinhosBot.Next.Application.Consumers;

namespace AchadinhosBot.Next.Application.Abstractions;

public interface IContentCalendarCommandOutboxStore
{
    Task SaveAsync(ContentCalendarCommandEnvelope envelope, CancellationToken ct);
    Task<IReadOnlyList<ContentCalendarCommandEnvelope>> ListPendingAsync(CancellationToken ct);
    Task DeleteAsync(string messageId, CancellationToken ct);
}
