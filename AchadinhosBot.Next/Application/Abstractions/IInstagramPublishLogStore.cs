using AchadinhosBot.Next.Domain.Logs;

namespace AchadinhosBot.Next.Application.Abstractions;

public interface IInstagramPublishLogStore
{
    Task AppendAsync(InstagramPublishLogEntry entry, CancellationToken ct);
    Task<IReadOnlyList<InstagramPublishLogEntry>> ListAsync(int take, CancellationToken ct);
    Task ClearAsync(CancellationToken ct);
}
