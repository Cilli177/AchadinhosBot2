using AchadinhosBot.Next.Domain.Logs;

namespace AchadinhosBot.Next.Application.Abstractions;

public interface IInstagramAiLogStore
{
    Task AppendAsync(InstagramAiLogEntry entry, CancellationToken ct);
    Task<IReadOnlyList<InstagramAiLogEntry>> ListAsync(int take, CancellationToken ct);
    Task ClearAsync(CancellationToken ct);
}
