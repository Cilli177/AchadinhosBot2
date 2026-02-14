using AchadinhosBot.Next.Domain.Logs;

namespace AchadinhosBot.Next.Application.Abstractions;

public interface IClickLogStore
{
    Task AppendAsync(ClickLogEntry entry, CancellationToken cancellationToken);
    Task<IReadOnlyList<ClickLogEntry>> QueryAsync(string? search, int limit, CancellationToken cancellationToken);
    Task ClearAsync(CancellationToken cancellationToken);
}
