using AchadinhosBot.Next.Domain.Logs;

namespace AchadinhosBot.Next.Application.Abstractions;

public interface IClickLogStore
{
    Task AppendAsync(ClickLogEntry entry, string? category, CancellationToken cancellationToken);
    Task<IReadOnlyList<ClickLogEntry>> QueryAsync(string? category, string? search, int limit, CancellationToken cancellationToken);
    Task ClearAsync(string? category, CancellationToken cancellationToken);
}
