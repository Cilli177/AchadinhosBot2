using AchadinhosBot.Next.Domain.Logs;

namespace AchadinhosBot.Next.Application.Abstractions;

public interface IMediaFailureLogStore
{
    Task AppendAsync(MediaFailureEntry entry, CancellationToken cancellationToken);
    Task<IReadOnlyList<MediaFailureEntry>> ListAsync(int limit, CancellationToken cancellationToken);
    Task ClearAsync(CancellationToken cancellationToken);
}
