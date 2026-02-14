using AchadinhosBot.Next.Domain.Instagram;

namespace AchadinhosBot.Next.Application.Abstractions;

public interface IInstagramCommentStore
{
    Task<IReadOnlyList<InstagramCommentPending>> ListPendingAsync(CancellationToken ct);
    Task AddAsync(InstagramCommentPending comment, CancellationToken ct);
    Task<InstagramCommentPending?> GetAsync(string id, CancellationToken ct);
    Task UpdateAsync(InstagramCommentPending comment, CancellationToken ct);
}
