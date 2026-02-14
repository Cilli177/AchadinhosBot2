using AchadinhosBot.Next.Domain.Instagram;

namespace AchadinhosBot.Next.Application.Abstractions;

public interface IInstagramPublishStore
{
    Task<IReadOnlyList<InstagramPublishDraft>> ListAsync(CancellationToken ct);
    Task<InstagramPublishDraft?> GetAsync(string id, CancellationToken ct);
    Task SaveAsync(InstagramPublishDraft draft, CancellationToken ct);
    Task UpdateAsync(InstagramPublishDraft draft, CancellationToken ct);
}
