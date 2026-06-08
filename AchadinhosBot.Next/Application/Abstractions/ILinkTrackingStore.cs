using AchadinhosBot.Next.Domain.Logs;

namespace AchadinhosBot.Next.Application.Abstractions;

public interface ILinkTrackingStore
{
    Task<LinkTrackingEntry> CreateAsync(LinkTrackingCreateRequest request, CancellationToken cancellationToken);
    Task<LinkTrackingEntry> CreateAsync(string targetUrl, CancellationToken cancellationToken);
    Task<LinkTrackingEntry> GetOrCreateAsync(LinkTrackingCreateRequest request, CancellationToken cancellationToken);
    Task<LinkTrackingEntry> GetOrCreateAsync(string targetUrl, CancellationToken cancellationToken);
    Task<LinkTrackingEntry?> RegisterClickAsync(string trackingId, CancellationToken cancellationToken);
    Task<LinkTrackingEntry?> GetLinkAsync(string id, CancellationToken cancellationToken);
    Task<IReadOnlyList<LinkTrackingEntry>> ListAsync(CancellationToken cancellationToken);
}
