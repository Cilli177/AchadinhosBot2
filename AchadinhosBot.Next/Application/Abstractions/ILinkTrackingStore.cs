using AchadinhosBot.Next.Domain.Logs;

namespace AchadinhosBot.Next.Application.Abstractions;

public interface ILinkTrackingStore
{
    Task<LinkTrackingEntry> CreateAsync(string targetUrl, CancellationToken cancellationToken);
    Task<LinkTrackingEntry?> RegisterClickAsync(string trackingId, CancellationToken cancellationToken);
}
