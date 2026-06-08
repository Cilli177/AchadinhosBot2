using AchadinhosBot.Next.Domain.Logs;

namespace AchadinhosBot.Next.Application.Abstractions;

public interface IWhatsAppNicheOperationsStore
{
    Task AppendRouteEventAsync(WhatsAppNicheRouteEvent entry, CancellationToken cancellationToken);
    Task<IReadOnlyList<WhatsAppNicheRouteEvent>> ListRouteEventsAsync(int limit, CancellationToken cancellationToken);
    Task SaveReviewAsync(WhatsAppNicheReviewItem item, CancellationToken cancellationToken);
    Task<IReadOnlyList<WhatsAppNicheReviewItem>> ListReviewsAsync(string? status, int limit, CancellationToken cancellationToken);
    Task<WhatsAppNicheReviewItem?> GetReviewAsync(string id, CancellationToken cancellationToken);
    Task UpdateReviewAsync(WhatsAppNicheReviewItem item, CancellationToken cancellationToken);
}
