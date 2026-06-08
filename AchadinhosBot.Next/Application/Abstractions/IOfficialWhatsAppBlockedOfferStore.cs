using AchadinhosBot.Next.Domain.Logs;

namespace AchadinhosBot.Next.Application.Abstractions;

public interface IOfficialWhatsAppBlockedOfferStore
{
    Task AppendAsync(OfficialWhatsAppBlockedOfferEntry entry, CancellationToken cancellationToken);
    Task<IReadOnlyList<OfficialWhatsAppBlockedOfferEntry>> ListAsync(int limit, CancellationToken cancellationToken);
    Task ClearAsync(CancellationToken cancellationToken);
}
