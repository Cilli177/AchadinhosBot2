using AchadinhosBot.Next.Domain.Logs;

namespace AchadinhosBot.Next.Application.Abstractions;

public interface IWhatsAppOutboundLogStore
{
    Task AppendAsync(WhatsAppOutboundLogEntry entry, CancellationToken cancellationToken);
    Task<IReadOnlyList<WhatsAppOutboundLogEntry>> ListRecentAsync(int limit, CancellationToken cancellationToken);
    Task<WhatsAppOutboundLogEntry?> GetAsync(string messageId, CancellationToken cancellationToken);
}
