using AchadinhosBot.Next.Domain.Logs;

namespace AchadinhosBot.Next.Application.Abstractions;

public interface IWhatsAppParticipantBlastProgressStore
{
    Task AppendAsync(WhatsAppParticipantBlastProgressEntry entry, CancellationToken cancellationToken);
    Task<IReadOnlyList<WhatsAppParticipantBlastProgressEntry>> ListAsync(string? operationId, int limit, CancellationToken cancellationToken);
    Task ClearAsync(CancellationToken cancellationToken);
}
