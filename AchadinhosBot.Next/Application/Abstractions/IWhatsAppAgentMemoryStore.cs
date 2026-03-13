using AchadinhosBot.Next.Domain.Agents;

namespace AchadinhosBot.Next.Application.Abstractions;

public interface IWhatsAppAgentMemoryStore
{
    Task AppendAsync(WhatsAppAgentMemoryEntry entry, CancellationToken cancellationToken);
    Task<IReadOnlyDictionary<string, WhatsAppAgentMemoryEntry>> GetLatestByMessageIdsAsync(IEnumerable<string> messageIds, CancellationToken cancellationToken);
}
