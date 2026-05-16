using AchadinhosBot.Next.Domain.Models;

namespace AchadinhosBot.Next.Application.Abstractions;

public interface IWhatsAppGroupMembershipStore
{
    Task AppendAsync(WhatsAppGroupMembershipEvent @event, CancellationToken cancellationToken);
    Task<IReadOnlyList<WhatsAppGroupMembershipEvent>> ListAsync(CancellationToken cancellationToken);
    
    // Métodos para controle de estado atual e sincronização
    Task<IReadOnlyList<string>> GetParticipantsAsync(string groupId, CancellationToken cancellationToken);
    Task<IReadOnlyList<string>> GetParticipantsAsync(string groupId, string? instanceName, CancellationToken cancellationToken);
    Task SetParticipantsAsync(string groupId, IEnumerable<string> participants, CancellationToken cancellationToken);
    Task SetParticipantsAsync(string groupId, string? instanceName, IEnumerable<string> participants, CancellationToken cancellationToken);
}
