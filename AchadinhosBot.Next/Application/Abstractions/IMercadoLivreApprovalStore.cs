using AchadinhosBot.Next.Domain.Compliance;

namespace AchadinhosBot.Next.Application.Abstractions;

public interface IMercadoLivreApprovalStore
{
    Task AppendAsync(MercadoLivrePendingApproval entry, CancellationToken cancellationToken);
    Task<IReadOnlyList<MercadoLivrePendingApproval>> ListAsync(string? status, int limit, CancellationToken cancellationToken);
    Task<MercadoLivrePendingApproval?> GetAsync(string id, CancellationToken cancellationToken);
    Task<bool> DecideAsync(
        string id,
        string status,
        string reviewedBy,
        string? reviewNote,
        string? convertedText,
        int convertedLinks,
        CancellationToken cancellationToken);
}
