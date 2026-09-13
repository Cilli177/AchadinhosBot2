using AchadinhosBot.Next.Domain.Content;

namespace AchadinhosBot.Next.Application.Abstractions;

public interface IContentCalendarStore
{
    Task<IReadOnlyList<ContentCalendarItem>> ListAsync(CancellationToken ct);
    Task<ContentCalendarItem?> GetAsync(string id, CancellationToken ct);
    Task SaveAsync(ContentCalendarItem item, CancellationToken ct);
    /// <summary>Claims one planned item before external work so concurrent runs cannot process it twice.</summary>
    Task<ContentCalendarItem?> TryClaimDueAsync(string id, string executionId, DateTimeOffset now, int maxAttempts, CancellationToken ct);
    Task DeleteAsync(string id, CancellationToken ct);
    Task<string> ExportCsvAsync(CancellationToken ct);
}
