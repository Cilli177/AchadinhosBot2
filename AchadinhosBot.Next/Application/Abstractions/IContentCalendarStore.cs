using AchadinhosBot.Next.Domain.Content;

namespace AchadinhosBot.Next.Application.Abstractions;

public interface IContentCalendarStore
{
    Task<IReadOnlyList<ContentCalendarItem>> ListAsync(CancellationToken ct);
    Task<ContentCalendarItem?> GetAsync(string id, CancellationToken ct);
    Task SaveAsync(ContentCalendarItem item, CancellationToken ct);
    Task DeleteAsync(string id, CancellationToken ct);
    Task<string> ExportCsvAsync(CancellationToken ct);
}
