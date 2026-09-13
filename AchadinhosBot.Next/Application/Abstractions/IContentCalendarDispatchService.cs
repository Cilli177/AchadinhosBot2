using AchadinhosBot.Next.Infrastructure.Content;

namespace AchadinhosBot.Next.Application.Abstractions;

public interface IContentCalendarDispatchService
{
    Task<ContentCalendarDispatchResult> QueueProcessDueAsync(string actor, CancellationToken ct);
}
