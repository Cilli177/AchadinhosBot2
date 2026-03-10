namespace AchadinhosBot.Next.Application.Abstractions;

public interface IInstagramPublishService
{
    Task<InstagramPublishDispatchResult> QueuePublishAsync(string draftId, string? actor, CancellationToken cancellationToken);
    Task<InstagramPublishExecutionOutcome> ExecutePublishAsync(string draftId, CancellationToken cancellationToken);
}

public sealed record InstagramPublishDispatchResult(
    bool Accepted,
    string Mode,
    string MessageId,
    bool PersistedLocally,
    int StatusCode,
    string? Error = null);

public sealed record InstagramPublishExecutionOutcome(
    bool Success,
    int StatusCode,
    string? MediaId,
    string? Error,
    string? DraftId,
    bool ShouldRetry = false);
