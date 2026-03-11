namespace AchadinhosBot.Next.Application.Abstractions;

public interface IInstagramWebhookService
{
    Task<InstagramWebhookProcessResult> ProcessAsync(string body, CancellationToken cancellationToken);
    string? ValidateChallenge(string mode, string token, string challenge);
    Task<InstagramManualReplyResult> QueueManualCommentReplyAsync(string commentStoreId, string reply, CancellationToken cancellationToken);
}

public sealed record InstagramWebhookProcessResult(bool Success, int CommentsProcessed, int DirectMessagesProcessed);

public sealed record InstagramManualReplyResult(bool Success, int StatusCode, string? Error = null);
