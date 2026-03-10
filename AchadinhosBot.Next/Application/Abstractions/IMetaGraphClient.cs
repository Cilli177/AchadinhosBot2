using AchadinhosBot.Next.Domain.Settings;

namespace AchadinhosBot.Next.Application.Abstractions;

public interface IMetaGraphClient
{
    Task<MetaGraphOperationResult> ValidateConfigurationAsync(InstagramPublishSettings settings, CancellationToken cancellationToken);
    Task<MetaGraphOperationResult> GetMediaStatusAsync(InstagramPublishSettings settings, string mediaId, CancellationToken cancellationToken);
    Task<MetaGraphPublishResult> PublishAsync(InstagramPublishSettings settings, string postType, IReadOnlyList<string> mediaUrls, string caption, CancellationToken cancellationToken);
    Task<MetaGraphOperationResult> ReplyToCommentAsync(InstagramPublishSettings settings, string commentId, string message, CancellationToken cancellationToken);
    Task<MetaGraphOperationResult> SendDirectMessageAsync(InstagramPublishSettings settings, string recipientId, string message, CancellationToken cancellationToken);
}

public sealed record MetaGraphOperationResult(bool Success, string? Error = null, string? RawResponse = null, bool IsTransient = false);

public sealed record MetaGraphPublishResult(bool Success, string? MediaId = null, string? Error = null, bool IsTransient = false);
