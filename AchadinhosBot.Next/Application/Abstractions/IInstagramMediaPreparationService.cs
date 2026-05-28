using AchadinhosBot.Next.Domain.Instagram;

namespace AchadinhosBot.Next.Application.Abstractions;

public interface IInstagramMediaPreparationService
{
    Task<InstagramMediaPreparationResult> PrepareAsync(
        InstagramPublishDraft draft,
        string? publicBaseUrl,
        CancellationToken cancellationToken);
}

public sealed record InstagramMediaPreparationResult(
    bool Success,
    IReadOnlyList<string> MediaUrls,
    string? Error,
    bool IsTransient = false,
    IReadOnlyList<string>? OriginalSelectedImageUrls = null,
    IReadOnlyList<string>? NormalizedImageUrls = null);
