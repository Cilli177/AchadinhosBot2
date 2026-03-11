using AchadinhosBot.Next.Domain.Instagram;

namespace AchadinhosBot.Next.Application.Abstractions;

public interface IVideoProcessingService
{
    Task<VideoProcessingResult> PrepareForInstagramPublicationAsync(
        InstagramPublishDraft draft,
        string? publicBaseUrl,
        CancellationToken cancellationToken);
}

public sealed record VideoProcessingResult(
    bool Success,
    string? VideoUrl,
    string? CoverUrl = null,
    bool WasProcessed = false,
    string? Error = null);
