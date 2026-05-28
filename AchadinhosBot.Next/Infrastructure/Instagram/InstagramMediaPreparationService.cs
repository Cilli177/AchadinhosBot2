using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Domain.Instagram;
using AchadinhosBot.Next.Infrastructure.Media;

namespace AchadinhosBot.Next.Infrastructure.Instagram;

public sealed class InstagramMediaPreparationService : IInstagramMediaPreparationService
{
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly IMediaStore _mediaStore;
    private readonly InstagramLinkMetaService _linkMetaService;
    private readonly IVideoProcessingService _videoProcessingService;
    private readonly ILogger<InstagramMediaPreparationService> _logger;

    public InstagramMediaPreparationService(
        IHttpClientFactory httpClientFactory,
        IMediaStore mediaStore,
        InstagramLinkMetaService linkMetaService,
        IVideoProcessingService videoProcessingService,
        ILogger<InstagramMediaPreparationService> logger)
    {
        _httpClientFactory = httpClientFactory;
        _mediaStore = mediaStore;
        _linkMetaService = linkMetaService;
        _videoProcessingService = videoProcessingService;
        _logger = logger;
    }

    public async Task<InstagramMediaPreparationResult> PrepareAsync(
        InstagramPublishDraft draft,
        string? publicBaseUrl,
        CancellationToken cancellationToken)
    {
        var selectedImageUrls = InstagramWorkflowSupport.ResolveSelectedImageUrls(draft);
        var publishImageUrls = selectedImageUrls;
        var normalized = await InstagramWorkflowSupport.NormalizeInstagramImagesAsync(
            _httpClientFactory,
            _mediaStore,
            publicBaseUrl,
            draft.PostType,
            selectedImageUrls,
            cancellationToken);
        if (normalized.Count > 0)
        {
            publishImageUrls = normalized;
        }

        var publishMediaUrls = publishImageUrls;
        if (draft.PostType is "story" or "feed" &&
            publishMediaUrls.Count > 0 &&
            publishMediaUrls.All(IsMissingLocalMediaUrl))
        {
            var repaired = await TryRepairExpiredImageMediaAsync(draft, publicBaseUrl, cancellationToken);
            if (repaired.Count > 0)
            {
                publishImageUrls = repaired;
                publishMediaUrls = repaired;
            }
        }

        if (!string.IsNullOrWhiteSpace(draft.VideoUrl))
        {
            var videoResult = await _videoProcessingService.PrepareForInstagramPublicationAsync(draft, publicBaseUrl, cancellationToken);
            if (!videoResult.Success || string.IsNullOrWhiteSpace(videoResult.VideoUrl))
            {
                return new InstagramMediaPreparationResult(
                    false,
                    Array.Empty<string>(),
                    videoResult.Error ?? "Falha ao preparar video para publicacao.");
            }

            draft.VideoUrl = videoResult.VideoUrl;
            if (!string.IsNullOrWhiteSpace(videoResult.CoverUrl))
            {
                draft.VideoCoverUrl = videoResult.CoverUrl;
            }

            if (draft.PostType is "reel" or "story" || publishImageUrls.Count == 0)
            {
                publishMediaUrls = new List<string> { videoResult.VideoUrl };
            }
        }

        return new InstagramMediaPreparationResult(
            true,
            publishMediaUrls,
            null,
            false,
            selectedImageUrls,
            normalized);
    }

    private async Task<List<string>> TryRepairExpiredImageMediaAsync(
        InstagramPublishDraft draft,
        string? publicBaseUrl,
        CancellationToken cancellationToken)
    {
        var offerUrl = FirstNonEmpty(
            draft.OriginalOfferUrl,
            draft.OfferUrl,
            draft.AutoReplyLink,
            draft.Ctas?.FirstOrDefault(c => !string.IsNullOrWhiteSpace(c.Link))?.Link);
        if (string.IsNullOrWhiteSpace(offerUrl))
        {
            return new List<string>();
        }

        try
        {
            var meta = await _linkMetaService.GetMetaAsync(offerUrl, cancellationToken);
            var candidates = (meta.Images ?? new List<string>())
                .Where(x => !string.IsNullOrWhiteSpace(x))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Take(3)
                .ToList();
            if (candidates.Count == 0)
            {
                return new List<string>();
            }

            draft.ImageUrls = candidates;
            draft.SelectedImageIndexes = new List<int>();
            var normalized = await InstagramWorkflowSupport.NormalizeInstagramImagesAsync(
                _httpClientFactory,
                _mediaStore,
                publicBaseUrl,
                draft.PostType,
                candidates,
                cancellationToken);
            return normalized.Count > 0 ? normalized : candidates;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Falha ao reparar midia expirada do draft {DraftId}.", draft.Id);
            return new List<string>();
        }
    }

    private bool IsMissingLocalMediaUrl(string? url)
    {
        if (string.IsNullOrWhiteSpace(url) || !Uri.TryCreate(url, UriKind.Absolute, out var uri))
        {
            return false;
        }

        if (!uri.AbsolutePath.StartsWith("/media/", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        var id = Path.GetFileNameWithoutExtension(uri.AbsolutePath);
        return string.IsNullOrWhiteSpace(id) || !_mediaStore.TryGet(id, out _);
    }

    private static string? FirstNonEmpty(params string?[] values)
        => values.FirstOrDefault(x => !string.IsNullOrWhiteSpace(x))?.Trim();
}
