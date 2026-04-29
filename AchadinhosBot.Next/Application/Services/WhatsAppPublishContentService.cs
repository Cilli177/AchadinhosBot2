using System.Text.RegularExpressions;
using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Configuration;
using AchadinhosBot.Next.Domain.Settings;
using Microsoft.Extensions.Options;

namespace AchadinhosBot.Next.Application.Services;

public sealed partial class WhatsAppPublishContentService
{
    private readonly IMessageProcessor _messageProcessor;
    private readonly AffiliateTrackedContentService _affiliateTrackedContentService;
    private readonly TrackingLinkShortenerService _trackingLinkShortenerService;
    private readonly IOfferImageResolver _offerImageResolver;
    private readonly ISettingsStore _settingsStore;
    private readonly DeliverySafetyOptions _deliverySafetyOptions;
    private readonly ILogger<WhatsAppPublishContentService> _logger;

    public WhatsAppPublishContentService(
        IMessageProcessor messageProcessor,
        AffiliateTrackedContentService affiliateTrackedContentService,
        TrackingLinkShortenerService trackingLinkShortenerService,
        IOfferImageResolver offerImageResolver,
        ISettingsStore settingsStore,
        IOptions<DeliverySafetyOptions> deliverySafetyOptions,
        ILogger<WhatsAppPublishContentService> logger)
    {
        _messageProcessor = messageProcessor;
        _affiliateTrackedContentService = affiliateTrackedContentService;
        _trackingLinkShortenerService = trackingLinkShortenerService;
        _offerImageResolver = offerImageResolver;
        _settingsStore = settingsStore;
        _deliverySafetyOptions = deliverySafetyOptions.Value;
        _logger = logger;
    }

    public async Task<string> PrepareAsync(string? text, string targetId, CancellationToken cancellationToken)
        => (await PrepareForSendAsync(text, null, targetId, cancellationToken)).Content;

    public async Task<WhatsAppPreparedContent> PrepareForSendAsync(
        string? text,
        string? preferredImageUrl,
        string targetId,
        CancellationToken cancellationToken)
    {
        var content = WhatsAppInviteLinkNormalizer.NormalizeOfficialInviteBlock(text);
        if (string.IsNullOrWhiteSpace(content))
        {
            return new WhatsAppPreparedContent(string.Empty, preferredImageUrl, null, null, null, false, null);
        }

        var originSurface = ResolveOriginSurface(targetId);
        var settings = await _settingsStore.GetAsync(cancellationToken);
        var footerText = ResolveFooterText(settings, targetId);

        var firstUrl = ExtractFirstUrl(content);
        var detectedStore = TrackingLinkShortenerService.ResolveStoreHint(firstUrl);

        if (!UrlRegex().IsMatch(content))
        {
            return new WhatsAppPreparedContent(content, preferredImageUrl, null, null, null, false, null);
        }

        string outboundContent = content;
        string? convertedOfferUrl = null;
        string? store = null;

        try
        {
            if (!string.Equals(detectedStore, "Mercado Livre", StringComparison.OrdinalIgnoreCase))
            {
                var processed = await _messageProcessor.ProcessAsync(
                    content,
                    "WhatsAppAdmin",
                    cancellationToken,
                    destinationChatRef: targetId);

                if (processed.Success && !string.IsNullOrWhiteSpace(processed.ConvertedText))
                {
                    var normalizedProcessed = WhatsAppInviteLinkNormalizer.NormalizeOfficialInviteBlock(processed.ConvertedText);
                    outboundContent = await _trackingLinkShortenerService.ApplyTrackingAsync(
                        normalizedProcessed,
                        originSurface,
                        cancellationToken);
                    outboundContent = AppendFooter(outboundContent, footerText);
                    outboundContent = WhatsAppInviteLinkNormalizer.NormalizeOfficialInviteBlock(outboundContent);
                    convertedOfferUrl = ExtractFirstUrl(outboundContent);
                    store = TrackingLinkShortenerService.ResolveStoreHint(convertedOfferUrl);
                    var imageResolution = await ResolveImageAsync(content, outboundContent, preferredImageUrl, store, cancellationToken);
                    return BuildPreparedContent(outboundContent, imageResolution);
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Falha ao preparar conteudo WhatsApp com comparativo. Target={TargetId}", targetId);
        }

        var rewritten = await _affiliateTrackedContentService.RewriteAsync(content, originSurface, cancellationToken);
        outboundContent = WhatsAppInviteLinkNormalizer.NormalizeOfficialInviteBlock(rewritten);
        outboundContent = AppendFooter(outboundContent, footerText);
        outboundContent = WhatsAppInviteLinkNormalizer.NormalizeOfficialInviteBlock(outboundContent);
        convertedOfferUrl = ExtractFirstUrl(outboundContent);
        store = TrackingLinkShortenerService.ResolveStoreHint(convertedOfferUrl);
        var fallbackImageResolution = await ResolveImageAsync(content, outboundContent, preferredImageUrl, store, cancellationToken);
        return BuildPreparedContent(outboundContent, fallbackImageResolution);
    }

    private async Task<OfferImageResolutionResult?> ResolveImageAsync(
        string originalContent,
        string outboundContent,
        string? preferredImageUrl,
        string? store,
        CancellationToken cancellationToken)
    {
        if (!string.IsNullOrWhiteSpace(preferredImageUrl))
        {
            return new OfferImageResolutionResult(
                true,
                preferredImageUrl,
                null,
                null,
                "admin_supplied_image",
                null,
                Array.Empty<string>());
        }

        var originalUrl = ExtractFirstUrl(originalContent);
        var convertedUrl = ExtractFirstUrl(outboundContent);
        if (string.IsNullOrWhiteSpace(originalUrl) && string.IsNullOrWhiteSpace(convertedUrl))
        {
            return null;
        }

        var resolution = await _offerImageResolver.ResolveAsync(
            new OfferImageResolutionRequest(
                originalUrl,
                convertedUrl,
                outboundContent,
                store,
                null),
            cancellationToken);
        return resolution;
    }

    private static WhatsAppPreparedContent BuildPreparedContent(
        string content,
        OfferImageResolutionResult? imageResolution)
        => new(
            content,
            imageResolution?.ResolvedImageUrl,
            imageResolution?.ResolvedImageBytes,
            imageResolution?.MimeType,
            imageResolution?.Source,
            imageResolution?.Success ?? false,
            imageResolution?.FailureReason);

    private static string? ExtractFirstUrl(string? text)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            return null;
        }

        var match = UrlRegex().Match(text);
        return match.Success ? match.Value : null;
    }

    [GeneratedRegex(@"https?://[^\s]+", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex UrlRegex();

    private string ResolveOriginSurface(string targetId)
    {
        if (string.IsNullOrWhiteSpace(targetId))
        {
            return "whatsapp_dm";
        }

        if (!targetId.EndsWith("@g.us", StringComparison.OrdinalIgnoreCase))
        {
            return "whatsapp_dm";
        }

        if (IsOfficialDestination(targetId))
        {
            return "whatsapp_grupo_oficial";
        }

        return "whatsapp_grupo";
    }

    private string? ResolveFooterText(AutomationSettings settings, string targetId)
    {
        var routeFooter = settings.WhatsAppForwardingRoutes?
            .FirstOrDefault(route =>
                route.Enabled &&
                route.DestinationGroupIds.Any(id => string.Equals(id?.Trim(), targetId.Trim(), StringComparison.OrdinalIgnoreCase)))
            ?.FooterText;

        if (!string.IsNullOrWhiteSpace(routeFooter))
        {
            return routeFooter.Trim();
        }

        var forwardingFooter = settings.WhatsAppForwarding?.FooterText;
        return string.IsNullOrWhiteSpace(forwardingFooter) ? null : forwardingFooter.Trim();
    }

    private static string AppendFooter(string content, string? footerText)
    {
        if (string.IsNullOrWhiteSpace(footerText))
        {
            return content;
        }

        var baseText = (content ?? string.Empty).TrimEnd();
        if (string.IsNullOrWhiteSpace(baseText))
        {
            return footerText.Trim();
        }

        return $"{baseText}\n\n{footerText.Trim()}";
    }

    private bool IsOfficialDestination(string targetId)
    {
        if (_deliverySafetyOptions.OfficialWhatsAppGroupIds.Any(id => string.Equals(id?.Trim(), targetId.Trim(), StringComparison.OrdinalIgnoreCase)))
        {
            return true;
        }

        var configured = Environment.GetEnvironmentVariable("OFFICIAL_WHATSAPP_GROUP_ID");
        return !string.IsNullOrWhiteSpace(configured) &&
               string.Equals(configured.Trim(), targetId.Trim(), StringComparison.OrdinalIgnoreCase);
    }
}

public sealed record WhatsAppPreparedContent(
    string Content,
    string? ResolvedImageUrl,
    byte[]? ResolvedImageBytes,
    string? ResolvedMimeType,
    string? ImageSource,
    bool HasImageCandidate,
    string? ImageFailureReason);
