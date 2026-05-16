using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Domain.Instagram;
using AchadinhosBot.Next.Domain.Models;
using AchadinhosBot.Next.Domain.Settings;

namespace AchadinhosBot.Next.Application.Services;

public sealed class StoryAutoPublishService
{
    private readonly IInstagramPublishStore _draftStore;
    private readonly IInstagramPublishService _publishService;
    private readonly ICatalogOfferStore _catalogStore;
    private readonly IWhatsAppGateway _whatsAppGateway;
    private readonly WhatsAppPublishContentService _whatsAppContent;
    private readonly ISettingsStore _settingsStore;

    public StoryAutoPublishService(
        IInstagramPublishStore draftStore,
        IInstagramPublishService publishService,
        ICatalogOfferStore catalogStore,
        IWhatsAppGateway whatsAppGateway,
        WhatsAppPublishContentService whatsAppContent,
        ISettingsStore settingsStore)
    {
        _draftStore = draftStore;
        _publishService = publishService;
        _catalogStore = catalogStore;
        _whatsAppGateway = whatsAppGateway;
        _whatsAppContent = whatsAppContent;
        _settingsStore = settingsStore;
    }

    public async Task<StoryAutoPublishResult> ApprovePublishAndVerifyAsync(string draftId, CancellationToken cancellationToken)
    {
        var draft = await _draftStore.GetAsync(draftId, cancellationToken);
        if (draft is null)
        {
            return StoryAutoPublishResult.Missing(draftId);
        }

        draft.Status = "approved";
        draft.Error = null;
        await _draftStore.UpdateAsync(draft, cancellationToken);

        var instagram = await _publishService.ExecutePublishAsync(draft.Id, cancellationToken);
        draft = await _draftStore.GetAsync(draft.Id, cancellationToken) ?? draft;
        var instagramVerified = instagram.Success &&
            string.Equals(draft.Status, "published", StringComparison.OrdinalIgnoreCase) &&
            !string.IsNullOrWhiteSpace(draft.MediaId);

        var catalogSynced = false;
        var catalogVerified = false;
        var catalogItemsUpdated = 0;
        string? catalogError = null;
        if (instagramVerified && draft.SendToCatalog)
        {
            try
            {
                var sync = await _catalogStore.SyncExplicitDraftsAsync(new[] { draft }, cancellationToken);
                catalogItemsUpdated = sync.Created + sync.Updated;
                catalogSynced = true;
                var byDraft = await _catalogStore.GetByDraftIdAsync(cancellationToken, CatalogTargets.ResolveDraftTarget(draft));
                catalogVerified = byDraft.TryGetValue(draft.Id, out var item) &&
                    item.Active &&
                    !string.IsNullOrWhiteSpace(item.TrackingUrl) &&
                    !string.IsNullOrWhiteSpace(item.ImageUrl);
            }
            catch (Exception ex)
            {
                catalogError = ex.Message;
            }
        }

        var settings = await _settingsStore.GetAsync(cancellationToken);
        var scout = settings.MercadoLivreAffiliateScout ?? new MercadoLivreAffiliateScoutSettings();
        var whatsappTarget = ResolveWhatsAppTarget(settings, scout);
        var whatsappSuccess = false;
        string? whatsappError = null;
        if (instagramVerified && !string.IsNullOrWhiteSpace(whatsappTarget))
        {
            try
            {
                var rawMessage = BuildWhatsAppStoryOfferMessage(draft);
                var preferredImage = draft.SuggestedImageUrls.FirstOrDefault() ?? draft.ImageUrls.FirstOrDefault();
                var prepared = await _whatsAppContent.PrepareTrustedLinksForSendAsync(
                    rawMessage,
                    preferredImage,
                    whatsappTarget,
                    draft.Store,
                    cancellationToken);
                var instanceName = scout.StoryAutoPublishWhatsAppInstanceName ?? scout.WhatsAppInstanceName ?? "ZapOfertas";
                WhatsAppSendResult send;
                if (prepared.ResolvedImageBytes is { Length: > 0 })
                {
                    send = await _whatsAppGateway.SendImageAsync(instanceName, whatsappTarget, prepared.ResolvedImageBytes, prepared.Content, prepared.ResolvedMimeType, cancellationToken);
                }
                else if (!string.IsNullOrWhiteSpace(prepared.ResolvedImageUrl))
                {
                    send = await _whatsAppGateway.SendImageUrlAsync(instanceName, whatsappTarget, prepared.ResolvedImageUrl, prepared.Content, prepared.ResolvedMimeType, "story-offer.jpg", cancellationToken);
                }
                else
                {
                    send = await _whatsAppGateway.SendTextAsync(instanceName, whatsappTarget, prepared.Content, cancellationToken);
                }

                whatsappSuccess = send.Success;
                whatsappError = send.Success ? null : send.Message;
            }
            catch (Exception ex)
            {
                whatsappError = ex.Message;
            }
        }

        return new StoryAutoPublishResult(
            draft.Id,
            draft.ProductName,
            instagramVerified,
            instagram.MediaId,
            instagram.Error,
            catalogSynced,
            catalogVerified,
            catalogItemsUpdated,
            catalogError,
            whatsappSuccess,
            whatsappTarget,
            whatsappError);
    }

    private static string? ResolveWhatsAppTarget(AutomationSettings settings, MercadoLivreAffiliateScoutSettings scout)
    {
        if (!string.IsNullOrWhiteSpace(scout.StoryAutoPublishWhatsAppTargetId))
        {
            return scout.StoryAutoPublishWhatsAppTargetId.Trim();
        }

        var routeTarget = settings.WhatsAppForwardingRoutes?
            .FirstOrDefault(route => route.Enabled)?
            .DestinationGroupIds
            .FirstOrDefault(id => !string.IsNullOrWhiteSpace(id));
        if (!string.IsNullOrWhiteSpace(routeTarget))
        {
            return routeTarget.Trim();
        }

        return settings.WhatsAppForwarding?.DestinationGroupIds
            .FirstOrDefault(id => !string.IsNullOrWhiteSpace(id))
            ?.Trim();
    }

    private static string BuildWhatsAppStoryOfferMessage(InstagramPublishDraft draft)
    {
        var offerUrl = draft.OfferUrl ?? draft.OriginalOfferUrl ?? draft.Ctas.FirstOrDefault()?.Link ?? string.Empty;
        var lines = new List<string>
        {
            "🔥 *Oferta em destaque*",
            string.Empty,
            $"*{draft.ProductName}*"
        };
        if (!string.IsNullOrWhiteSpace(draft.CurrentPrice))
        {
            lines.Add($"💰 Preço: *{draft.CurrentPrice.Trim()}*");
        }

        lines.Add(string.Empty);
        lines.Add($"🛒 Pegar oferta: {offerUrl}");
        return string.Join(Environment.NewLine, lines);
    }
}

public sealed record StoryAutoPublishResult(
    string DraftId,
    string? ProductName,
    bool InstagramPosted,
    string? InstagramMediaId,
    string? InstagramError,
    bool CatalogSynced,
    bool CatalogVerified,
    int CatalogItemsUpdated,
    string? CatalogError,
    bool WhatsAppPosted,
    string? WhatsAppTargetId,
    string? WhatsAppError)
{
    public bool Success => InstagramPosted && CatalogVerified && WhatsAppPosted;

    public static StoryAutoPublishResult Missing(string draftId)
        => new(draftId, null, false, null, "Draft not found.", false, false, 0, "Draft not found.", false, null, "Draft not found.");
}
