using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Domain.Instagram;
using AchadinhosBot.Next.Domain.Models;
using AchadinhosBot.Next.Domain.Settings;
using AchadinhosBot.Next.Infrastructure.Instagram;

namespace AchadinhosBot.Next.Application.Services;

public sealed class ReelAutoPublishService
{
    private readonly IInstagramPublishStore _draftStore;
    private readonly IInstagramPublishService _publishService;
    private readonly ICatalogOfferStore _catalogStore;
    private readonly IWhatsAppGateway _whatsAppGateway;
    private readonly WhatsAppPublishContentService _whatsAppContent;
    private readonly WhatsAppNicheGroupService _nicheGroupService;
    private readonly ISettingsStore _settingsStore;

    public ReelAutoPublishService(
        IInstagramPublishStore draftStore,
        IInstagramPublishService publishService,
        ICatalogOfferStore catalogStore,
        IWhatsAppGateway whatsAppGateway,
        WhatsAppPublishContentService whatsAppContent,
        WhatsAppNicheGroupService nicheGroupService,
        ISettingsStore settingsStore)
    {
        _draftStore = draftStore;
        _publishService = publishService;
        _catalogStore = catalogStore;
        _whatsAppGateway = whatsAppGateway;
        _whatsAppContent = whatsAppContent;
        _nicheGroupService = nicheGroupService;
        _settingsStore = settingsStore;
    }

    public async Task<ReelAutoPublishResult> ApprovePublishAndVerifyAsync(string draftId, CancellationToken ct)
    {
        var draft = await _draftStore.GetAsync(draftId, ct);
        if (draft is null)
        {
            return ReelAutoPublishResult.Missing(draftId);
        }

        draft.Status = "approved";
        draft.Error = null;
        draft.SendToCatalog = true;
        draft.CatalogTarget = CatalogTargets.Prod;
        draft.CatalogIntentLocked = true;
        await _draftStore.UpdateAsync(draft, ct);

        var instagram = await _publishService.ExecutePublishAsync(draft.Id, ct);
        draft = await _draftStore.GetAsync(draft.Id, ct) ?? draft;
        var instagramVerified = instagram.Success &&
            string.Equals(draft.Status, "published", StringComparison.OrdinalIgnoreCase) &&
            !string.IsNullOrWhiteSpace(draft.MediaId);

        var catalogVerified = false;
        var catalogItemsUpdated = 0;
        string? catalogError = null;
        if (instagramVerified)
        {
            try
            {
                var sync = await _catalogStore.SyncExplicitDraftsAsync(new[] { draft }, ct);
                catalogItemsUpdated = sync.Created + sync.Updated;
                var byDraft = await _catalogStore.GetByDraftIdAsync(ct, CatalogTargets.Prod);
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

        var settings = await _settingsStore.GetAsync(ct);
        var generalTarget = settings.WhatsAppForwarding?.DestinationGroupIds
            .FirstOrDefault(id => !string.IsNullOrWhiteSpace(id))
            ?.Trim();
        var generalSuccess = false;
        string? generalError = null;
        if (instagramVerified && !string.IsNullOrWhiteSpace(generalTarget))
        {
            try
            {
                var prepared = await _whatsAppContent.PrepareForSendAsync(
                    ResolveOfferContent(draft),
                    ResolveImageUrl(draft),
                    generalTarget,
                    ct);
                var instance = settings.WhatsAppForwarding?.InstanceName ?? "ZapOfertas";
                var send = await SendPreparedAsync(instance, generalTarget, prepared, ct);
                generalSuccess = send.Success;
                generalError = send.Success ? null : send.Message;
            }
            catch (Exception ex)
            {
                generalError = ex.Message;
            }
        }

        WhatsAppNicheRouteResult? niche = null;
        if (instagramVerified)
        {
            niche = await _nicheGroupService.RouteOfferAsync(
                new WhatsAppNicheRouteOfferRequest(
                    draft.ProductName,
                    FirstNotEmpty(draft.OfferUrl, draft.AutoReplyLink, draft.OriginalOfferUrl),
                    draft.Store,
                    null,
                    draft.CurrentPrice,
                    null,
                    null,
                    null,
                    draft.Id,
                    ResolveImageUrl(draft),
                    ResolveOfferContent(draft),
                    null,
                    true),
                ct);
        }

        return new ReelAutoPublishResult(
            draft.Id,
            draft.ProductName,
            instagramVerified,
            instagram.MediaId,
            instagram.Error,
            catalogVerified,
            catalogItemsUpdated,
            catalogError,
            generalSuccess,
            generalTarget,
            generalError,
            niche?.Success == true,
            niche?.Slug,
            niche?.TargetGroupId,
            niche?.Reason);
    }

    private async Task<WhatsAppSendResult> SendPreparedAsync(
        string? instance,
        string target,
        WhatsAppPreparedContent prepared,
        CancellationToken ct)
    {
        if (prepared.ResolvedImageBytes is { Length: > 0 })
        {
            return await _whatsAppGateway.SendImageAsync(instance, target, prepared.ResolvedImageBytes, prepared.Content, prepared.ResolvedMimeType, ct);
        }

        if (!string.IsNullOrWhiteSpace(prepared.ResolvedImageUrl))
        {
            return await _whatsAppGateway.SendImageUrlAsync(instance, target, prepared.ResolvedImageUrl, prepared.Content, prepared.ResolvedMimeType, "reel-offer.jpg", ct);
        }

        return await _whatsAppGateway.SendTextAsync(instance, target, prepared.Content, ct);
    }

    private static string ResolveOfferContent(InstagramPublishDraft draft)
        => !string.IsNullOrWhiteSpace(draft.AutoReplyMessage)
            ? draft.AutoReplyMessage.Trim()
            : InstagramWorkflowSupport.BuildWhatsAppCaption(
                draft.Caption,
                draft.ProductName,
                FirstNotEmpty(draft.AutoReplyLink, draft.OfferUrl, draft.OriginalOfferUrl),
                draft.CurrentPrice,
                draft.PreviousPrice,
                draft.DiscountPercent);

    private static string? ResolveImageUrl(InstagramPublishDraft draft)
        => draft.ImageUrls.FirstOrDefault(x => !string.IsNullOrWhiteSpace(x))
            ?? draft.SuggestedImageUrls.FirstOrDefault(x => !string.IsNullOrWhiteSpace(x))
            ?? draft.VideoCoverUrl;

    private static string? FirstNotEmpty(params string?[] values)
        => values.FirstOrDefault(x => !string.IsNullOrWhiteSpace(x))?.Trim();
}

public sealed record ReelAutoPublishResult(
    string DraftId,
    string? ProductName,
    bool InstagramPosted,
    string? InstagramMediaId,
    string? InstagramError,
    bool CatalogVerified,
    int CatalogItemsUpdated,
    string? CatalogError,
    bool GeneralWhatsAppPosted,
    string? GeneralWhatsAppTargetId,
    string? GeneralWhatsAppError,
    bool NicheWhatsAppPosted,
    string? NicheSlug,
    string? NicheTargetId,
    string? NicheMessage)
{
    public bool Success => InstagramPosted && CatalogVerified && GeneralWhatsAppPosted && NicheWhatsAppPosted;

    public static ReelAutoPublishResult Missing(string draftId)
        => new(draftId, null, false, null, "Draft not found.", false, 0, "Draft not found.", false, null, "Draft not found.", false, null, null, "Draft not found.");
}
