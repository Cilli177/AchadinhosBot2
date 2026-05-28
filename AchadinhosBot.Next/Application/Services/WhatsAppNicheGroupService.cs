using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Configuration;
using AchadinhosBot.Next.Domain.Logs;
using AchadinhosBot.Next.Domain.Models;
using AchadinhosBot.Next.Domain.Offers;
using AchadinhosBot.Next.Domain.Settings;
using Microsoft.Extensions.Options;

namespace AchadinhosBot.Next.Application.Services;

public sealed partial class WhatsAppNicheGroupService
{
    private const int MaxDirectInviteParticipants = 20;
    private static readonly TimeSpan NicheRepeatWindow = TimeSpan.FromDays(3);
    private readonly ISettingsStore _settingsStore;
    private readonly IWhatsAppGateway _whatsAppGateway;
    private readonly IWhatsAppTransport _whatsAppTransport;
    private readonly IWhatsAppOutboundLogStore _whatsAppOutboundLogStore;
    private readonly ILinkTrackingStore _linkTrackingStore;
    private readonly ICatalogOfferStore _catalogOfferStore;
    private readonly IOfferImageResolver _offerImageResolver;
    private readonly IIdempotencyStore _idempotencyStore;
    private readonly IWhatsAppNicheOperationsStore _operationsStore;
    private readonly IClickLogStore _clickLogStore;
    private readonly WebhookOptions _webhookOptions;

    public WhatsAppNicheGroupService(
        ISettingsStore settingsStore,
        IWhatsAppGateway whatsAppGateway,
        IWhatsAppTransport whatsAppTransport,
        IWhatsAppOutboundLogStore whatsAppOutboundLogStore,
        ILinkTrackingStore linkTrackingStore,
        ICatalogOfferStore catalogOfferStore,
        IOfferImageResolver offerImageResolver,
        IIdempotencyStore idempotencyStore,
        IWhatsAppNicheOperationsStore operationsStore,
        IClickLogStore clickLogStore,
        IOptions<WebhookOptions> webhookOptions)
    {
        _settingsStore = settingsStore;
        _whatsAppGateway = whatsAppGateway;
        _whatsAppTransport = whatsAppTransport;
        _whatsAppOutboundLogStore = whatsAppOutboundLogStore;
        _linkTrackingStore = linkTrackingStore;
        _catalogOfferStore = catalogOfferStore;
        _offerImageResolver = offerImageResolver;
        _idempotencyStore = idempotencyStore;
        _operationsStore = operationsStore;
        _clickLogStore = clickLogStore;
        _webhookOptions = webhookOptions.Value;
    }

    public async Task<IReadOnlyList<WhatsAppNicheGroupSettings>> ListAsync(CancellationToken ct)
    {
        var settings = await _settingsStore.GetAsync(ct);
        var changed = EnsureDefaults(settings);
        if (changed)
        {
            await _settingsStore.SaveAsync(settings, ct);
        }

        return settings.WhatsAppNicheGroups
            .OrderBy(x => WhatsAppNicheDefinitions.GetOrder(x.Slug))
            .ToArray();
    }

    public async Task<WhatsAppNicheGroupSettings> UpsertAsync(string slug, WhatsAppNicheGroupUpsertRequest request, CancellationToken ct)
    {
        var normalizedSlug = WhatsAppNicheDefinitions.NormalizeSlug(slug);
        if (!WhatsAppNicheDefinitions.IsKnown(normalizedSlug))
        {
            throw new ArgumentException("Nicho invalido.");
        }

        var settings = await _settingsStore.GetAsync(ct);
        EnsureDefaults(settings);
        var group = settings.WhatsAppNicheGroups.First(x => string.Equals(x.Slug, normalizedSlug, StringComparison.OrdinalIgnoreCase));
        group.DisplayName = FirstNonEmpty(request.DisplayName, group.DisplayName, WhatsAppNicheDefinitions.GetDisplayName(normalizedSlug));
        group.Description = FirstNonEmpty(request.Description, group.Description, WhatsAppNicheDefinitions.GetDescription(normalizedSlug));
        group.Enabled = request.Enabled ?? group.Enabled;
        group.InstanceName = NormalizeOptional(request.InstanceName) ?? group.InstanceName;
        group.GroupId = NormalizeOptional(request.GroupId) ?? group.GroupId;
        group.InviteUrl = NormalizeOptional(request.InviteUrl) ?? group.InviteUrl;
        group.Campaign = NormalizeOptional(request.Campaign) ?? group.Campaign;
        group.DailyLimit = Math.Clamp(request.DailyLimit ?? group.DailyLimit, 0, 10_000);
        group.UpdatedAtUtc = DateTimeOffset.UtcNow;
        await _settingsStore.SaveAsync(settings, ct);
        return group;
    }

    public async Task<WhatsAppNicheGroupCreateSummary> CreateOrRegisterDefaultsAsync(WhatsAppNicheGroupCreateRequest request, CancellationToken ct)
    {
        var settings = await _settingsStore.GetAsync(ct);
        EnsureDefaults(settings);
        var slugs = ResolveRequestedSlugs(request.Slugs);
        var results = new List<WhatsAppNicheGroupCreateResult>();

        foreach (var slug in slugs)
        {
            var group = settings.WhatsAppNicheGroups.First(x => string.Equals(x.Slug, slug, StringComparison.OrdinalIgnoreCase));
            group.InstanceName = NormalizeOptional(request.InstanceName) ?? group.InstanceName;
            group.UpdatedAtUtc = DateTimeOffset.UtcNow;

            if (request.ManualGroups?.TryGetValue(slug, out var manual) == true)
            {
                group.GroupId = NormalizeOptional(manual.GroupId) ?? group.GroupId;
                group.InviteUrl = NormalizeOptional(manual.InviteUrl) ?? group.InviteUrl;
                group.LastCreationStatus = "registered_manual";
                group.LastCreationMessage = "Grupo registrado manualmente.";
                results.Add(new WhatsAppNicheGroupCreateResult(slug, true, group.GroupId, group.InviteUrl, group.LastCreationStatus, group.LastCreationMessage));
                continue;
            }

            if (!string.IsNullOrWhiteSpace(group.GroupId) && request.SkipExisting != false)
            {
                results.Add(new WhatsAppNicheGroupCreateResult(slug, true, group.GroupId, group.InviteUrl, "already_configured", "Grupo ja configurado."));
                continue;
            }

            var createResult = await _whatsAppGateway.CreateGroupAsync(
                group.InstanceName,
                group.DisplayName,
                group.Description,
                request.SeedParticipantJids ?? Array.Empty<string>(),
                ct);

            group.LastCreationStatus = createResult.Success ? "created_api" : "manual_required";
            group.LastCreationMessage = createResult.Message;
            group.GroupId = NormalizeOptional(createResult.GroupId) ?? group.GroupId;
            group.InviteUrl = NormalizeOptional(createResult.InviteUrl) ?? group.InviteUrl;
            group.CreatedAtUtc ??= createResult.Success ? DateTimeOffset.UtcNow : null;

            results.Add(new WhatsAppNicheGroupCreateResult(
                slug,
                createResult.Success,
                group.GroupId,
                group.InviteUrl,
                group.LastCreationStatus,
                group.LastCreationMessage));
        }

        await _settingsStore.SaveAsync(settings, ct);
        return new WhatsAppNicheGroupCreateSummary(results.Count(x => x.Success), results.Count(x => !x.Success), results);
    }

    public async Task<WhatsAppNicheInviteCampaignResult> CreateInviteCampaignAsync(string slug, WhatsAppNicheInviteCampaignRequest request, CancellationToken ct)
    {
        var group = await GetConfiguredGroupAsync(slug, ct);
        if (string.IsNullOrWhiteSpace(group.InviteUrl))
        {
            return new WhatsAppNicheInviteCampaignResult(false, "missing_invite", group.Slug, null, 0, 0, "Configure o inviteUrl oficial do nicho antes da campanha.");
        }

        var trackedUrl = await CreateTrackedUrlAsync(group.InviteUrl, "WhatsApp", $"whatsapp_niche_{group.Slug}_invite", $"invite_niche_{group.Slug}", null, null, ct);
        var message = BuildInviteMessage(group, trackedUrl, request.Message);
        var participants = (request.ParticipantJids ?? Array.Empty<string>())
            .Where(x => !string.IsNullOrWhiteSpace(x))
            .Select(x => x.Trim())
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();

        if (!request.SendNow || participants.Length == 0)
        {
            return new WhatsAppNicheInviteCampaignResult(true, "prepared", group.Slug, trackedUrl, participants.Length, 0, message);
        }

        if (participants.Length > MaxDirectInviteParticipants)
        {
            return new WhatsAppNicheInviteCampaignResult(false, "too_many_participants", group.Slug, trackedUrl, participants.Length, 0, $"Campanha direta limitada a {MaxDirectInviteParticipants} participantes. Use amostra menor ou blast assistido.");
        }

        var sent = 0;
        foreach (var participant in participants)
        {
            var result = await _whatsAppGateway.SendTextAsync(group.InstanceName, participant, message, ct);
            if (result.Success)
            {
                sent++;
            }
        }

        return new WhatsAppNicheInviteCampaignResult(true, "sent", group.Slug, trackedUrl, participants.Length, sent, message);
    }

    public async Task<WhatsAppNicheRouteResult> RouteOfferAsync(WhatsAppNicheRouteOfferRequest request, CancellationToken ct)
    {
        var offer = await ResolveRouteOfferAsync(request, ct);
        var settings = await _settingsStore.GetAsync(ct);
        EnsureDefaults(settings);
        var explicitRequestSlug = WhatsAppNicheDefinitions.NormalizeSlug(request.Category);
        var hasExplicitRequestSlug = WhatsAppNicheDefinitions.IsKnown(explicitRequestSlug)
            && !string.Equals(explicitRequestSlug, WhatsAppNicheDefinitions.Geral, StringComparison.OrdinalIgnoreCase);
        var overrideDecision = hasExplicitRequestSlug ? null : ResolveOverride(settings, offer);
        var decision = overrideDecision ?? WhatsAppNicheClassifier.Classify(offer);
        if (decision.RequiresReview)
        {
            await _operationsStore.SaveReviewAsync(new WhatsAppNicheReviewItem
            {
                Reason = decision.Reason,
                Confidence = decision.Confidence,
                SuggestedSlug = decision.Slug,
                ProductName = offer.ProductName,
                ProductUrl = offer.ProductUrl,
                StoreName = offer.StoreName,
                PriceText = offer.PriceText,
                ImageUrl = offer.ImageUrl,
                OriginalText = request.OriginalText
            }, ct);
            await AppendRouteEventAsync(request, offer, new(false, "review_required", decision.Slug, decision.Reason, decision.Confidence, null, null, null), null, ct);
            return new WhatsAppNicheRouteResult(false, "review_required", decision.Slug, decision.Reason, decision.Confidence, null, null, null);
        }

        var group = settings.WhatsAppNicheGroups.FirstOrDefault(x => string.Equals(x.Slug, decision.Slug, StringComparison.OrdinalIgnoreCase));
        if (group is null || !group.Enabled || string.IsNullOrWhiteSpace(group.GroupId))
        {
            await AppendRouteEventAsync(request, offer, new(false, "missing_group", decision.Slug, "Nicho classificado, mas sem grupo WhatsApp ativo configurado.", decision.Confidence, null, null, null), null, ct);
            return new WhatsAppNicheRouteResult(false, "missing_group", decision.Slug, "Nicho classificado, mas sem grupo WhatsApp ativo configurado.", decision.Confidence, null, null, null);
        }

        var offerUrl = FirstNonEmpty(offer.ProductUrl, request.ProductUrl);
        if (string.IsNullOrWhiteSpace(offerUrl))
        {
            await AppendRouteEventAsync(request, offer, new(false, "missing_url", decision.Slug, "Oferta sem URL roteavel.", decision.Confidence, null, group.GroupId, null), null, ct);
            return new WhatsAppNicheRouteResult(false, "missing_url", decision.Slug, "Oferta sem URL roteavel.", decision.Confidence, null, group.GroupId, null);
        }

        var repeatDedupeKey = BuildRepeatDedupeKey(group.Slug, offer);
        if (request.SendNow &&
            (await WasRecentlySentToGroupAsync(group, offer, ct) ||
             !_idempotencyStore.TryBegin(repeatDedupeKey, NicheRepeatWindow)))
        {
            var duplicate = new WhatsAppNicheRouteResult(
                false,
                "duplicate_recent",
                group.Slug,
                $"Mesmo produto ja enviado para {group.DisplayName} nas ultimas {NicheRepeatWindow.TotalDays:0} dias.",
                decision.Confidence,
                null,
                group.GroupId,
                null);
            await AppendRouteEventAsync(request, offer, duplicate, null, ct);
            return duplicate;
        }

        var campaign = NormalizeOptional(request.Campaign) ?? group.Campaign;
        var trackedUrl = await CreateTrackedUrlAsync(
            offerUrl,
            offer.StoreName,
            $"whatsapp_niche_{group.Slug}",
            campaign,
            request.OfferId,
            request.DraftId,
            ct);

        var message = BuildOfferMessage(offer, trackedUrl, group.Slug, request.OriginalText, offerUrl);
        var image = await ResolveOfferImageAsync(offer, request, offerUrl, trackedUrl, ct);
        var trackedId = ExtractTrackingIdFromRedirectUrl(trackedUrl);
        if (request.SendNow && TrackingIdDecorator.IsBlockedOfferTrackingId(trackedId))
        {
            _idempotencyStore.RemoveByPrefix(repeatDedupeKey);
            await SaveGuardReviewAsync(offer, request, group.Slug, "blocked_unapproved_tracking", decision.Confidence, ct);
            var blocked = new WhatsAppNicheRouteResult(false, "blocked_unapproved_tracking", group.Slug, "Tracking nao aprovado para envio automatico em nichos.", decision.Confidence, trackedUrl, group.GroupId, message);
            await AppendRouteEventAsync(request, offer, blocked, image, ct);
            return blocked;
        }

        if (request.SendNow && image is null && !IsCouponCampaignOffer(offer, request.OriginalText))
        {
            _idempotencyStore.RemoveByPrefix(repeatDedupeKey);
            await SaveGuardReviewAsync(offer, request, group.Slug, "missing_image_for_niche_send", decision.Confidence, ct);
            var missingImage = new WhatsAppNicheRouteResult(false, "review_required", group.Slug, "Oferta sem imagem confiavel para envio automatico em nichos.", decision.Confidence, trackedUrl, group.GroupId, message);
            await AppendRouteEventAsync(request, offer, missingImage, null, ct);
            return missingImage;
        }
        if (request.SendNow)
        {
            if (!TryReserveDailySlot(group, DateTimeOffset.UtcNow, out var quotaMessage))
            {
                var quota = new WhatsAppNicheRouteResult(false, "daily_limit_reached", group.Slug, quotaMessage, decision.Confidence, trackedUrl, group.GroupId, null);
                await AppendRouteEventAsync(request, offer, quota, image, ct);
                return quota;
            }

            var send = await SendOfferAsync(group, message, image, ct);
            if (!send.Success)
            {
                _idempotencyStore.RemoveByPrefix(repeatDedupeKey);
                var failed = new WhatsAppNicheRouteResult(false, "send_failed", group.Slug, send.Message ?? "Falha ao enviar.", decision.Confidence, trackedUrl, group.GroupId, message);
                await AppendRouteEventAsync(request, offer, failed, image, ct);
                return failed;
            }

            await _settingsStore.SaveAsync(settings, ct);
            var sent = new WhatsAppNicheRouteResult(true, "sent", group.Slug, decision.Reason, decision.Confidence, trackedUrl, group.GroupId, message);
            await AppendRouteEventAsync(request, offer, sent, image, ct);
            return sent;
        }

        var prepared = new WhatsAppNicheRouteResult(true, "prepared", group.Slug, decision.Reason, decision.Confidence, trackedUrl, group.GroupId, message);
        await AppendRouteEventAsync(request, offer, prepared, image, ct);
        return prepared;
    }

    public async Task<IReadOnlyList<WhatsAppNicheRouteResult>> RouteOfferWithOverridesAsync(WhatsAppNicheRouteOfferRequest request, CancellationToken ct)
    {
        var offer = await ResolveRouteOfferAsync(request, ct);
        var settings = await _settingsStore.GetAsync(ct);
        EnsureDefaults(settings);
        var overrideItem = ResolveOverrideItem(settings, offer);
        if (overrideItem is null || overrideItem.TargetSlugs.Count <= 1)
        {
            var hybridSlugs = ResolveHybridTargetSlugs(offer);
            if (hybridSlugs.Count > 1)
            {
                return await RouteOfferToSlugsAsync(request, hybridSlugs, ct);
            }

            return [await RouteOfferAsync(request, ct)];
        }

        return await RouteOfferToSlugsAsync(request, overrideItem.TargetSlugs, ct);
    }

    private async Task<IReadOnlyList<WhatsAppNicheRouteResult>> RouteOfferToSlugsAsync(
        WhatsAppNicheRouteOfferRequest request,
        IReadOnlyList<string> slugs,
        CancellationToken ct)
    {
        var results = new List<WhatsAppNicheRouteResult>();
        foreach (var slug in slugs)
        {
            var forced = request with
            {
                Category = slug,
                Campaign = NormalizeOptional(request.Campaign) ?? $"niche_live_{slug}"
            };
            results.Add(await RouteOfferAsync(forced, ct));
        }

        return results;
    }

    private static IReadOnlyList<string> ResolveHybridTargetSlugs(WhatsAppNicheRouteOfferInput offer)
        => WhatsAppNicheClassifier.ResolveHybridTargetSlugs(offer);

    public Task<IReadOnlyList<WhatsAppNicheRouteEvent>> ListRouteEventsAsync(int limit, CancellationToken ct)
        => _operationsStore.ListRouteEventsAsync(limit, ct);

    public Task<IReadOnlyList<WhatsAppNicheReviewItem>> ListReviewsAsync(string? status, int limit, CancellationToken ct)
        => _operationsStore.ListReviewsAsync(status, limit, ct);

    public async Task<IReadOnlyList<WhatsAppNicheRouteResult>?> ApproveReviewAsync(string id, IReadOnlyList<string> slugs, CancellationToken ct)
    {
        var review = await _operationsStore.GetReviewAsync(id, ct);
        if (review is null) return null;
        var normalizedSlugs = slugs
            .Select(WhatsAppNicheDefinitions.NormalizeSlug)
            .Where(WhatsAppNicheDefinitions.IsKnown)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
        if (normalizedSlugs.Count == 0) return [];
        review.Status = "approved";
        review.DecidedAtUtc = DateTimeOffset.UtcNow;
        review.DecidedSlug = normalizedSlugs[0];
        review.DecidedSlugs = normalizedSlugs;
        await _operationsStore.UpdateReviewAsync(review, ct);

        var results = new List<WhatsAppNicheRouteResult>();
        foreach (var slug in normalizedSlugs)
        {
            var productUrl = ExtractBestOfferUrl(review.OriginalText) ?? review.ProductUrl;
            results.Add(await RouteOfferAsync(new(review.ProductName, productUrl, review.StoreName, slug, review.PriceText, null, null, null, null, review.ImageUrl, review.OriginalText, $"niche_live_{slug}", true), ct));
        }

        return results;
    }

    public async Task<IReadOnlyList<WhatsAppNicheRouteResult>> ApproveReviewsAsync(IReadOnlyList<string> ids, IReadOnlyList<string> slugs, CancellationToken ct)
    {
        var results = new List<WhatsAppNicheRouteResult>();
        foreach (var id in ids.Where(x => !string.IsNullOrWhiteSpace(x)).Distinct(StringComparer.OrdinalIgnoreCase))
        {
            var itemResults = await ApproveReviewAsync(id, slugs, ct);
            if (itemResults is not null)
            {
                results.AddRange(itemResults);
            }
        }

        return results;
    }

    public async Task<bool> RejectReviewAsync(string id, string? note, CancellationToken ct)
    {
        var review = await _operationsStore.GetReviewAsync(id, ct);
        if (review is null) return false;
        review.Status = "rejected";
        review.DecidedAtUtc = DateTimeOffset.UtcNow;
        review.DecisionNote = NormalizeOptional(note);
        await _operationsStore.UpdateReviewAsync(review, ct);
        return true;
    }

    public async Task<IReadOnlyList<WhatsAppNicheOverrideSettings>> ListOverridesAsync(CancellationToken ct)
        => (await _settingsStore.GetAsync(ct)).WhatsAppNicheOverrides;

    public async Task<WhatsAppNicheOverrideSettings> UpsertOverrideAsync(WhatsAppNicheOverrideUpsertRequest request, CancellationToken ct)
    {
        var settings = await _settingsStore.GetAsync(ct);
        var item = string.IsNullOrWhiteSpace(request.Id) ? null : settings.WhatsAppNicheOverrides.FirstOrDefault(x => x.Id == request.Id);
        item ??= new WhatsAppNicheOverrideSettings();
        item.MatchText = request.MatchText.Trim();
        item.Mode = request.Mode.Trim().ToLowerInvariant();
        item.Enabled = request.Enabled;
        item.TargetSlugs = request.TargetSlugs.Select(WhatsAppNicheDefinitions.NormalizeSlug).Where(WhatsAppNicheDefinitions.IsKnown).Distinct().ToList();
        if (!settings.WhatsAppNicheOverrides.Any(x => x.Id == item.Id)) settings.WhatsAppNicheOverrides.Add(item);
        await _settingsStore.SaveAsync(settings, ct);
        return item;
    }

    public async Task<bool> DeleteOverrideAsync(string id, CancellationToken ct)
    {
        var settings = await _settingsStore.GetAsync(ct);
        var removed = settings.WhatsAppNicheOverrides.RemoveAll(x => x.Id == id) > 0;
        if (removed) await _settingsStore.SaveAsync(settings, ct);
        return removed;
    }

    public async Task<WhatsAppNicheMetricsReport> GetMetricsAsync(CancellationToken ct)
    {
        var events = await _operationsStore.ListRouteEventsAsync(5000, ct);
        var since = DateTimeOffset.UtcNow.AddDays(-1);
        var clicks = await _clickLogStore.QueryAsync(null, null, 5000, ct);
        var settings = await _settingsStore.GetAsync(ct);
        EnsureDefaults(settings);
        var grouped = events.Where(x => x.Timestamp >= since)
            .GroupBy(x => x.Slug, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(x => x.Key, x => x.ToArray(), StringComparer.OrdinalIgnoreCase);
        var slugs = settings.WhatsAppNicheGroups
            .Where(x => x.Enabled)
            .Select(x => x.Slug)
            .Concat(grouped.Keys)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(WhatsAppNicheDefinitions.GetOrder)
            .ToArray();
        var groups = slugs.Select(slug =>
        {
            var rows = grouped.TryGetValue(slug, out var entries) ? entries : Array.Empty<WhatsAppNicheRouteEvent>();
            var sentRows = rows.Where(x => x.Status == "sent").ToArray();
            var trackedIds = sentRows.Select(x => x.TrackingId).Where(x => !string.IsNullOrWhiteSpace(x)).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
            var slugClicks = clicks.Where(x =>
                x.Timestamp >= since &&
                trackedIds.Contains(x.TrackingId, StringComparer.OrdinalIgnoreCase)).ToArray();
            return new WhatsAppNicheMetricRow(
                slug,
                sentRows.Length,
                rows.Count(x => x.Status == "duplicate_recent"),
                rows.Count(x => x.Status == "review_required"),
                slugClicks.Length,
                sentRows.Length == 0 ? 0 : Math.Round((decimal)slugClicks.Length / sentRows.Length, 2),
                trackedIds.Length);
        }).ToArray();
        var topProducts = events
            .Where(x => x.Timestamp >= since && x.Status == "sent" && !string.IsNullOrWhiteSpace(x.TrackingId))
            .Select(x => new
            {
                Event = x,
                Clicks = clicks.Count(c => c.Timestamp >= since && string.Equals(c.TrackingId, x.TrackingId, StringComparison.OrdinalIgnoreCase))
            })
            .Where(x => x.Clicks > 0)
            .OrderByDescending(x => x.Clicks)
            .ThenByDescending(x => x.Event.Timestamp)
            .Take(5)
            .Select(x => new WhatsAppNicheTopProduct(x.Event.Slug, x.Event.ProductName, x.Event.TrackingId, x.Clicks))
            .ToArray();
        var alerts = BuildAlerts(groups, events);
        return new(groups, topProducts, alerts, BuildDailySummary(groups, topProducts, alerts));
    }

    private async Task<WhatsAppNicheGroupSettings> GetConfiguredGroupAsync(string slug, CancellationToken ct)
    {
        var settings = await _settingsStore.GetAsync(ct);
        EnsureDefaults(settings);
        var normalized = WhatsAppNicheDefinitions.NormalizeSlug(slug);
        var group = settings.WhatsAppNicheGroups.FirstOrDefault(x => string.Equals(x.Slug, normalized, StringComparison.OrdinalIgnoreCase));
        if (group is null)
        {
            throw new ArgumentException("Nicho invalido.");
        }

        return group;
    }

    private async Task<WhatsAppNicheRouteOfferInput> ResolveRouteOfferAsync(WhatsAppNicheRouteOfferRequest request, CancellationToken ct)
    {
        if (!string.IsNullOrWhiteSpace(request.CatalogItemIdOrKeyword))
        {
            var catalog = await _catalogOfferStore.FindByCodeAsync(request.CatalogItemIdOrKeyword, ct);
            if (catalog is not null)
            {
                return new WhatsAppNicheRouteOfferInput(
                    catalog.ProductName,
                    FirstNonEmpty(catalog.AffiliateTargetUrl, catalog.OfferUrl, catalog.OriginalProductUrl),
                    catalog.Store,
                    catalog.Niche,
                    catalog.PriceText,
                    request.CommissionRaw,
                    catalog.ImageUrl,
                    catalog.DraftId);
            }
        }

        return new WhatsAppNicheRouteOfferInput(
            request.ProductName,
            request.ProductUrl,
            request.StoreName,
            request.Category,
            request.PriceText,
            request.CommissionRaw,
            request.ImageUrl,
            request.DraftId);
    }

    private async Task<string> CreateTrackedUrlAsync(string targetUrl, string? store, string originSurface, string campaign, string? offerId, string? draftId, CancellationToken ct)
    {
        var baseUrl = NormalizePublicBaseUrl(_webhookOptions.PublicBaseUrl);
        var targetTrackingId = ExtractTrackingIdFromRedirectUrl(targetUrl);
        var resolvedOfferId = TrackingIdDecorator.Resolve(FirstNonEmpty(offerId, targetTrackingId) ?? string.Empty).LookupId;
        if (IsCanonicalOfferTrackingId(resolvedOfferId) && await _linkTrackingStore.GetLinkAsync(resolvedOfferId, ct) is not null)
        {
            return $"{baseUrl}/r/{Uri.EscapeDataString(TrackingIdDecorator.Decorate(resolvedOfferId, campaign))}";
        }

        var tracking = await _linkTrackingStore.CreateAsync(new LinkTrackingCreateRequest
        {
            TargetUrl = targetUrl,
            Store = store,
            OriginChannel = "whatsapp",
            OriginSurface = originSurface,
            Campaign = campaign,
            OfferId = offerId,
            DraftId = draftId,
            ExpiresAtUtc = DateTimeOffset.UtcNow.AddDays(14)
        }, ct);

        var trackingId = string.IsNullOrWhiteSpace(tracking.Slug) ? tracking.Id : tracking.Slug;
        return $"{baseUrl}/r/{Uri.EscapeDataString(TrackingIdDecorator.Decorate(trackingId, campaign))}";
    }

    private static bool IsCanonicalOfferTrackingId(string? offerId)
        => !string.IsNullOrWhiteSpace(offerId)
           && (offerId.StartsWith("ML-", StringComparison.OrdinalIgnoreCase)
               || offerId.StartsWith("SP-", StringComparison.OrdinalIgnoreCase)
               || offerId.StartsWith("AM-", StringComparison.OrdinalIgnoreCase)
               || offerId.StartsWith("SHE-", StringComparison.OrdinalIgnoreCase));

    private static string BuildRepeatDedupeKey(string slug, WhatsAppNicheRouteOfferInput offer)
    {
        var identity = FirstNonEmpty(
            ExtractMarketplaceProductIdentity(offer.ProductUrl),
            BuildNormalizedProductIdentity(offer.StoreName, offer.ProductName));
        var hash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(identity))).ToLowerInvariant();
        return $"wa-niche-repeat:{slug}:{hash}";
    }

    private async Task<bool> WasRecentlySentToGroupAsync(
        WhatsAppNicheGroupSettings group,
        WhatsAppNicheRouteOfferInput offer,
        CancellationToken ct)
    {
        var identity = BuildProductIdentity(offer);
        if (string.IsNullOrWhiteSpace(identity))
        {
            return false;
        }

        var cutoff = DateTimeOffset.UtcNow - NicheRepeatWindow;
        var routeEvents = await _operationsStore.ListRouteEventsAsync(2000, ct);
        if (routeEvents.Any(entry =>
            entry.Timestamp >= cutoff &&
            string.Equals(entry.Slug, group.Slug, StringComparison.OrdinalIgnoreCase) &&
            string.Equals(entry.Status, "sent", StringComparison.OrdinalIgnoreCase) &&
            string.Equals(entry.ProductIdentity, identity, StringComparison.OrdinalIgnoreCase)))
        {
            return true;
        }

        return false;
    }

    private static string BuildNormalizedProductIdentity(string? store, string? title)
        => $"{NormalizeIdentityToken(store)}|{NormalizeIdentityToken(title)}";

    private static string BuildProductIdentity(WhatsAppNicheRouteOfferInput offer)
        => FirstNonEmpty(
            ExtractMarketplaceProductIdentity(offer.ProductUrl),
            BuildNormalizedProductIdentity(offer.StoreName, offer.ProductName));

    private static string? ExtractMarketplaceProductIdentity(string? url)
    {
        if (string.IsNullOrWhiteSpace(url))
        {
            return null;
        }

        var decoded = Uri.UnescapeDataString(url);
        var mlMatch = MercadoLivreProductRegex().Match(decoded);
        if (mlMatch.Success)
        {
            var mlProductId = FirstNonEmpty(mlMatch.Groups[1].Value, mlMatch.Groups[2].Value);
            return $"ml:{mlProductId.ToUpperInvariant()}";
        }

        var amazonMatch = AmazonProductRegex().Match(decoded);
        if (amazonMatch.Success)
        {
            return $"am:{amazonMatch.Groups[1].Value.ToUpperInvariant()}";
        }

        var shopeeMatch = ShopeeProductRegex().Match(decoded);
        if (shopeeMatch.Success)
        {
            return $"sp:{shopeeMatch.Groups[1].Value}";
        }

        return null;
    }

    private static string NormalizeIdentityToken(string? value)
        => Regex.Replace(
            RemoveDiacritics(value ?? string.Empty).ToLowerInvariant(),
            @"[^a-z0-9]+",
            " ",
            RegexOptions.CultureInvariant).Trim();

    private static string RemoveDiacritics(string value)
    {
        value = new string(value.Where(ch => !char.IsSurrogate(ch)).ToArray());
        var normalized = value.Normalize(NormalizationForm.FormD);
        return new string(normalized
            .Where(ch => CharUnicodeInfo.GetUnicodeCategory(ch) != UnicodeCategory.NonSpacingMark)
            .ToArray());
    }

    private static bool EnsureDefaults(AutomationSettings settings)
    {
        var changed = false;
        settings.WhatsAppNicheGroups ??= new List<WhatsAppNicheGroupSettings>();
        foreach (var definition in WhatsAppNicheDefinitions.All)
        {
            var existing = settings.WhatsAppNicheGroups.FirstOrDefault(x => string.Equals(x.Slug, definition.Slug, StringComparison.OrdinalIgnoreCase));
            if (existing is null)
            {
                settings.WhatsAppNicheGroups.Add(new WhatsAppNicheGroupSettings
                {
                    Slug = definition.Slug,
                    DisplayName = definition.DisplayName,
                    Description = definition.Description,
                    Campaign = $"niche_{definition.Slug}",
                    DailyLimit = definition.DailyLimit,
                    UpdatedAtUtc = DateTimeOffset.UtcNow
                });
                changed = true;
                continue;
            }

            existing.Slug = definition.Slug;
            existing.DisplayName = FirstNonEmpty(existing.DisplayName, definition.DisplayName);
            existing.Description = FirstNonEmpty(existing.Description, definition.Description);
            existing.Campaign = FirstNonEmpty(existing.Campaign, $"niche_{definition.Slug}");
            existing.DailyLimit = existing.DailyLimit < 0 ? definition.DailyLimit : existing.DailyLimit;
        }

        return changed;
    }

    private static bool TryReserveDailySlot(WhatsAppNicheGroupSettings group, DateTimeOffset now, out string message)
    {
        var quotaDate = group.SentQuotaDateUtc?.UtcDateTime.Date;
        if (quotaDate != now.UtcDateTime.Date)
        {
            group.SentQuotaDateUtc = now;
            group.SentToday = 0;
        }

        if (group.DailyLimit == 0)
        {
            group.SentToday++;
            group.UpdatedAtUtc = now;
            message = "ok";
            return true;
        }

        if (group.SentToday >= group.DailyLimit)
        {
            message = $"Limite diario do nicho {group.Slug} atingido ({group.DailyLimit}).";
            return false;
        }

        group.SentToday++;
        group.UpdatedAtUtc = now;
        message = "ok";
        return true;
    }

    private async Task<OfferImageResolutionResult?> ResolveOfferImageAsync(
        WhatsAppNicheRouteOfferInput offer,
        WhatsAppNicheRouteOfferRequest request,
        string offerUrl,
        string trackedUrl,
        CancellationToken ct)
    {
        try
        {
            var resolvedOfferUrl = await ResolveTrackingTargetUrlAsync(offerUrl, ct);
            var result = await _offerImageResolver.ResolveAsync(
                new OfferImageResolutionRequest(
                    resolvedOfferUrl,
                    trackedUrl,
                    BuildImageContextText(offer, trackedUrl),
                    offer.StoreName,
                    FirstNonEmpty(request.ImageUrl, offer.ImageUrl)),
                ct);

            return result.Success ? result : null;
        }
        catch
        {
            return null;
        }
    }

    private async Task<string> ResolveTrackingTargetUrlAsync(string offerUrl, CancellationToken ct)
    {
        var trackingId = ExtractTrackingIdFromRedirectUrl(offerUrl);
        if (string.IsNullOrWhiteSpace(trackingId))
        {
            return offerUrl;
        }

        var resolved = TrackingIdDecorator.Resolve(trackingId).LookupId;
        var tracking = await _linkTrackingStore.GetLinkAsync(resolved, ct);
        return string.IsNullOrWhiteSpace(tracking?.TargetUrl) ? offerUrl : tracking.TargetUrl;
    }

    private async Task SaveGuardReviewAsync(
        WhatsAppNicheRouteOfferInput offer,
        WhatsAppNicheRouteOfferRequest request,
        string slug,
        string reason,
        int confidence,
        CancellationToken ct)
    {
        await _operationsStore.SaveReviewAsync(new WhatsAppNicheReviewItem
        {
            Reason = reason,
            Confidence = confidence,
            SuggestedSlug = slug,
            ProductName = offer.ProductName,
            ProductUrl = offer.ProductUrl,
            StoreName = offer.StoreName,
            PriceText = offer.PriceText,
            ImageUrl = offer.ImageUrl,
            OriginalText = request.OriginalText
        }, ct);
    }

    private static string? ExtractTrackingIdFromRedirectUrl(string? url)
    {
        if (string.IsNullOrWhiteSpace(url))
        {
            return null;
        }

        var marker = "/r/";
        var index = url.IndexOf(marker, StringComparison.OrdinalIgnoreCase);
        if (index < 0)
        {
            return null;
        }

        var id = url[(index + marker.Length)..];
        var separator = id.IndexOfAny(['?', '#', '&']);
        if (separator >= 0)
        {
            id = id[..separator];
        }

        return Uri.UnescapeDataString(id);
    }

    private async Task<WhatsAppSendResult> SendOfferAsync(
        WhatsAppNicheGroupSettings group,
        string message,
        OfferImageResolutionResult? image,
        CancellationToken ct)
    {
        var messageId = Guid.NewGuid().ToString("N");
        WhatsAppSendResult result;
        string kind;
        string? mediaUrl = null;
        string? mimeType = image?.MimeType;
        string? fileName = null;

        if (image?.ResolvedImageBytes is { Length: > 0 })
        {
            kind = "image-bytes";
            result = await _whatsAppTransport.SendImageAsync(
                group.InstanceName,
                group.GroupId!,
                image.ResolvedImageBytes,
                message,
                image.MimeType,
                ct);
        }
        else if (!string.IsNullOrWhiteSpace(image?.ResolvedImageUrl))
        {
            kind = "image-url";
            mediaUrl = image.ResolvedImageUrl;
            fileName = "oferta.jpg";
            result = await _whatsAppTransport.SendImageUrlAsync(
                group.InstanceName,
                group.GroupId!,
                image.ResolvedImageUrl,
                message,
                image.MimeType,
                "oferta.jpg",
                ct);
        }
        else
        {
            kind = "text";
            result = await _whatsAppTransport.SendTextAsync(group.InstanceName, group.GroupId!, message, ct);
        }

        if (result.Success)
        {
            await _whatsAppOutboundLogStore.AppendAsync(new WhatsAppOutboundLogEntry
            {
                MessageId = messageId,
                CreatedAtUtc = DateTimeOffset.UtcNow,
                Kind = kind,
                InstanceName = group.InstanceName,
                To = group.GroupId!,
                Text = message,
                MediaUrl = mediaUrl,
                MimeType = mimeType,
                FileName = fileName
            }, ct);
        }

        return result;
    }

    private static string BuildImageContextText(WhatsAppNicheRouteOfferInput offer, string trackedUrl)
        => string.Join("\n", new[]
        {
            offer.ProductName,
            offer.PriceText,
            offer.StoreName,
            offer.Category,
            trackedUrl
        }.Where(x => !string.IsNullOrWhiteSpace(x)));

    private static string BuildOfferMessage(
        WhatsAppNicheRouteOfferInput offer,
        string trackedUrl,
        string slug,
        string? originalText,
        string? originalUrl)
    {
        var reused = TryBuildFromOriginalText(originalText, trackedUrl, originalUrl, slug);
        if (!string.IsNullOrWhiteSpace(reused))
        {
            return reused;
        }

        return BuildGeneratedOfferMessage(offer, trackedUrl, slug);
    }

    private static string? TryBuildFromOriginalText(string? originalText, string trackedUrl, string? originalUrl, string slug)
    {
        if (string.IsNullOrWhiteSpace(originalText))
        {
            return null;
        }

        var text = originalText.Trim();
        if (!UrlRegex().IsMatch(text))
        {
            return AddEmotionalFooter(text, trackedUrl);
        }

        var replaced = ReplaceOfferCtaUrl(text, trackedUrl);

        if (!replaced.Contains(trackedUrl, StringComparison.OrdinalIgnoreCase)
            && !string.IsNullOrWhiteSpace(originalUrl)
            && !LooksLikeBioOrHubUrl(originalUrl))
        {
            replaced = replaced.Replace(originalUrl.Trim(), trackedUrl, StringComparison.OrdinalIgnoreCase);
        }

        if (!replaced.Contains(trackedUrl, StringComparison.OrdinalIgnoreCase))
        {
            var preferred = UrlRegex().Matches(replaced)
                .Select(match => match.Value.Trim())
                .Where(url => (IsAllowedOfferTrackingUrl(url) || LooksLikeStoreUrl(url)) && !LooksLikeBioOrHubUrl(url))
                .ToArray();

            if (preferred.Length > 0)
            {
                replaced = ReplaceLast(replaced, preferred[^1], trackedUrl);
            }
        }

        if (!replaced.Contains(trackedUrl, StringComparison.OrdinalIgnoreCase))
        {
            replaced = AddEmotionalFooter(replaced, trackedUrl);
        }

        replaced = DecorateRemainingOfferTrackingUrls(replaced, slug, trackedUrl);
        return NormalizeNicheCaption(replaced);
    }

    private static string DecorateRemainingOfferTrackingUrls(string text, string slug, string primaryTrackedUrl)
    {
        var campaign = $"niche_live_{slug}";
        var result = text;
        var urls = UrlRegex().Matches(text)
            .Cast<Match>()
            .Select(match => NormalizeCapturedUrl(match.Value))
            .Where(url => !string.IsNullOrWhiteSpace(url))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();

        foreach (var url in urls)
        {
            if (url.Equals(primaryTrackedUrl, StringComparison.OrdinalIgnoreCase) || LooksLikeBioOrHubUrl(url))
            {
                continue;
            }

            var trackingId = ExtractTrackingIdFromRedirectUrl(url);
            if (string.IsNullOrWhiteSpace(trackingId)
                || !TrackingIdDecorator.IsAllowedOfferTrackingId(trackingId)
                || TrackingIdDecorator.IsBlockedOfferTrackingId(trackingId))
            {
                continue;
            }

            var lookupId = TrackingIdDecorator.Resolve(trackingId).LookupId;
            var decoratedId = TrackingIdDecorator.Decorate(lookupId, campaign);
            if (string.Equals(trackingId, decoratedId, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            result = result.Replace(url, ReplaceTrackingIdInUrl(url, decoratedId), StringComparison.OrdinalIgnoreCase);
        }

        return result;
    }

    private static string ReplaceTrackingIdInUrl(string url, string trackingId)
    {
        var marker = "/r/";
        var index = url.IndexOf(marker, StringComparison.OrdinalIgnoreCase);
        if (index < 0)
        {
            return url;
        }

        var start = index + marker.Length;
        var end = url.IndexOfAny(['?', '#', '&'], start);
        if (end < 0)
        {
            end = url.Length;
        }

        return string.Concat(url.AsSpan(0, start), Uri.EscapeDataString(trackingId), url.AsSpan(end));
    }

    private static string AddEmotionalFooter(string text, string trackedUrl)
        => $"{text.TrimEnd()}\n\n🔥 Corre aqui antes que suma:\n{trackedUrl}";

    private static string ReplaceOfferCtaUrl(string text, string trackedUrl)
    {
        if (LooksLikeCouponCampaignText(text))
        {
            var couponUrl = UrlRegex().Matches(text)
                .Cast<Match>()
                .Select(match => NormalizeCapturedUrl(match.Value))
                .FirstOrDefault(IsAllowedOfferTrackingUrl);
            if (!string.IsNullOrWhiteSpace(couponUrl))
            {
                return ReplaceLast(text, couponUrl, trackedUrl);
            }
        }

        var multiline = ExtractUrlAfterCtaLine(text);
        if (!string.IsNullOrWhiteSpace(multiline))
        {
            return ReplaceLast(text, multiline, trackedUrl);
        }

        var matches = OfferCtaUrlRegex().Matches(text);
        foreach (Match match in matches)
        {
            var url = match.Groups["url"].Value.Trim();
            if (LooksLikeBioOrHubUrl(url) || LooksLikeCouponUrl(url, text))
            {
                continue;
            }

            return ReplaceLast(text, url, trackedUrl);
        }

        return text;
    }

    private static string? ExtractBestOfferUrl(string? text)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            return null;
        }

        var multiline = ExtractUrlAfterCtaLine(text);
        if (!string.IsNullOrWhiteSpace(multiline))
        {
            return multiline;
        }

        var cta = OfferCtaUrlRegex().Matches(text)
            .Cast<Match>()
            .Select(match => NormalizeCapturedUrl(match.Groups["url"].Value))
            .FirstOrDefault(url => !LooksLikeBioOrHubUrl(url) && !LooksLikeCouponUrl(url, text));
        if (!string.IsNullOrWhiteSpace(cta))
        {
            return cta;
        }

        var matches = UrlRegex().Matches(text);
        var urls = matches
            .Cast<Match>()
            .Select(match => NormalizeCapturedUrl(match.Value))
            .Where(url => !LooksLikeBioOrHubUrl(url))
            .ToArray();

        if (LooksLikeCouponCampaignText(text))
        {
            var storeTracking = urls.FirstOrDefault(IsAllowedOfferTrackingUrl);
            if (!string.IsNullOrWhiteSpace(storeTracking))
            {
                return storeTracking;
            }
        }

        return matches
            .Cast<Match>()
            .Select(match => NormalizeCapturedUrl(match.Value))
            .FirstOrDefault(url => !LooksLikeBioOrHubUrl(url) && !LooksLikeCouponUrl(url, text))
            ?? matches
                .Cast<Match>()
                .Select(match => NormalizeCapturedUrl(match.Value))
                .LastOrDefault(url => !LooksLikeBioOrHubUrl(url));
    }

    private static string? ExtractUrlAfterCtaLine(string text)
    {
        var lines = text.Split('\n').Select(x => x.Trim()).ToArray();
        for (var i = 0; i < lines.Length; i++)
        {
            if (!LooksLikeOfferCtaLine(lines[i]))
            {
                continue;
            }

            var sameLine = UrlRegex().Match(lines[i]);
            if (sameLine.Success)
            {
                var url = NormalizeCapturedUrl(sameLine.Value);
                if (!LooksLikeBioOrHubUrl(url) && !LooksLikeCouponCtaLine(lines[i]))
                {
                    return url;
                }
            }

            for (var j = i + 1; j < Math.Min(lines.Length, i + 4); j++)
            {
                if (LooksLikeCouponCtaLine(lines[j]))
                {
                    break;
                }

                var match = UrlRegex().Match(lines[j]);
                if (match.Success)
                {
                    var url = NormalizeCapturedUrl(match.Value);
                    if (!LooksLikeBioOrHubUrl(url))
                    {
                        return url;
                    }
                }
            }
        }

        return null;
    }

    private static string NormalizeCapturedUrl(string url)
        => url.Trim().TrimEnd('.', ',', ';', ':', '!', '?', ')', ']', '}');

    private static bool LooksLikeCouponUrl(string url, string text)
    {
        var index = text.IndexOf(url, StringComparison.OrdinalIgnoreCase);
        if (index < 0)
        {
            return false;
        }

        var start = Math.Max(0, index - 80);
        var context = NormalizeTextForUrlContext(text[start..Math.Min(text.Length, index + url.Length + 20)]);
        return ContainsAnyText(context, "cupom", "cupons", "resgate");
    }

    private static bool LooksLikeCouponCampaignText(string text)
    {
        var normalized = NormalizeTextForUrlContext(text);
        return ContainsAnyText(normalized, "cupom", "cupons", "resgate")
               && !ContainsAnyText(normalized, "compre aqui", "comprar aqui", "pegar oferta", "ver oferta", "link do produto", "link produto");
    }

    private static bool IsCouponCampaignOffer(WhatsAppNicheRouteOfferInput offer, string? originalText)
        => LooksLikeCouponCampaignText($"{offer.ProductName}\n{offer.StoreName}\n{originalText}");

    private static bool IsAllowedOfferTrackingUrl(string url)
    {
        var id = ExtractTrackingIdFromRedirectUrl(url);
        return !string.IsNullOrWhiteSpace(id)
               && TrackingIdDecorator.IsAllowedOfferTrackingId(id)
               && !TrackingIdDecorator.IsBlockedOfferTrackingId(id);
    }

    private static bool LooksLikeOfferCtaLine(string line)
    {
        var normalized = NormalizeTextForUrlContext(line);
        return ContainsAnyText(normalized, "compre aqui", "comprar aqui", "pegar oferta", "ver oferta", "link do produto", "link produto")
               && !LooksLikeCouponCtaLine(line);
    }

    private static bool LooksLikeCouponCtaLine(string line)
    {
        var normalized = NormalizeTextForUrlContext(line);
        return ContainsAnyText(normalized, "cupom", "cupons", "resgate");
    }

    private static bool ContainsAnyText(string text, params string[] terms)
        => terms.Any(term => text.Contains(term, StringComparison.OrdinalIgnoreCase));

    private static string NormalizeTextForUrlContext(string value)
    {
        var normalized = value.Normalize(NormalizationForm.FormD).ToLowerInvariant();
        return new string(normalized.Where(ch => CharUnicodeInfo.GetUnicodeCategory(ch) != UnicodeCategory.NonSpacingMark).ToArray());
    }

    private static string ReplaceLast(string text, string oldValue, string newValue)
    {
        var index = text.LastIndexOf(oldValue, StringComparison.OrdinalIgnoreCase);
        if (index < 0)
        {
            return text;
        }

        return string.Concat(text.AsSpan(0, index), newValue, text.AsSpan(index + oldValue.Length));
    }

    private static string NormalizeNicheCaption(string text)
    {
        var trimmed = text.Trim();
        if (trimmed.Contains("⚠", StringComparison.Ordinal) || trimmed.Contains("Promo", StringComparison.OrdinalIgnoreCase))
        {
            return trimmed;
        }

        return $"{trimmed}\n\n⚠ Oferta sujeita a alterar ou acabar sem aviso.";
    }

    private static bool LooksLikeOfferTrackingUrl(string url)
        => url.Contains("/r/", StringComparison.OrdinalIgnoreCase)
           || url.Contains("reidasofertas", StringComparison.OrdinalIgnoreCase)
           || url.Contains("achadinhos", StringComparison.OrdinalIgnoreCase);

    private static bool LooksLikeStoreUrl(string url)
        => url.Contains("mercadolivre", StringComparison.OrdinalIgnoreCase)
           || url.Contains("meli.la", StringComparison.OrdinalIgnoreCase)
           || url.Contains("shopee", StringComparison.OrdinalIgnoreCase)
           || url.Contains("s.shopee", StringComparison.OrdinalIgnoreCase)
           || url.Contains("amazon", StringComparison.OrdinalIgnoreCase)
           || url.Contains("amzn.to", StringComparison.OrdinalIgnoreCase);

    private static bool LooksLikeBioOrHubUrl(string url)
        => InstitutionalUrlGuard.ShouldPreserve(url)
           || url.Contains("bio.reidasofertas", StringComparison.OrdinalIgnoreCase)
           || url.Contains("destaque", StringComparison.OrdinalIgnoreCase)
           || url.Contains("grupo-vip", StringComparison.OrdinalIgnoreCase)
           || url.Contains("chat.whatsapp.com", StringComparison.OrdinalIgnoreCase);

    private static string BuildGeneratedOfferMessage(WhatsAppNicheRouteOfferInput offer, string trackedUrl, string slug)
    {
        var lines = new List<string>();
        var variant = ResolveTemplateVariant($"{offer.ProductName}|{offer.ProductUrl}|{slug}");
        lines.Add(BuildNicheHook(slug, variant));
        if (!string.IsNullOrWhiteSpace(offer.ProductName))
        {
            lines.Add($"*{offer.ProductName.Trim()}*");
        }

        if (!string.IsNullOrWhiteSpace(offer.PriceText))
        {
            lines.Add($"Preco de achadinho: *{offer.PriceText.Trim()}*");
        }

        if (!string.IsNullOrWhiteSpace(offer.StoreName))
        {
            lines.Add($"Loja: {offer.StoreName.Trim()}");
        }

        lines.Add(string.Empty);
        lines.Add(BuildNicheCta(slug, variant));
        lines.Add(trackedUrl);
        lines.Add(string.Empty);
        lines.Add(BuildScarcityLine(variant));
        return string.Join("\n", lines);
    }

    private static int ResolveTemplateVariant(string seed)
        => Math.Abs(StringComparer.OrdinalIgnoreCase.GetHashCode(seed)) % 4;

    private static string BuildNicheHook(string slug, int variant)
        => (slug, variant) switch
        {
            (WhatsAppNicheDefinitions.Casa, 0) => "🏠 Achado pra casa que trabalha mais que muita reuniao:",
            (WhatsAppNicheDefinitions.Casa, 1) => "🍳 Se a cozinha tivesse grupo, ela mandava esse link:",
            (WhatsAppNicheDefinitions.Casa, 2) => "✨ Utilidade domestica com cara de compra esperta:",
            (WhatsAppNicheDefinitions.Beleza, 0) => "💅 Alerta beleza: esse aqui merece espaco no necessaire.",
            (WhatsAppNicheDefinitions.Beleza, 1) => "🚨 Plantao autocuidado apitando forte:",
            (WhatsAppNicheDefinitions.Beleza, 2) => "✨ Produto de beleza piscou no radar:",
            (WhatsAppNicheDefinitions.FitnessHealth, 0) => "💪 Achado fitness que entrou em modo treino:",
            (WhatsAppNicheDefinitions.FitnessHealth, 1) => "🥤 Radar de performance apitou por aqui:",
            (WhatsAppNicheDefinitions.FitnessHealth, 2) => "⚡ Oferta boa pra quem leva rotina a serio:",
            (WhatsAppNicheDefinitions.FitnessHealth, _) => "🏋️ Achadinho fitness selecionado pelo radar:",
            (WhatsAppNicheDefinitions.Moda, 0) => "👟 Look do dia encontrou desconto e veio correndo avisar:",
            (WhatsAppNicheDefinitions.Moda, 1) => "🛍️ Achadinho fashion passando na sua timeline:",
            (WhatsAppNicheDefinitions.Moda, 2) => "🔥 Moda boa + preco bom = perigo pro carrinho:",
            (WhatsAppNicheDefinitions.Tech, 0) => "⚡ Plantao tech: gadget bom piscou no radar.",
            (WhatsAppNicheDefinitions.Tech, 1) => "💻 Oferta tech com cheiro de upgrade:",
            (WhatsAppNicheDefinitions.Tech, 2) => "🎮 Alerta dos eletronicos que a gente respeita:",
            (WhatsAppNicheDefinitions.Ate50, _) => "💸 Baratinho perigoso para o carrinho:",
            (WhatsAppNicheDefinitions.MercadoLivre, _) => "🟡 Mercado Livre entregou preco interessante:",
            _ => "🔥 Achadinho selecionado pelo Rei das Ofertas:"
        };

    private static string BuildNicheCta(string slug, int variant)
        => (slug, variant) switch
        {
            (WhatsAppNicheDefinitions.Casa, 0) => "Se sua casa pudesse falar, ja teria mandado voce clicar:",
            (WhatsAppNicheDefinitions.Casa, 1) => "Da uma olhada antes que alguem organize o estoque inteiro:",
            (WhatsAppNicheDefinitions.Beleza, 0) => "Clica antes que o preco resolva fazer skincare reverso:",
            (WhatsAppNicheDefinitions.Beleza, 1) => "Vai ver com calma, mas nao com calma demais:",
            (WhatsAppNicheDefinitions.FitnessHealth, 0) => "Confere antes que o estoque entre em fase de bulking:",
            (WhatsAppNicheDefinitions.FitnessHealth, 1) => "Vai olhar agora, porque suplemento bom nao espera descanso:",
            (WhatsAppNicheDefinitions.FitnessHealth, _) => "Da uma olhada antes que esse preco perca o folego:",
            (WhatsAppNicheDefinitions.Moda, 0) => "Vai la ver antes que acabe tamanho, cor e paciencia:",
            (WhatsAppNicheDefinitions.Moda, 1) => "Confere logo, porque moda boa nao espera provador:",
            (WhatsAppNicheDefinitions.Tech, 0) => "Confere agora, porque tech boa some no modo ninja:",
            (WhatsAppNicheDefinitions.Tech, 1) => "Abre ai e ve se o upgrade finalmente veio:",
            (WhatsAppNicheDefinitions.Ate50, _) => "Compra facil, arrependimento dificil:",
            _ => "Ver oferta:"
        };

    private static string BuildScarcityLine(int variant)
        => variant switch
        {
            0 => "⚠ Oferta sujeita a alterar ou acabar sem aviso.",
            1 => "⏰ Preco bom costuma ser ligeiro.",
            2 => "🔥 Se gostou, nao deixa pra depois.",
            _ => "👀 Achado visto, carrinho avisado."
        };

    [GeneratedRegex(@"https?://[^\s]+", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex UrlRegex();

    [GeneratedRegex(@"(?im)(?<prefix>(?:pegar oferta|compre aqui|comprar aqui|ver oferta|link do produto|link produto|produto|oferta)[^\r\n]*?)(?<url>https?://[^\s]+)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex OfferCtaUrlRegex();

    [GeneratedRegex(@"(?:item_id[:=]|[/_-])(MLB-?\d{5,})|/p/(MLB\d{5,})", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex MercadoLivreProductRegex();

    [GeneratedRegex(@"(?:/dp/|/gp/product/)([A-Z0-9]{10})", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex AmazonProductRegex();

    [GeneratedRegex(@"(?:-i\.|/product/)\d+\.(\d+)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex ShopeeProductRegex();

    private static string BuildInviteMessage(WhatsAppNicheGroupSettings group, string trackedUrl, string? customMessage)
    {
        if (!string.IsNullOrWhiteSpace(customMessage))
        {
            return customMessage.Replace("{link}", trackedUrl, StringComparison.OrdinalIgnoreCase)
                .Replace("{nicho}", group.DisplayName, StringComparison.OrdinalIgnoreCase);
        }

        return $"Quer receber menos bagunca e mais oferta do que voce curte?\n\nO grupo {group.DisplayName} separa achadinhos por interesse.\n\nEntrar aqui: {trackedUrl}";
    }

    private static IReadOnlyList<string> ResolveRequestedSlugs(IReadOnlyList<string>? requested)
        => (requested is { Count: > 0 } ? requested : WhatsAppNicheDefinitions.All.Select(x => x.Slug).ToArray())
            .Select(WhatsAppNicheDefinitions.NormalizeSlug)
            .Where(WhatsAppNicheDefinitions.IsKnown)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();

    private static string NormalizePublicBaseUrl(string? publicBaseUrl)
    {
        if (Uri.TryCreate(publicBaseUrl?.Trim(), UriKind.Absolute, out var uri))
        {
            return $"{uri.Scheme}://{uri.Authority}".TrimEnd('/');
        }

        return "https://reidasofertas.ia.br";
    }

    private static string FirstNonEmpty(params string?[] values)
        => values.FirstOrDefault(x => !string.IsNullOrWhiteSpace(x))?.Trim() ?? string.Empty;

    private static string? NormalizeOptional(string? value)
        => string.IsNullOrWhiteSpace(value) ? null : value.Trim();

    private static WhatsAppNicheDecision? ResolveOverride(AutomationSettings settings, WhatsAppNicheRouteOfferInput offer)
    {
        var item = ResolveOverrideItem(settings, offer);
        return item is null ? null : new WhatsAppNicheDecision(item.TargetSlugs[0], false, $"override_{item.Mode}", 100);
    }

    private static WhatsAppNicheOverrideSettings? ResolveOverrideItem(AutomationSettings settings, WhatsAppNicheRouteOfferInput offer)
    {
        var text = $"{offer.ProductName} {offer.ProductUrl} {offer.StoreName}";
        return settings.WhatsAppNicheOverrides.FirstOrDefault(x =>
            x.Enabled &&
            !string.IsNullOrWhiteSpace(x.MatchText) &&
            text.Contains(x.MatchText, StringComparison.OrdinalIgnoreCase) &&
            x.TargetSlugs.Count > 0);
    }

    private async Task AppendRouteEventAsync(WhatsAppNicheRouteOfferRequest request, WhatsAppNicheRouteOfferInput offer, WhatsAppNicheRouteResult result, OfferImageResolutionResult? image, CancellationToken ct)
    {
        var trackingId = result.TrackingUrl is null ? null : result.TrackingUrl.Split('/').LastOrDefault();
        var resolvedOfferId = TrackingIdDecorator.Resolve(request.OfferId ?? string.Empty).LookupId;
        await _operationsStore.AppendRouteEventAsync(new WhatsAppNicheRouteEvent
        {
            Slug = result.Slug,
            Status = result.Status,
            Reason = result.Reason,
            Confidence = result.Confidence,
            ProductName = offer.ProductName,
            ProductUrl = offer.ProductUrl,
            ProductIdentity = BuildProductIdentity(offer),
            StoreName = offer.StoreName,
            TrackingUrl = result.TrackingUrl,
            TrackingId = trackingId,
            TargetGroupId = result.TargetGroupId,
            HadImage = image is not null,
            ImageSource = image?.Source,
            ResolvedImageUrl = image?.ResolvedImageUrl,
            ReusedCanonicalTracking = IsCanonicalOfferTrackingId(resolvedOfferId)
        }, ct);
    }

    private static IReadOnlyList<string> BuildAlerts(IReadOnlyList<WhatsAppNicheMetricRow> rows, IReadOnlyList<WhatsAppNicheRouteEvent> events)
    {
        var alerts = new List<string>();
        var now = DateTimeOffset.UtcNow;
        foreach (var row in rows)
        {
            var latestSent = events.Where(x => x.Slug == row.Slug && x.Status == "sent").MaxBy(x => x.Timestamp);
            if (row.Sent == 0)
                alerts.Add($"{row.Slug}: nenhum envio nas ultimas 24h.");
            if (latestSent is not null && now - latestSent.Timestamp > TimeSpan.FromHours(8))
                alerts.Add($"{row.Slug}: sem envio ha mais de 8h.");
            if (row.ReviewRequired >= 5)
                alerts.Add($"{row.Slug}: {row.ReviewRequired} ofertas em revisao nas ultimas 24h.");
            var sentWithoutImage = events.Count(x => x.Timestamp >= now.AddHours(-24)
                && x.Slug == row.Slug
                && x.Status == "sent"
                && !x.HadImage
                && !LooksLikeCouponCampaignText($"{x.ProductName} {x.Reason}"));
            if (sentWithoutImage > 0)
                alerts.Add($"{row.Slug}: {sentWithoutImage} envio(s) sem imagem nas ultimas 24h.");
        }

        if (events.Any(x => x.Timestamp >= now.AddHours(-24) && (x.TrackingId?.StartsWith("LK-", StringComparison.OrdinalIgnoreCase) ?? false)))
            alerts.Add("LK detectado em roteamento recente; revisar origem antes de escalar.");
        return alerts;
    }

    private static string BuildDailySummary(IReadOnlyList<WhatsAppNicheMetricRow> rows, IReadOnlyList<WhatsAppNicheTopProduct> topProducts, IReadOnlyList<string> alerts)
    {
        var best = rows.Where(x => x.Clicks > 0)
            .OrderByDescending(x => x.ClicksPerSend)
            .ThenByDescending(x => x.Clicks)
            .FirstOrDefault();
        var top = topProducts.FirstOrDefault();
        return string.Join(" ", new[]
        {
            $"Nichos nas ultimas 24h: {rows.Sum(x => x.Sent)} envios, {rows.Sum(x => x.Clicks)} cliques e {rows.Sum(x => x.ReviewRequired)} revisoes.",
            best is null ? "Ainda sem nicho lider." : $"Melhor eficiencia: {best.Slug} com {best.ClicksPerSend:0.##} clique(s) por envio.",
            top is null ? "Ainda sem produto lider." : $"Produto lider: {top.ProductName} ({top.Slug}) com {top.Clicks} clique(s).",
            alerts.Count == 0 ? "Sem alertas operacionais." : $"Alertas ativos: {alerts.Count}."
        });
    }
}

public static partial class WhatsAppNicheClassifier
{
    public static WhatsAppNicheDecision Classify(CanonicalOfferRecord offer)
        => Classify(new WhatsAppNicheRouteOfferInput(
            offer.ProductName,
            offer.ProductUrl,
            offer.StoreName,
            offer.Category,
            offer.PromoPrice?.ToString(CultureInfo.InvariantCulture),
            offer.CommissionRaw,
            null,
            null));

    public static WhatsAppNicheDecision Classify(CatalogOfferItem item)
        => Classify(new WhatsAppNicheRouteOfferInput(
            item.ProductName,
            FirstNonEmpty(item.AffiliateTargetUrl, item.OfferUrl, item.OriginalProductUrl),
            item.Store,
            item.Niche,
            item.PriceText,
            null,
            item.ImageUrl,
            item.DraftId));

    public static WhatsAppNicheDecision Classify(WhatsAppNicheRouteOfferInput offer)
    {
        var explicitNiche = WhatsAppNicheDefinitions.NormalizeSlug(offer.Category);
        var text = Normalize($"{offer.ProductName} {offer.StoreName} {offer.Category} {offer.ProductUrl} {offer.CommissionRaw}");
        if ((string.IsNullOrWhiteSpace(offer.Category)
             || !WhatsAppNicheDefinitions.IsKnown(explicitNiche)
             || explicitNiche == WhatsAppNicheDefinitions.Geral
             || explicitNiche == WhatsAppNicheDefinitions.FitnessHealth)
            && ContainsBeautyCareTerms(text))
        {
            return new WhatsAppNicheDecision(WhatsAppNicheDefinitions.Beleza, false, "termos_beleza_prioritarios", 96);
        }

        if (WhatsAppNicheDefinitions.IsKnown(explicitNiche) && explicitNiche != WhatsAppNicheDefinitions.Geral)
        {
            return new WhatsAppNicheDecision(explicitNiche, false, "nicho_explicito", 100);
        }

        var price = TryParsePrice(offer.PriceText);
        var isMercadoLivre = ContainsAny(text, "mercado livre", "mercadolivre", "mercadolivre.com", "produto.mercadolivre");
        var hasCommissionSignal = ContainsAny(text, "comissao", "commission", "%") || !string.IsNullOrWhiteSpace(offer.CommissionRaw);
        if (isMercadoLivre && hasCommissionSignal)
        {
            return new WhatsAppNicheDecision(WhatsAppNicheDefinitions.MercadoLivre, false, "mercado_livre_com_comissao", 95);
        }

        if (price is > 0 and <= 50)
        {
            return new WhatsAppNicheDecision(WhatsAppNicheDefinitions.Ate50, false, "preco_ate_50", 96);
        }

        if (ContainsAny(text, "creatina", "whey", "pre treino", "pre-treino", "vitamina", "suplemento", "protein", "colageno", "omega 3", "omega3", "termogenico"))
        {
            return new WhatsAppNicheDecision(WhatsAppNicheDefinitions.FitnessHealth, false, "termos_fitness_health", 90);
        }

        if (ContainsAny(text, "smart tv", "televisao", "televisão", " tv ", " tvs ", "qled", "oled", "roku tv", "google tv", "projetor", "projector", "hy300", "hy320", "magcubic"))
        {
            return new WhatsAppNicheDecision(WhatsAppNicheDefinitions.Tech, false, "video_tech_e_casa", 94);
        }

        if (ContainsAny(text, "relogio masculino", "relogio feminino", "relogio unissex", "relogio analogico", "relogio digital", "relogios masculino", "relogios feminino", "g-shock", "casio vintage", "poedagar"))
        {
            return new WhatsAppNicheDecision(WhatsAppNicheDefinitions.Moda, false, "relogio_moda", 95);
        }

        if (ContainsAny(text, "celular", "smartphone", "iphone", "fone", "headset", "notebook", "laptop", "smart home", "alexa", "periferico", "teclado", "mouse", "game", "gamer", "console", "ssd", "monitor", "camera", "dji", "osmo", "gopro", "placa de video", "placa mae", "placa-mae", "processador", "ryzen", "rtx", "tablet", "ipad", "joystick", "controle", "caixa de som", "soundbar", "smart band"))
        {
            return new WhatsAppNicheDecision(WhatsAppNicheDefinitions.Tech, false, "termos_tech", 90);
        }

        if (ContainsAny(text, "bicicleta eletrica", "bike eletrica", "bici eletrica"))
        {
            return new WhatsAppNicheDecision(WhatsAppNicheDefinitions.Tech, false, "mobilidade_eletrica_tech", 95);
        }

        if (ContainsAny(text, "album figurinha", "album de figurinha", "album copa", "figurinhas copa", "panini copa", "copa do mundo 2026", "cupom de desconto", "cupom amazon", "cupom mercado livre", "cupons mercado livre", "cupom shopee", "cupons shopee", "cupom generico", "cupom app"))
        {
            return new WhatsAppNicheDecision(WhatsAppNicheDefinitions.Casa, false, "campanha_ampla_copa_ou_cupom", 95);
        }

        if (ContainsAny(text, "prateleira", "estante", "multiuso", "decoracao", "decorativo", "espelho", "quarto", "guarda roupa", "guarda-roupa", "organizador", "organizadora"))
        {
            return new WhatsAppNicheDecision(WhatsAppNicheDefinitions.Casa, false, "termos_casa_organizacao", 92);
        }

        if (ContainsBeautyCareTerms(text))
        {
            return new WhatsAppNicheDecision(WhatsAppNicheDefinitions.Beleza, false, "termos_beleza", 90);
        }

        if (ContainsAny(text, "cozinha", "organizador", "organizacao", "decoracao", "decorativo", "espelho", "cama", "mesa", "banho", "utensilio", "panela", "air fryer", "cooktop", "sanduicheira", "misteira", "grill", "micro ondas", "micro-ondas", "limpeza", "purificador", "filtro", "tinta", "ferramenta", "bolsa ferramenta", "bolsa de ferramenta", "travesseiro", "liquidificador", "lavadora", "lavadora de alta pressao", "lavadora alta pressao", "alta pressao", "lava e seca", "lava loucas", "luminaria", "luminaria de lava", "lava lamp", "sapateira", "persiana", "ar condicionado", "faqueiro", "xicara", "petisqueira", "quadro", "quadros", "aromatizador", "sofa", "estante", "escrivaninha", "guarda roupa", "guarda-roupa", "toalha", "tapete", "colcha", "geladeira", "refrigerador", "prateleira", "quarto"))
        {
            return new WhatsAppNicheDecision(WhatsAppNicheDefinitions.Casa, false, "termos_casa", 90);
        }

        if (ContainsAny(text, "cafe", "achocolatado", "alimento", "supermercado", "graos", "grao", "vinho", "cerveja", "amaciante", "detergente", "sabao")
            || ContainsWholeWordAny(text, "gin", "vodka"))
        {
            return new WhatsAppNicheDecision(WhatsAppNicheDefinitions.Casa, false, "mercado_bebidas_em_casa_temporario", 90);
        }

        if (!ContainsAny(text, "bolsa ferramenta", "bolsa de ferramenta", "tinta")
            && ContainsAny(text, "vestido", "camiseta", "blusa", "calca", "short", "bermuda", "tenis", "sandalia", "scarpin", "bota", "sapato", "bolsa", "mochila", "relogio", "relogios", "watch", "oculos", "moda", "calcado", "acessorio", "acessorios", "terno", "paleto", "blazer", "moletom", "poncho", "tricot", "regata", "colar"))
        {
            return new WhatsAppNicheDecision(WhatsAppNicheDefinitions.Moda, false, "termos_moda", 90);
        }

        if (isMercadoLivre)
        {
            return new WhatsAppNicheDecision(WhatsAppNicheDefinitions.MercadoLivre, false, "mercado_livre_sem_comissao_explicita", 70);
        }

        return new WhatsAppNicheDecision(WhatsAppNicheDefinitions.Geral, true, "nicho_ambiguo_requer_revisao", 20);
    }

    public static IReadOnlyList<string> ResolveHybridTargetSlugs(WhatsAppNicheRouteOfferInput offer)
    {
        var text = $" {Normalize($"{offer.ProductName} {offer.StoreName} {offer.Category} {offer.ProductUrl}")} ";
        if (ContainsAny(text, "smart tv", "televisao", " tv ", " tvs ", "qled", "oled", "roku tv", "google tv", "projetor", "projector", "hy300", "hy320", "magcubic"))
        {
            return [WhatsAppNicheDefinitions.Tech, WhatsAppNicheDefinitions.Casa];
        }

        return [];
    }

    private static decimal? TryParsePrice(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        var match = PriceRegex().Match(value);
        if (!match.Success)
        {
            return null;
        }

        var raw = match.Value.Replace("R$", string.Empty, StringComparison.OrdinalIgnoreCase).Trim();
        raw = raw.Replace(".", string.Empty, StringComparison.Ordinal).Replace(",", ".", StringComparison.Ordinal);
        return decimal.TryParse(raw, NumberStyles.Number, CultureInfo.InvariantCulture, out var parsed) ? parsed : null;
    }

    private static bool ContainsAny(string text, params string[] terms)
        => terms.Any(term => text.Contains(term, StringComparison.OrdinalIgnoreCase));

    private static bool ContainsBeautyCareTerms(string text)
        => ContainsAny(
            text,
            "creme",
            "perfume",
            "skincare",
            "skin care",
            "maquiagem",
            "higiene",
            "cabelo",
            "shampoo",
            "condicionador",
            "mascara capilar",
            "mascara de cabelo",
            "leave in",
            "leave-in",
            "protetor solar",
            "fps",
            "gloss",
            "batom",
            "secador",
            "prancha",
            "hidratante",
            "serum",
            "deo colonia",
            "body splash",
            "aparador",
            "barba");

    private static bool ContainsWholeWordAny(string text, params string[] terms)
    {
        var tokens = text.Split(new[] { ' ', '\r', '\n', '\t', '.', ',', ';', ':', '/', '\\', '-', '_', '|', '(', ')', '[', ']', '{', '}', '!', '?' }, StringSplitOptions.RemoveEmptyEntries);
        return terms.Any(term => tokens.Contains(term, StringComparer.OrdinalIgnoreCase));
    }

    private static string Normalize(string value)
    {
        var normalized = value.Normalize(NormalizationForm.FormD).ToLowerInvariant();
        return new string(normalized.Where(ch => CharUnicodeInfo.GetUnicodeCategory(ch) != UnicodeCategory.NonSpacingMark).ToArray());
    }

    private static string FirstNonEmpty(params string?[] values)
        => values.FirstOrDefault(x => !string.IsNullOrWhiteSpace(x))?.Trim() ?? string.Empty;

    [GeneratedRegex(@"R?\$?\s*\d{1,5}(?:[\.,]\d{2})?")]
    private static partial Regex PriceRegex();
}

public static class WhatsAppNicheDefinitions
{
    public const string MercadoLivre = "mercado_livre";
    public const string Casa = "casa";
    public const string Beleza = "beleza";
    public const string FitnessHealth = "fitness_health";
    public const string Moda = "moda";
    public const string Tech = "tech";
    public const string Ate50 = "ate_50";
    public const string Geral = "geral";

    public static readonly IReadOnlyList<WhatsAppNicheDefinition> All =
    [
        new(MercadoLivre, "Rei das Ofertas - Mercado Livre VIP", "Produtos Mercado Livre com boa comissao, imagem e preco competitivo.", 8),
        new(Casa, "Rei das Ofertas - Casa, Cozinha e Organizacao", "Utensilios, cozinha, cama, mesa, banho, organizacao e decoracao simples.", 8),
        new(Beleza, "Rei das Ofertas - Beleza e Cuidados", "Skincare, cabelo, perfume, maquiagem e higiene.", 8),
        new(FitnessHealth, "Fitness e Saude", "Suplementos, nutricao esportiva, vitaminas, treino e recuperacao.", 8),
        new(Moda, "Rei das Ofertas - Moda, Calcados e Acessorios", "Roupas, bolsas, tenis, sandalias, relogios e oculos.", 8),
        new(Tech, "Rei das Ofertas - Tech e Eletronicos", "Celular, fone, notebook, smart home, perifericos e games.", 4),
        new(Ate50, "Rei das Ofertas - Achadinhos ate R$50", "Impulso, utilidades baratas, bugs e presentes simples.", 12),
        new(Geral, "Rei das Ofertas - Geral", "Porta de entrada com top ofertas do dia e campanhas especiais.", 5)
    ];

    public static bool IsKnown(string? slug)
        => All.Any(x => string.Equals(x.Slug, slug, StringComparison.OrdinalIgnoreCase));

    public static string NormalizeSlug(string? value)
    {
        var normalized = (value ?? string.Empty).Trim().ToLowerInvariant()
            .Replace("-", "_", StringComparison.Ordinal)
            .Replace(" ", "_", StringComparison.Ordinal);
        return normalized switch
        {
            "mercadolivre" or "ml" or "mercado_livre_vip" => MercadoLivre,
            "casa_cozinha" or "cozinha" or "organizacao" or "organização" => Casa,
            "beleza_cuidados" or "cuidados" => Beleza,
            "fitness" or "fitness_saude" or "fitness_e_saude" or "saude" or "saude_fitness" => FitnessHealth,
            "moda_calcados" or "moda_calcados_acessorios" or "calcados" or "calçados" => Moda,
            "eletronicos" or "eletrônicos" or "electronicos" or "tecnologia" => Tech,
            "ate50" or "ate_r_50" or "ate_r$50" or "baratinhos" => Ate50,
            "" => Geral,
            _ => normalized
        };
    }

    public static int GetOrder(string? slug)
    {
        var normalized = NormalizeSlug(slug);
        for (var i = 0; i < All.Count; i++)
        {
            if (string.Equals(All[i].Slug, normalized, StringComparison.OrdinalIgnoreCase))
            {
                return i;
            }
        }

        return 999;
    }

    public static string GetDisplayName(string slug)
        => All.First(x => string.Equals(x.Slug, slug, StringComparison.OrdinalIgnoreCase)).DisplayName;

    public static string GetDescription(string slug)
        => All.First(x => string.Equals(x.Slug, slug, StringComparison.OrdinalIgnoreCase)).Description;
}

public sealed record WhatsAppNicheDefinition(string Slug, string DisplayName, string Description, int DailyLimit);

public sealed record WhatsAppNicheDecision(string Slug, bool RequiresReview, string Reason, int Confidence);

public sealed record WhatsAppNicheRouteOfferInput(
    string? ProductName,
    string? ProductUrl,
    string? StoreName,
    string? Category,
    string? PriceText,
    string? CommissionRaw,
    string? ImageUrl,
    string? DraftId);

public sealed record WhatsAppNicheGroupUpsertRequest(
    string? DisplayName,
    string? Description,
    bool? Enabled,
    string? InstanceName,
    string? GroupId,
    string? InviteUrl,
    string? Campaign,
    int? DailyLimit);

public sealed record WhatsAppNicheGroupCreateRequest(
    string? InstanceName,
    IReadOnlyList<string>? SeedParticipantJids,
    IReadOnlyList<string>? Slugs,
    bool? SkipExisting,
    IReadOnlyDictionary<string, WhatsAppNicheManualGroupRequest>? ManualGroups);

public sealed record WhatsAppNicheManualGroupRequest(string? GroupId, string? InviteUrl);

public sealed record WhatsAppNicheGroupCreateSummary(int CreatedOrRegistered, int Failed, IReadOnlyList<WhatsAppNicheGroupCreateResult> Results);

public sealed record WhatsAppNicheGroupCreateResult(string Slug, bool Success, string? GroupId, string? InviteUrl, string? Status, string? Message);

public sealed record WhatsAppNicheInviteCampaignRequest(
    IReadOnlyList<string>? ParticipantJids,
    string? Message,
    bool SendNow = false);

public sealed record WhatsAppNicheInviteCampaignResult(
    bool Success,
    string Status,
    string Slug,
    string? TrackedInviteUrl,
    int ParticipantsRequested,
    int ParticipantsSent,
    string Message);

public sealed record WhatsAppNicheRouteOfferRequest(
    string? ProductName,
    string? ProductUrl,
    string? StoreName,
    string? Category,
    string? PriceText,
    string? CommissionRaw,
    string? CatalogItemIdOrKeyword,
    string? OfferId,
    string? DraftId,
    string? ImageUrl,
    string? OriginalText,
    string? Campaign,
    bool SendNow = false);

public sealed record WhatsAppNicheRouteResult(
    bool Success,
    string Status,
    string Slug,
    string Reason,
    int Confidence,
    string? TrackingUrl,
    string? TargetGroupId,
    string? Message);

public sealed record WhatsAppNicheOverrideUpsertRequest(string? Id, string MatchText, string Mode, bool Enabled, IReadOnlyList<string> TargetSlugs);
public sealed record WhatsAppNicheMetricRow(string Slug, int Sent, int DuplicateRecent, int ReviewRequired, int Clicks, decimal ClicksPerSend, int UniqueTrackedOffers);
public sealed record WhatsAppNicheTopProduct(string Slug, string? ProductName, string? TrackingId, int Clicks);
public sealed record WhatsAppNicheMetricsReport(IReadOnlyList<WhatsAppNicheMetricRow> Rows, IReadOnlyList<WhatsAppNicheTopProduct> TopProducts, IReadOnlyList<string> Alerts, string DailySummary);
