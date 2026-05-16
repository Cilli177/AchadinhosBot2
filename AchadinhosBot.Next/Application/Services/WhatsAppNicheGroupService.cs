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
        var decision = WhatsAppNicheClassifier.Classify(offer);
        if (decision.RequiresReview)
        {
            return new WhatsAppNicheRouteResult(false, "review_required", decision.Slug, decision.Reason, null, null, null);
        }

        var settings = await _settingsStore.GetAsync(ct);
        EnsureDefaults(settings);
        var group = settings.WhatsAppNicheGroups.FirstOrDefault(x => string.Equals(x.Slug, decision.Slug, StringComparison.OrdinalIgnoreCase));
        if (group is null || !group.Enabled || string.IsNullOrWhiteSpace(group.GroupId))
        {
            return new WhatsAppNicheRouteResult(false, "missing_group", decision.Slug, "Nicho classificado, mas sem grupo WhatsApp ativo configurado.", null, null, null);
        }

        var offerUrl = FirstNonEmpty(offer.ProductUrl, request.ProductUrl);
        if (string.IsNullOrWhiteSpace(offerUrl))
        {
            return new WhatsAppNicheRouteResult(false, "missing_url", decision.Slug, "Oferta sem URL roteavel.", null, group.GroupId, null);
        }

        var repeatDedupeKey = BuildRepeatDedupeKey(group.Slug, offer);
        if (request.SendNow &&
            (await WasRecentlySentToGroupAsync(group, offer, ct) ||
             !_idempotencyStore.TryBegin(repeatDedupeKey, NicheRepeatWindow)))
        {
            return new WhatsAppNicheRouteResult(
                false,
                "duplicate_recent",
                group.Slug,
                $"Mesmo produto ja enviado para {group.DisplayName} nas ultimas {NicheRepeatWindow.TotalDays:0} dias.",
                null,
                group.GroupId,
                null);
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
        if (request.SendNow)
        {
            if (!TryReserveDailySlot(group, DateTimeOffset.UtcNow, out var quotaMessage))
            {
                return new WhatsAppNicheRouteResult(false, "daily_limit_reached", group.Slug, quotaMessage, trackedUrl, group.GroupId, null);
            }

            var send = await SendOfferAsync(group, message, image, ct);
            if (!send.Success)
            {
                _idempotencyStore.RemoveByPrefix(repeatDedupeKey);
                return new WhatsAppNicheRouteResult(false, "send_failed", group.Slug, send.Message ?? "Falha ao enviar.", trackedUrl, group.GroupId, message);
            }

            await _settingsStore.SaveAsync(settings, ct);
            return new WhatsAppNicheRouteResult(true, "sent", group.Slug, decision.Reason, trackedUrl, group.GroupId, message);
        }

        return new WhatsAppNicheRouteResult(true, "prepared", group.Slug, decision.Reason, trackedUrl, group.GroupId, message);
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
        var resolvedOfferId = TrackingIdDecorator.Resolve(offerId ?? string.Empty).LookupId;
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
        var titleToken = NormalizeIdentityToken(offer.ProductName);
        if (string.IsNullOrWhiteSpace(titleToken))
        {
            return false;
        }

        var cutoff = DateTimeOffset.UtcNow - NicheRepeatWindow;
        var recent = await _whatsAppOutboundLogStore.ListRecentAsync(1000, ct);
        return recent.Any(entry =>
            entry.CreatedAtUtc >= cutoff &&
            string.Equals(entry.To, group.GroupId, StringComparison.OrdinalIgnoreCase) &&
            NormalizeIdentityToken(entry.Text).Contains(titleToken, StringComparison.Ordinal));
    }

    private static string BuildNormalizedProductIdentity(string? store, string? title)
        => $"{NormalizeIdentityToken(store)}|{NormalizeIdentityToken(title)}";

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
            var result = await _offerImageResolver.ResolveAsync(
                new OfferImageResolutionRequest(
                    offerUrl,
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
        var reused = TryBuildFromOriginalText(originalText, trackedUrl, originalUrl);
        if (!string.IsNullOrWhiteSpace(reused))
        {
            return reused;
        }

        return BuildGeneratedOfferMessage(offer, trackedUrl, slug);
    }

    private static string? TryBuildFromOriginalText(string? originalText, string trackedUrl, string? originalUrl)
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
                .Where(url => (LooksLikeOfferTrackingUrl(url) || LooksLikeStoreUrl(url)) && !LooksLikeBioOrHubUrl(url))
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

        return NormalizeNicheCaption(replaced);
    }

    private static string AddEmotionalFooter(string text, string trackedUrl)
        => $"{text.TrimEnd()}\n\n🔥 Corre aqui antes que suma:\n{trackedUrl}";

    private static string ReplaceOfferCtaUrl(string text, string trackedUrl)
    {
        var matches = OfferCtaUrlRegex().Matches(text);
        foreach (Match match in matches)
        {
            var url = match.Groups["url"].Value.Trim();
            if (LooksLikeBioOrHubUrl(url))
            {
                continue;
            }

            return ReplaceLast(text, url, trackedUrl);
        }

        return text;
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
           || url.Contains("grupo-vip", StringComparison.OrdinalIgnoreCase);

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

    [GeneratedRegex(@"(?:item_id[:=]|[/_-])(MLB\d{5,})|/p/(MLB\d{5,})", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
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
        if (WhatsAppNicheDefinitions.IsKnown(explicitNiche) && explicitNiche != WhatsAppNicheDefinitions.Geral)
        {
            return new WhatsAppNicheDecision(explicitNiche, false, "nicho_explicito");
        }

        var text = Normalize($"{offer.ProductName} {offer.StoreName} {offer.Category} {offer.ProductUrl} {offer.CommissionRaw}");
        var price = TryParsePrice(offer.PriceText);
        var isMercadoLivre = ContainsAny(text, "mercado livre", "mercadolivre", "mercadolivre.com", "produto.mercadolivre");
        var hasCommissionSignal = ContainsAny(text, "comissao", "commission", "%") || !string.IsNullOrWhiteSpace(offer.CommissionRaw);
        if (isMercadoLivre && hasCommissionSignal)
        {
            return new WhatsAppNicheDecision(WhatsAppNicheDefinitions.MercadoLivre, false, "mercado_livre_com_comissao");
        }

        if (price is > 0 and <= 50)
        {
            return new WhatsAppNicheDecision(WhatsAppNicheDefinitions.Ate50, false, "preco_ate_50");
        }

        if (ContainsAny(text, "creatina", "whey", "pre treino", "pre-treino", "vitamina", "suplemento", "protein", "colageno", "omega 3", "omega3", "termogenico"))
        {
            return new WhatsAppNicheDecision(WhatsAppNicheDefinitions.FitnessHealth, false, "termos_fitness_health");
        }

        if (ContainsAny(text, "celular", "smartphone", "iphone", "fone", "headset", "notebook", "laptop", "smart home", "alexa", "periferico", "teclado", "mouse", "game", "gamer", "console", "ssd", "monitor"))
        {
            return new WhatsAppNicheDecision(WhatsAppNicheDefinitions.Tech, false, "termos_tech");
        }

        if (ContainsAny(text, "creme", "perfume", "skincare", "skin care", "maquiagem", "higiene", "cabelo", "shampoo", "condicionador", "protetor solar", "gloss", "batom", "secador", "prancha"))
        {
            return new WhatsAppNicheDecision(WhatsAppNicheDefinitions.Beleza, false, "termos_beleza");
        }

        if (ContainsAny(text, "cozinha", "organizador", "organizacao", "casa", "decoracao", "cama", "mesa", "banho", "utensilio", "panela", "air fryer", "limpeza", "purificador", "filtro"))
        {
            return new WhatsAppNicheDecision(WhatsAppNicheDefinitions.Casa, false, "termos_casa");
        }

        if (ContainsAny(text, "vestido", "camiseta", "blusa", "calca", "tenis", "sandalia", "bolsa", "relogio", "oculos", "moda", "calcado", "acessorio", "terno", "paleto", "blazer"))
        {
            return new WhatsAppNicheDecision(WhatsAppNicheDefinitions.Moda, false, "termos_moda");
        }

        if (isMercadoLivre)
        {
            return new WhatsAppNicheDecision(WhatsAppNicheDefinitions.MercadoLivre, false, "mercado_livre_sem_comissao_explicita");
        }

        return new WhatsAppNicheDecision(WhatsAppNicheDefinitions.Geral, true, "nicho_ambiguo_requer_revisao");
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

public sealed record WhatsAppNicheDecision(string Slug, bool RequiresReview, string Reason);

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
    string? TrackingUrl,
    string? TargetGroupId,
    string? Message);
