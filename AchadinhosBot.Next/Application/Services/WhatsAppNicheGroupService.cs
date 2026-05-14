using System.Globalization;
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
    private readonly ISettingsStore _settingsStore;
    private readonly IWhatsAppGateway _whatsAppGateway;
    private readonly ILinkTrackingStore _linkTrackingStore;
    private readonly ICatalogOfferStore _catalogOfferStore;
    private readonly WebhookOptions _webhookOptions;

    public WhatsAppNicheGroupService(
        ISettingsStore settingsStore,
        IWhatsAppGateway whatsAppGateway,
        ILinkTrackingStore linkTrackingStore,
        ICatalogOfferStore catalogOfferStore,
        IOptions<WebhookOptions> webhookOptions)
    {
        _settingsStore = settingsStore;
        _whatsAppGateway = whatsAppGateway;
        _linkTrackingStore = linkTrackingStore;
        _catalogOfferStore = catalogOfferStore;
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
        group.DailyLimit = Math.Clamp(request.DailyLimit ?? group.DailyLimit, 1, 50);
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

        var campaign = NormalizeOptional(request.Campaign) ?? group.Campaign;
        var trackedUrl = await CreateTrackedUrlAsync(
            offerUrl,
            offer.StoreName,
            $"whatsapp_niche_{group.Slug}",
            campaign,
            request.OfferId,
            request.DraftId,
            ct);

        var message = BuildOfferMessage(offer, trackedUrl);
        if (request.SendNow)
        {
            if (!TryReserveDailySlot(group, DateTimeOffset.UtcNow, out var quotaMessage))
            {
                return new WhatsAppNicheRouteResult(false, "daily_limit_reached", group.Slug, quotaMessage, trackedUrl, group.GroupId, null);
            }

            var send = await _whatsAppGateway.SendTextAsync(group.InstanceName, group.GroupId, message, ct);
            if (!send.Success)
            {
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
            request.DraftId);
    }

    private async Task<string> CreateTrackedUrlAsync(string targetUrl, string? store, string originSurface, string campaign, string? offerId, string? draftId, CancellationToken ct)
    {
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

        var baseUrl = NormalizePublicBaseUrl(_webhookOptions.PublicBaseUrl);
        return $"{baseUrl}/r/{Uri.EscapeDataString(string.IsNullOrWhiteSpace(tracking.Slug) ? tracking.Id : tracking.Slug)}?src=wg&camp={Uri.EscapeDataString(campaign)}";
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
            existing.DailyLimit = existing.DailyLimit <= 0 ? definition.DailyLimit : existing.DailyLimit;
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

        if (group.SentToday >= Math.Max(1, group.DailyLimit))
        {
            message = $"Limite diario do nicho {group.Slug} atingido ({group.DailyLimit}).";
            return false;
        }

        group.SentToday++;
        group.UpdatedAtUtc = now;
        message = "ok";
        return true;
    }

    private static string BuildOfferMessage(WhatsAppNicheRouteOfferInput offer, string trackedUrl)
    {
        var lines = new List<string>();
        if (!string.IsNullOrWhiteSpace(offer.ProductName))
        {
            lines.Add(offer.ProductName.Trim());
        }

        if (!string.IsNullOrWhiteSpace(offer.PriceText))
        {
            lines.Add($"Preco: {offer.PriceText.Trim()}");
        }

        if (!string.IsNullOrWhiteSpace(offer.StoreName))
        {
            lines.Add($"Loja: {offer.StoreName.Trim()}");
        }

        lines.Add($"Comprar: {trackedUrl}");
        return string.Join("\n", lines);
    }

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
            null));

    public static WhatsAppNicheDecision Classify(CatalogOfferItem item)
        => Classify(new WhatsAppNicheRouteOfferInput(
            item.ProductName,
            FirstNonEmpty(item.AffiliateTargetUrl, item.OfferUrl, item.OriginalProductUrl),
            item.Store,
            item.Niche,
            item.PriceText,
            null,
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

        if (ContainsAny(text, "celular", "smartphone", "iphone", "fone", "headset", "notebook", "laptop", "smart home", "alexa", "periferico", "teclado", "mouse", "game", "gamer", "console", "ssd", "monitor"))
        {
            return new WhatsAppNicheDecision(WhatsAppNicheDefinitions.Tech, false, "termos_tech");
        }

        if (ContainsAny(text, "creme", "perfume", "skincare", "skin care", "maquiagem", "higiene", "cabelo", "shampoo", "condicionador", "protetor solar", "suplemento"))
        {
            return new WhatsAppNicheDecision(WhatsAppNicheDefinitions.Beleza, false, "termos_beleza");
        }

        if (ContainsAny(text, "cozinha", "organizador", "organizacao", "casa", "decoracao", "cama", "mesa", "banho", "utensilio", "panela", "air fryer", "limpeza"))
        {
            return new WhatsAppNicheDecision(WhatsAppNicheDefinitions.Casa, false, "termos_casa");
        }

        if (ContainsAny(text, "vestido", "camiseta", "blusa", "calca", "tenis", "sandalia", "bolsa", "relogio", "oculos", "moda", "calcado", "acessorio"))
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
    public const string Moda = "moda";
    public const string Tech = "tech";
    public const string Ate50 = "ate_50";
    public const string Geral = "geral";

    public static readonly IReadOnlyList<WhatsAppNicheDefinition> All =
    [
        new(MercadoLivre, "Rei das Ofertas - Mercado Livre VIP", "Produtos Mercado Livre com boa comissao, imagem e preco competitivo.", 8),
        new(Casa, "Rei das Ofertas - Casa, Cozinha e Organizacao", "Utensilios, cozinha, cama, mesa, banho, organizacao e decoracao simples.", 8),
        new(Beleza, "Rei das Ofertas - Beleza e Cuidados", "Skincare, cabelo, perfume, maquiagem, higiene e suplementos leves.", 8),
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
