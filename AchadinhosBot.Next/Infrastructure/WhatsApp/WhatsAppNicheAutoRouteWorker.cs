using System.Text.Json;
using System.Text.RegularExpressions;
using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Application.Services;
using AchadinhosBot.Next.Domain.Logs;

namespace AchadinhosBot.Next.Infrastructure.WhatsApp;

public sealed partial class WhatsAppNicheAutoRouteWorker : BackgroundService
{
    private static readonly TimeSpan Interval = TimeSpan.FromSeconds(60);
    private static readonly string[] SourceGroups =
    [
        "120363405661434395@g.us",
        "120363409272515351@g.us"
    ];

    private readonly IWhatsAppOutboundLogStore _outboundLogStore;
    private readonly ILinkTrackingStore _linkTrackingStore;
    private readonly ISettingsStore _settingsStore;
    private readonly IWhatsAppNicheOperationsStore _operationsStore;
    private readonly WhatsAppNicheGroupService _nicheGroupService;
    private readonly IWebHostEnvironment _environment;
    private readonly ILogger<WhatsAppNicheAutoRouteWorker> _logger;
    private readonly HashSet<string> _seen = new(StringComparer.OrdinalIgnoreCase);
    private bool _loaded;

    public WhatsAppNicheAutoRouteWorker(
        IWhatsAppOutboundLogStore outboundLogStore,
        ILinkTrackingStore linkTrackingStore,
        ISettingsStore settingsStore,
        IWhatsAppNicheOperationsStore operationsStore,
        WhatsAppNicheGroupService nicheGroupService,
        IWebHostEnvironment environment,
        ILogger<WhatsAppNicheAutoRouteWorker> logger)
    {
        _outboundLogStore = outboundLogStore;
        _linkTrackingStore = linkTrackingStore;
        _settingsStore = settingsStore;
        _operationsStore = operationsStore;
        _nicheGroupService = nicheGroupService;
        _environment = environment;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await RunOnceAsync(stoppingToken);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Falha no roteamento automatico de nichos.");
            }

            await Task.Delay(Interval, stoppingToken);
        }
    }

    private async Task RunOnceAsync(CancellationToken ct)
    {
        await EnsureSeenLoadedAsync(ct);
        var recent = await _outboundLogStore.ListRecentAsync(500, ct);
        var sourceOffers = recent
            .Where(IsSourceOffer)
            .OrderBy(x => x.CreatedAtUtc)
            .ToArray();

        if (!_loaded)
        {
            foreach (var entry in sourceOffers)
            {
                _seen.Add(BuildSeenKey(entry));
            }

            _loaded = true;
            await SaveSeenAsync(ct);
            _logger.LogInformation("WhatsAppNicheAutoRouteWorker iniciou com {Count} ofertas fonte marcadas como ja vistas.", _seen.Count);
            return;
        }

        var changed = false;
        foreach (var entry in sourceOffers)
        {
            var seenKey = BuildSeenKey(entry);
            if (_seen.Contains(seenKey))
            {
                continue;
            }

            _seen.Add(seenKey);
            changed = true;

            var candidates = await TryBuildRequestsAsync(entry, ct);
            if (candidates.Count == 0)
            {
                continue;
            }

            foreach (var candidate in candidates)
            {
                var results = await _nicheGroupService.RouteOfferWithOverridesAsync(candidate, ct);
                foreach (var result in results)
                {
                    _logger.LogInformation(
                        "Oferta roteada automaticamente para nicho. Source={Source} Slug={Slug} Status={Status} Success={Success}",
                        entry.To,
                        result.Slug,
                        result.Status,
                        result.Success);
                }
            }
        }

        if (changed)
        {
            await SaveSeenAsync(ct);
        }
    }

    private async Task<IReadOnlyList<WhatsAppNicheRouteOfferRequest>> TryBuildRequestsAsync(WhatsAppOutboundLogEntry entry, CancellationToken ct)
    {
        var text = StripScoutCommissionForAudience(entry.Text ?? string.Empty);
        var title = ExtractTitle(text);
        var category = ClassifyForActiveNiche(title) ?? ClassifyForActiveNiche(text);
        if (string.IsNullOrWhiteSpace(title) || string.IsNullOrWhiteSpace(category))
        {
            await SaveReviewAsync(entry, text, title, "auto_route_missing_product_or_niche", 10, null, ct);
            return Array.Empty<WhatsAppNicheRouteOfferRequest>();
        }

        var url = ExtractBestOfferUrl(text);
        if (string.IsNullOrWhiteSpace(url))
        {
            await SaveReviewAsync(entry, text, title, "auto_route_missing_offer_url", 10, category, ct);
            return Array.Empty<WhatsAppNicheRouteOfferRequest>();
        }

        var settings = await _settingsStore.GetAsync(ct);
        var whatsappInviteUrls = UrlRegex().Matches(text)
            .Cast<Match>()
            .Select(match => match.Value.Trim())
            .Where(WhatsAppInviteLinkNormalizer.IsWhatsAppInviteUrl)
            .ToArray();
        var unapprovedInviteUrl = whatsappInviteUrls.FirstOrDefault(inviteUrl =>
            !WhatsAppInviteLinkNormalizer.IsApprovedInviteUrl(
                inviteUrl,
                settings.WhatsAppNicheGroups.Select(group => group.InviteUrl)));
        if (!string.IsNullOrWhiteSpace(unapprovedInviteUrl))
        {
            _logger.LogWarning(
                "Oferta ignorada no auto-route por convite WhatsApp nao aprovado. MessageId={MessageId} Url={Url}",
                entry.MessageId,
                unapprovedInviteUrl);
            await SaveReviewAsync(entry, text, title, "unapproved_whatsapp_invite", 0, category, ct);
            return Array.Empty<WhatsAppNicheRouteOfferRequest>();
        }

        var offerId = ExtractTrackingId(url);
        var target = url;
        if (!string.IsNullOrWhiteSpace(offerId))
        {
            var tracking = await _linkTrackingStore.GetLinkAsync(TrackingIdDecorator.Resolve(offerId).LookupId, ct);
            target = tracking?.TargetUrl ?? url;
        }

        if (LooksLikeBioOrHubUrl(target))
        {
            _logger.LogWarning(
                "Oferta ignorada no auto-route por URL institucional ou de grupo. MessageId={MessageId} Url={Url}",
                entry.MessageId,
                target);
            await SaveReviewAsync(entry, text, title, "institutional_or_group_url_as_offer", 0, category, ct);
            return Array.Empty<WhatsAppNicheRouteOfferRequest>();
        }

        return ResolveTargetCategories(category, title)
            .Select(targetCategory => new WhatsAppNicheRouteOfferRequest(
                title,
                target,
                ResolveStore(offerId, text),
                targetCategory,
                ExtractPrice(text),
                ExtractCommission(text),
                null,
                string.IsNullOrWhiteSpace(offerId) ? entry.MessageId : offerId,
                null,
                entry.MediaUrl,
                text,
                $"niche_live_{targetCategory}",
                true))
            .ToArray();
    }

    private static string StripScoutCommissionForAudience(string text)
        => ScoutCommissionLineRegex().Replace(text, string.Empty);

    private async Task SaveReviewAsync(
        WhatsAppOutboundLogEntry entry,
        string text,
        string? title,
        string reason,
        int confidence,
        string? suggestedSlug,
        CancellationToken ct)
    {
        await _operationsStore.SaveReviewAsync(new WhatsAppNicheReviewItem
        {
            Reason = reason,
            Confidence = confidence,
            SuggestedSlug = suggestedSlug,
            ProductName = title,
            ProductUrl = ExtractBestOfferUrl(text),
            StoreName = ResolveStore(ExtractTrackingId(ExtractBestOfferUrl(text)), text),
            PriceText = ExtractPrice(text),
            ImageUrl = entry.MediaUrl,
            OriginalText = text,
            SourceGroupId = entry.To
        }, ct);
    }

    private static IReadOnlyList<string> ResolveTargetCategories(string primaryCategory, string? title)
    {
        var categories = new List<string> { primaryCategory };
        var normalized = Normalize(title ?? string.Empty);

        if (ContainsAny(normalized, "lixeira inteligente", "lixeira com sensor", "lampada inteligente", "aspirador robo", "smart home", "mesa de apoio", "caixa de som", "soundbar", "smart tv", "televisao", "tv "))
        {
            AddHybridCategory(categories, WhatsAppNicheDefinitions.Casa);
            AddHybridCategory(categories, WhatsAppNicheDefinitions.Tech);
        }

        if (ContainsAny(
                normalized,
                "cadeira gamer",
                "cadeira de escritorio",
                "cadeira escritorio",
                "cadeira ergonomica",
                "cadeira executiva"))
        {
            AddHybridCategory(categories, WhatsAppNicheDefinitions.Casa);
            AddHybridCategory(categories, WhatsAppNicheDefinitions.Tech);
        }

        return categories;
    }

    private static void AddHybridCategory(List<string> categories, string category)
    {
        if (!categories.Contains(category, StringComparer.OrdinalIgnoreCase))
        {
            categories.Add(category);
        }
    }

    private static bool IsSourceOffer(WhatsAppOutboundLogEntry entry)
        => SourceGroups.Any(x => string.Equals(x, entry.To, StringComparison.OrdinalIgnoreCase))
           && !string.IsNullOrWhiteSpace(entry.Text)
           && UrlRegex().IsMatch(entry.Text)
           && !entry.Text.Contains("Ciclo finalizado", StringComparison.OrdinalIgnoreCase)
           && !entry.Text.Contains("Comissao da oferta acima", StringComparison.OrdinalIgnoreCase)
           && !entry.Text.Contains("Comissão da oferta acima", StringComparison.OrdinalIgnoreCase);

    private static string BuildSeenKey(WhatsAppOutboundLogEntry entry)
        => $"{entry.To}|{ExtractTrackingId(ExtractBestOfferUrl(entry.Text ?? string.Empty)) ?? entry.MessageId}";

    private static string? ExtractBestOfferUrl(string text)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            return null;
        }

        var product = LinkProdutoRegex().Match(text);
        if (product.Success)
        {
            return NormalizeCapturedUrl(product.Groups[1].Value);
        }

        var cta = OfferCtaUrlRegex().Matches(text)
            .Cast<Match>()
            .Select(match => NormalizeCapturedUrl(match.Groups["url"].Value))
            .FirstOrDefault(url => !LooksLikeBioOrHubUrl(url));
        if (!string.IsNullOrWhiteSpace(cta))
        {
            return cta;
        }

        var matches = UrlRegex().Matches(text);
        return matches
            .Cast<Match>()
            .Select(match => NormalizeCapturedUrl(match.Value))
            .LastOrDefault(url => !LooksLikeBioOrHubUrl(url));
    }

    private static string? ExtractTrackingId(string? url)
    {
        if (string.IsNullOrWhiteSpace(url))
        {
            return null;
        }

        var match = TrackingRegex().Match(url);
        return match.Success ? NormalizeTrackingId(match.Groups[1].Value) : null;
    }

    private static string NormalizeCapturedUrl(string url)
        => url.Trim().TrimEnd('.', ',', ';', ':', '!', '?', ')', ']', '}', '⚡');

    private static string? NormalizeTrackingId(string trackingId)
    {
        var normalized = Regex.Replace(
            trackingId.Trim(),
            @"[^A-Za-z0-9-].*$",
            string.Empty,
            RegexOptions.CultureInvariant);
        return string.IsNullOrWhiteSpace(normalized) ? null : normalized;
    }

    private static bool LooksLikeBioOrHubUrl(string url)
        => InstitutionalUrlGuard.ShouldPreserve(url)
           || url.Contains("bio.reidasofertas", StringComparison.OrdinalIgnoreCase)
           || url.Contains("destaque", StringComparison.OrdinalIgnoreCase)
           || url.Contains("grupo-vip", StringComparison.OrdinalIgnoreCase)
           || url.Contains("chat.whatsapp.com", StringComparison.OrdinalIgnoreCase);

    private static string? ExtractTitle(string text)
    {
        var scout = ScoutTitleRegex().Match(text);
        if (scout.Success)
        {
            return scout.Groups["title"].Value.Trim();
        }

        var lines = text.Split('\n')
            .Select(x => x.Trim())
            .Where(x => !string.IsNullOrWhiteSpace(x))
            .ToArray();

        var boldTitle = BoldLineRegex().Matches(text)
            .Cast<Match>()
            .Select(match => match.Groups["title"].Value.Trim())
            .FirstOrDefault(IsLikelyProductTitle);
        if (!string.IsNullOrWhiteSpace(boldTitle))
        {
            return boldTitle;
        }

        var likelyTitle = lines
            .Select(x => x.Trim('*').Trim())
            .FirstOrDefault(IsLikelyProductTitle);
        if (!string.IsNullOrWhiteSpace(likelyTitle))
        {
            return likelyTitle;
        }

        return text.Split('\n')
            .Select(x => x.Trim().Trim('*'))
            .FirstOrDefault(x => IsLikelyProductTitle(x)
                                 && !x.StartsWith("Preco", StringComparison.OrdinalIgnoreCase)
                                 && !x.StartsWith("Preço", StringComparison.OrdinalIgnoreCase)
                                 && !x.StartsWith("Loja", StringComparison.OrdinalIgnoreCase)
                                 && !x.StartsWith("Comprar", StringComparison.OrdinalIgnoreCase)
                                 && !x.StartsWith("http", StringComparison.OrdinalIgnoreCase));
    }

    private static bool IsLikelyProductTitle(string line)
    {
        if (LooksLikeOperationalLine(line))
        {
            return false;
        }

        var normalized = Normalize(line);
        if (PriceRegex().IsMatch(line) && normalized.Length < 24)
        {
            return false;
        }

        if (LooksLikeGenericPromoLine(normalized))
        {
            return false;
        }

        return normalized.Length >= 8
               && ContainsAny(
                   normalized,
                   "iphone", "celular", "smartphone", "fone", "notebook", "monitor", "gamer", "carregador", "teclado", "mouse", "ssd", "tv", "camera", "dji", "osmo", "gopro",
                   "chapinha", "perfume", "skincare", "creme", "maquiagem", "cabelo", "secador", "shampoo", "gloss", "batom",
                   "whey", "creatina", "pre treino", "pre-treino", "suplemento", "vitamina",
                   "cozinha", "pote", "marmita", "cadeira", "organizador", "mesa", "banho", "casa", "panela", "air fryer", "toalha", "tapete", "purificador", "filtro", "tinta", "ferramenta",
                   "calca", "tenis", "meia", "cueca", "camiseta", "bolsa", "sandalia", "vestido", "terno", "paleto", "blazer", "puma", "kappa", "reebok");
    }

    private static bool LooksLikeOperationalLine(string line)
    {
        if (string.IsNullOrWhiteSpace(line))
        {
            return true;
        }

        var value = line.Trim().Trim('*');
        return value.StartsWith("Preco", StringComparison.OrdinalIgnoreCase)
               || value.StartsWith("Pre", StringComparison.OrdinalIgnoreCase) && value.Contains("o:", StringComparison.OrdinalIgnoreCase)
               || value.StartsWith("Loja", StringComparison.OrdinalIgnoreCase)
               || value.StartsWith("Comprar", StringComparison.OrdinalIgnoreCase)
               || value.StartsWith("Compre", StringComparison.OrdinalIgnoreCase)
               || value.StartsWith("Pegar oferta", StringComparison.OrdinalIgnoreCase)
               || value.StartsWith("Link", StringComparison.OrdinalIgnoreCase)
               || value.StartsWith("http", StringComparison.OrdinalIgnoreCase)
               || PriceOnlyRegex().IsMatch(value)
               || value.Contains("reidasofertas.ia.br", StringComparison.OrdinalIgnoreCase);
    }

    private static string? ClassifyForActiveNiche(string? title)
    {
        var text = Normalize(title ?? string.Empty);
        if (ContainsAny(text, "iphone", "celular", "smartphone", "fone", "headset", "notebook", "monitor", "smart tv", "qled", "oled", "pc gamer", "gamer", "carregador", "teclado", "mouse", "ssd", "placa de video", "processador", "ryzen", "rtx", "periferico", "caixa de som", "camera", "dji", "osmo", "gopro"))
        {
            return WhatsAppNicheDefinitions.Tech;
        }

        if (ContainsAny(text, "creatina", "whey", "pre treino", "pre-treino", "suplemento", "multivitaminico", "vitamina", "growth", "dark lab"))
        {
            return WhatsAppNicheDefinitions.FitnessHealth;
        }

        if (ContainsAny(text, "chapinha", "prancha", "perfume", "skincare", "creme", "maquiagem", "cabelo", "secador", "shampoo", "condicionador", "hidratante", "cerave", "natura", "lattafa", "wella", "oleo capilar", "gloss", "batom"))
        {
            return WhatsAppNicheDefinitions.Beleza;
        }

        if (ContainsAny(text, "cozinha", "pote", "potes", "hermetico", "marmita", "cadeira", "organizador", "mesa", "banho", "casa", "panela", "air fryer", "toalha", "tapete", "assadeira", "cama", "beliche", "sofa", "almofada", "guarda roupa", "armario", "balcao", "comoda", "lixeira", "jogo de jantar", "sala de jantar", "travesseiro", "mixer", "liquidificador", "batedeira", "eletroportatil", "porta escova", "saboneteira", "purificador", "filtro", "tinta", "ferramenta", "bolsa ferramenta", "bolsa de ferramenta"))
        {
            return WhatsAppNicheDefinitions.Casa;
        }

        if (!ContainsAny(text, "bolsa ferramenta", "bolsa de ferramenta", "tinta")
            && ContainsAny(text, "calca", "tenis", "meia", "cueca", "camiseta", "camisa", "bolsa", "mochila", "sandalia", "vestido", "pijama", "sobretudo", "kimono", "blusa", "tricot", "terno", "paleto", "blazer", "lupo", "puma", "kappa", "reebok", "calvin klein"))
        {
            return WhatsAppNicheDefinitions.Moda;
        }

        return null;
    }

    private static string? ResolveStore(string? offerId, string text)
    {
        if (offerId?.StartsWith("ML-", StringComparison.OrdinalIgnoreCase) == true || text.Contains("Mercado Livre", StringComparison.OrdinalIgnoreCase))
        {
            return "Mercado Livre";
        }

        if (offerId?.StartsWith("SP-", StringComparison.OrdinalIgnoreCase) == true || text.Contains("Shopee", StringComparison.OrdinalIgnoreCase))
        {
            return "Shopee";
        }

        if (offerId?.StartsWith("AM-", StringComparison.OrdinalIgnoreCase) == true || text.Contains("Amazon", StringComparison.OrdinalIgnoreCase))
        {
            return "Amazon";
        }

        return null;
    }

    private static string? ExtractPrice(string text)
    {
        var labelled = PriceLabelRegex().Match(text);
        if (labelled.Success)
        {
            return labelled.Groups[1].Value.Trim();
        }

        var price = PriceRegex().Match(text);
        return price.Success ? price.Value.Trim() : null;
    }

    private static string? ExtractCommission(string text)
    {
        var match = CommissionRegex().Match(text);
        return match.Success ? match.Groups[1].Value.Trim() : null;
    }

    private async Task EnsureSeenLoadedAsync(CancellationToken ct)
    {
        if (_loaded || _seen.Count > 0)
        {
            return;
        }

        var path = SeenPath();
        if (!File.Exists(path))
        {
            return;
        }

        var values = JsonSerializer.Deserialize<string[]>(await File.ReadAllTextAsync(path, ct)) ?? [];
        foreach (var value in values)
        {
            _seen.Add(value);
        }

        _loaded = true;
    }

    private async Task SaveSeenAsync(CancellationToken ct)
    {
        var path = SeenPath();
        Directory.CreateDirectory(Path.GetDirectoryName(path) ?? AppContext.BaseDirectory);
        var values = _seen.TakeLast(5000).ToArray();
        await File.WriteAllTextAsync(path, JsonSerializer.Serialize(values), ct);
    }

    private string SeenPath()
        => Path.Combine(ResolveDataRoot(), "whatsapp-niche-auto-route-seen.json");

    private string ResolveDataRoot()
    {
        foreach (var candidate in new[] { @"D:\Achadinhos\data", @"C:\Achadinhos\data" })
        {
            if (Directory.Exists(candidate))
            {
                return candidate;
            }
        }

        return Path.Combine(_environment.ContentRootPath, "data");
    }

    private static bool ContainsAny(string text, params string[] terms)
        => terms.Any(term => text.Contains(term, StringComparison.OrdinalIgnoreCase));

    private static string Normalize(string value)
    {
        var normalized = value.Normalize(System.Text.NormalizationForm.FormD).ToLowerInvariant();
        return new string(normalized.Where(ch => System.Globalization.CharUnicodeInfo.GetUnicodeCategory(ch) != System.Globalization.UnicodeCategory.NonSpacingMark).ToArray());
    }

    private static bool LooksLikeGenericPromoLine(string normalized)
        => ContainsAny(
            normalized,
            "para deixar o link ativo",
            "sei que voce precisa",
            "e uma cozinha toda nova",
            "pra quem quer ter",
            "unico cardio",
            "corre aqui antes",
            "achadinho mercado livre selecionado");

    [GeneratedRegex(@"https?://[^\s]+", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex UrlRegex();

    [GeneratedRegex(@"https?://[^/]+/r/([^?\s]+)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex TrackingRegex();

    [GeneratedRegex(@"Link produto:\s*(https?://[^\s]+)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex LinkProdutoRegex();

    [GeneratedRegex(@"(?im)(?:pegar oferta|compre aqui|comprar aqui|ver oferta|link do produto|link produto|produto|oferta)[^\r\n]*?(?<url>https?://[^\s]+)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex OfferCtaUrlRegex();

    [GeneratedRegex(@"Achadinho Mercado Livre selecionado!\*\s*\r?\n\r?\n\*(?<title>.+?)\*", RegexOptions.IgnoreCase | RegexOptions.Singleline | RegexOptions.CultureInvariant)]
    private static partial Regex ScoutTitleRegex();

    [GeneratedRegex(@"\*(?<title>[^*\r\n]{8,160})\*", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex BoldLineRegex();

    [GeneratedRegex(@"Pre[cç]o:\s*\*?([^*\r\n]+)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex PriceLabelRegex();

    [GeneratedRegex(@"R\$\s*[0-9.]+,[0-9]{2}", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex PriceRegex();

    [GeneratedRegex(@"^\s*(?:[^\p{L}\p{N}]*\s*)?R\$\s*[0-9.]+,[0-9]{2}\s*$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex PriceOnlyRegex();

    [GeneratedRegex(@"Comiss[aã]o da oferta:\s*\*?([^*\r\n]+)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex CommissionRegex();
    [GeneratedRegex(@"(?:^|\r?\n)\s*📊\s*Comiss[aã]o da oferta:\s*\*?[^*\r\n]+\*?\s*(?:\r?\n)?", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex ScoutCommissionLineRegex();
}
