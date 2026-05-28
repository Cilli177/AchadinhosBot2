using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Domain.Logs;

namespace AchadinhosBot.Next.Application.Services;

public sealed class WhatsAppNicheAiReviewService
{
    private static readonly HashSet<string> AutoReviewReasons =
    [
        "auto_route_missing_product_or_niche",
        "missing_image_for_niche_send",
        "nicho_ambiguo_requer_revisao"
    ];

    private readonly ISettingsStore _settingsStore;
    private readonly WhatsAppNicheAiClassifier _classifier;
    private readonly WhatsAppNicheGroupService _groupService;

    public WhatsAppNicheAiReviewService(
        ISettingsStore settingsStore,
        WhatsAppNicheAiClassifier classifier,
        WhatsAppNicheGroupService groupService)
    {
        _settingsStore = settingsStore;
        _classifier = classifier;
        _groupService = groupService;
    }

    public async Task<WhatsAppNicheAiReviewBatchResult> ReviewPendingAsync(WhatsAppNicheAiReviewBatchRequest request, CancellationToken ct)
    {
        var limit = Math.Clamp(request.Limit ?? 30, 1, 100);
        var minConfidence = Math.Clamp(request.MinConfidence ?? 85, 1, 100);
        var settings = await _settingsStore.GetAsync(ct);
        var pending = await _groupService.ListReviewsAsync("pending", limit, ct);
        var results = new List<WhatsAppNicheAiReviewItemResult>();

        foreach (var review in pending.Where(IsAutoReviewCandidate))
        {
            var text = BuildReviewText(review);
            var policyDecision = TryResolvePolicyDecision(text, review.ProductName);
            if (policyDecision is not null)
            {
                if (request.DryRun != false)
                {
                    results.Add(WhatsAppNicheAiReviewItemResult.Prepared(review, policyDecision.Slugs, policyDecision.Decision));
                    continue;
                }

                var policyRouteResults = await _groupService.ApproveReviewAsync(review.Id, policyDecision.Slugs, ct) ?? [];
                results.Add(WhatsAppNicheAiReviewItemResult.Approved(review, policyDecision.Slugs, policyDecision.Decision, policyRouteResults));
                continue;
            }

            var decision = await _classifier.ClassifyAsync(text, review.ProductName, settings, ct);
            if (decision is null)
            {
                results.Add(WhatsAppNicheAiReviewItemResult.Kept(review, "ai_sem_decisao", null, null));
                continue;
            }

            if (decision.RequiresReview
                || string.IsNullOrWhiteSpace(decision.Slug)
                || string.IsNullOrWhiteSpace(decision.ProductName)
                || decision.Confidence < minConfidence)
            {
                results.Add(WhatsAppNicheAiReviewItemResult.Kept(review, decision.Reason, decision.Slug, decision));
                continue;
            }

            var slugs = ResolveHybridSlugs(decision.Slug, decision.ProductName);
            if (request.DryRun != false)
            {
                results.Add(WhatsAppNicheAiReviewItemResult.Prepared(review, slugs, decision));
                continue;
            }

            var routeResults = await _groupService.ApproveReviewAsync(review.Id, slugs, ct) ?? [];
            results.Add(WhatsAppNicheAiReviewItemResult.Approved(review, slugs, decision, routeResults));
        }

        return new WhatsAppNicheAiReviewBatchResult(
            request.DryRun != false,
            results.Count,
            results.Count(x => x.Action == "approved"),
            results.Count(x => x.Action == "prepared"),
            results.Count(x => x.Action == "kept"),
            results);
    }

    private static bool IsAutoReviewCandidate(WhatsAppNicheReviewItem item)
        => AutoReviewReasons.Contains(item.Reason)
           && !LooksLikeBlockedContext($"{item.ProductName}\n{item.OriginalText}");

    private static string BuildReviewText(WhatsAppNicheReviewItem review)
        => string.Join("\n", new[]
        {
            $"Produto conhecido: {review.ProductName ?? "(ausente)"}",
            $"Preco: {review.PriceText ?? "(ausente)"}",
            $"Loja: {review.StoreName ?? "(ausente)"}",
            $"Link principal: {review.ProductUrl ?? "(ausente)"}",
            $"Imagem: {(string.IsNullOrWhiteSpace(review.ImageUrl) ? "(ausente)" : review.ImageUrl)}",
            "Anuncio completo:",
            review.OriginalText
        }.Where(x => !string.IsNullOrWhiteSpace(x)));

    private static IReadOnlyList<string> ResolveHybridSlugs(string slug, string productName)
    {
        var slugs = new List<string> { slug };
        var normalized = Normalize(productName);
        if (ContainsAny(normalized, "smart tv", "televisao", "tv ", "caixa de som", "soundbar", "lixeira inteligente", "lixeira com sensor", "aspirador robo", "smart home"))
        {
            Add(slugs, WhatsAppNicheDefinitions.Casa);
            Add(slugs, WhatsAppNicheDefinitions.Tech);
        }

        if (ContainsAny(normalized, "cadeira gamer", "cadeira de escritorio", "cadeira ergonomica", "cadeira executiva"))
        {
            Add(slugs, WhatsAppNicheDefinitions.Casa);
            Add(slugs, WhatsAppNicheDefinitions.Tech);
        }

        return slugs;
    }

    private static WhatsAppNicheAiPolicyDecision? TryResolvePolicyDecision(string text, string? productName)
    {
        var normalized = Normalize(text);
        var title = FirstMeaningfulTitle(productName, ExtractProductNameFromText(text));

        if (LooksLikeCupomGenerico(normalized, text))
        {
            return NewPolicyDecision(
                title ?? "Cupom de desconto",
                AllAudienceSlugs(),
                "cupom_amplo_liberado",
                "Cupom liberado para todos os grupos ativos de teste.");
        }

        if (ContainsAny(normalized, "album figurinha", "album de figurinha", "album copa", "figurinhas copa", "figurinhas oficial copa", "panini copa", "copa do mundo 2026"))
        {
            return NewPolicyDecision(
                title ?? "Album e figurinhas Copa do Mundo 2026",
                AllAudienceSlugs(),
                "copa_figurinhas_amplo",
                "Album/figurinhas de Copa liberado como chamariz para todos os grupos.");
        }

        if (ContainsAny(normalized, "bicicleta eletrica", "bike eletrica", "bici eletrica"))
        {
            return NewPolicyDecision(
                title ?? "Bicicleta eletrica",
                [WhatsAppNicheDefinitions.Tech],
                "mobilidade_eletrica_tech",
                "Bicicleta eletrica tratada como tech/mobilidade.");
        }

        if (ContainsAny(normalized, "vodka man", "whisky silver perfume"))
        {
            return null;
        }

        if (ContainsAny(normalized, "vinho", "whisky", "cerveja") || ContainsWholeWordAny(normalized, "gin", "vodka"))
        {
            return NewPolicyDecision(
                title ?? "Bebida em oferta",
                [WhatsAppNicheDefinitions.Casa],
                "bebida_em_casa_temporario",
                "Bebidas ficam em casa temporariamente ate criar nicho proprio.");
        }

        if (ContainsAny(normalized, "cafe", "achocolatado", "alimento", "supermercado", "graos", "grao", "amaciante", "detergente", "sabao", "limpeza"))
        {
            return NewPolicyDecision(
                title ?? "Produto de mercado",
                [WhatsAppNicheDefinitions.Casa],
                "mercado_em_casa_temporario",
                "Alimentos/mercado ficam em casa temporariamente.");
        }

        return null;
    }

    private static WhatsAppNicheAiPolicyDecision NewPolicyDecision(string productName, IReadOnlyList<string> slugs, string reason, string detail)
        => new(new WhatsAppNicheAiDecision(productName, slugs[0], 100, $"{reason}: {detail}", false, "policy"), slugs);

    private static IReadOnlyList<string> AllAudienceSlugs()
        =>
        [
            WhatsAppNicheDefinitions.Casa,
            WhatsAppNicheDefinitions.Beleza,
            WhatsAppNicheDefinitions.FitnessHealth,
            WhatsAppNicheDefinitions.Moda,
            WhatsAppNicheDefinitions.Tech
        ];

    private static void Add(List<string> slugs, string slug)
    {
        if (!slugs.Contains(slug, StringComparer.OrdinalIgnoreCase))
        {
            slugs.Add(slug);
        }
    }

    private static bool LooksLikeBlockedContext(string text)
    {
        var normalized = Normalize(text);
        if (ContainsAny(normalized, "vodka man", "whisky silver perfume"))
        {
            return false;
        }

        return ContainsAny(
            normalized,
            "pneu ", "goodyear", "automotivo");
    }

    private static bool LooksLikeCupomGenerico(string normalized, string originalText)
        => ContainsAny(normalized, "cupom de desconto", "cupom amazon", "cupom mercado livre", "cupons mercado livre", "cupom shopee", "cupons shopee", "cupom generico", "cupom app", "cupom de 10 off", "cupom de 10%")
           || (ContainsAny(normalized, "cupom", "resgate o cupom", "use o cupom")
               && !HasConcreteProductLine(originalText));

    private static bool HasConcreteProductLine(string text)
        => text.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(line => line.Trim().Trim('*'))
            .Any(line =>
                line.Length >= 16
                && line.Any(char.IsLetter)
                && !line.StartsWith("R$", StringComparison.OrdinalIgnoreCase)
                && !line.StartsWith("De:", StringComparison.OrdinalIgnoreCase)
                && !line.StartsWith("Por:", StringComparison.OrdinalIgnoreCase)
                && !line.StartsWith("Cupom", StringComparison.OrdinalIgnoreCase)
                && !line.StartsWith("Resgate", StringComparison.OrdinalIgnoreCase)
                && !line.StartsWith("Use o cupom", StringComparison.OrdinalIgnoreCase)
                && !line.StartsWith("http", StringComparison.OrdinalIgnoreCase)
                && !line.Contains("reidasofertas.ia.br", StringComparison.OrdinalIgnoreCase)
                && !line.Contains("mais ofertas", StringComparison.OrdinalIgnoreCase)
                && !line.Contains("destaques", StringComparison.OrdinalIgnoreCase));

    private static string? ExtractProductNameFromText(string text)
    {
        foreach (var raw in text.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var line = TrimProductLine(raw);
            if (line.Length < 8
                || line.StartsWith("R$", StringComparison.OrdinalIgnoreCase)
                || line.Contains("R$", StringComparison.OrdinalIgnoreCase)
                || line.StartsWith("Produto conhecido:", StringComparison.OrdinalIgnoreCase)
                || line.StartsWith("Preco:", StringComparison.OrdinalIgnoreCase)
                || line.StartsWith("Preço:", StringComparison.OrdinalIgnoreCase)
                || line.StartsWith("Loja:", StringComparison.OrdinalIgnoreCase)
                || line.StartsWith("Link principal:", StringComparison.OrdinalIgnoreCase)
                || line.StartsWith("Imagem:", StringComparison.OrdinalIgnoreCase)
                || line.StartsWith("Anuncio completo:", StringComparison.OrdinalIgnoreCase)
                || line.StartsWith("Anúncio completo:", StringComparison.OrdinalIgnoreCase)
                || line.StartsWith("De:", StringComparison.OrdinalIgnoreCase)
                || line.StartsWith("Por:", StringComparison.OrdinalIgnoreCase)
                || line.StartsWith("Cupom", StringComparison.OrdinalIgnoreCase)
                || line.StartsWith("http", StringComparison.OrdinalIgnoreCase)
                || line.Contains("reidasofertas.ia.br", StringComparison.OrdinalIgnoreCase)
                || IsLikelySlogan(line))
            {
                continue;
            }

            return line;
        }

        return null;
    }

    private static bool IsLikelySlogan(string line)
        => line.Length <= 42
           && line.Any(char.IsLetter)
           && !line.Any(char.IsLower)
           && !ContainsAny(Normalize(line), "mlb", "iphone", "samsung", "philco", "electrolux", "brastemp", "tramontina");

    private static string TrimProductLine(string value)
    {
        var line = value.Trim().Trim('*', ' ');
        while (line.Length > 0)
        {
            var category = char.GetUnicodeCategory(line, 0);
            if (char.IsLetterOrDigit(line, 0) || category == System.Globalization.UnicodeCategory.CurrencySymbol)
            {
                break;
            }

            line = line[1..].TrimStart();
        }

        return line.Trim();
    }

    private static string? FirstNonEmpty(params string?[] values)
        => values.FirstOrDefault(x => !string.IsNullOrWhiteSpace(x))?.Trim();

    private static string? FirstMeaningfulTitle(string? productName, string? extractedTitle)
    {
        if (!string.IsNullOrWhiteSpace(productName) && !IsGenericProductName(productName))
        {
            return productName.Trim();
        }

        if (!string.IsNullOrWhiteSpace(extractedTitle) && !IsGenericProductName(extractedTitle))
        {
            return extractedTitle.Trim();
        }

        return FirstNonEmpty(productName, extractedTitle);
    }

    private static bool IsGenericProductName(string value)
        => ContainsAny(Normalize(value), "produto conhecido", "ausente", "mercado livre", "amazon", "shopee", "cupom de desconto", "cupons shopee", "cupom mercado livre");

    private static bool ContainsAny(string text, params string[] terms)
        => terms.Any(term => text.Contains(term, StringComparison.OrdinalIgnoreCase));

    private static bool ContainsWholeWordAny(string text, params string[] terms)
    {
        var tokens = text.Split(new[] { ' ', '\r', '\n', '\t', '.', ',', ';', ':', '/', '\\', '-', '_', '|', '(', ')', '[', ']', '{', '}', '!', '?' }, StringSplitOptions.RemoveEmptyEntries);
        return terms.Any(term => tokens.Contains(term, StringComparer.OrdinalIgnoreCase));
    }

    private static string Normalize(string value)
    {
        value = new string(value.Where(ch => !char.IsSurrogate(ch)).ToArray());
        var normalized = value.Normalize(System.Text.NormalizationForm.FormD).ToLowerInvariant();
        return new string(normalized.Where(ch => System.Globalization.CharUnicodeInfo.GetUnicodeCategory(ch) != System.Globalization.UnicodeCategory.NonSpacingMark).ToArray());
    }
}

public sealed record WhatsAppNicheAiReviewBatchRequest(bool? DryRun, int? Limit, int? MinConfidence);

public sealed record WhatsAppNicheAiPolicyDecision(WhatsAppNicheAiDecision Decision, IReadOnlyList<string> Slugs);

public sealed record WhatsAppNicheAiReviewBatchResult(
    bool DryRun,
    int Total,
    int Approved,
    int Prepared,
    int Kept,
    IReadOnlyList<WhatsAppNicheAiReviewItemResult> Items);

public sealed record WhatsAppNicheAiReviewItemResult(
    string ReviewId,
    string Action,
    string Reason,
    string? SuggestedSlug,
    IReadOnlyList<string> Slugs,
    string? ProductName,
    int? Confidence,
    IReadOnlyList<WhatsAppNicheRouteResult> RouteResults)
{
    public static WhatsAppNicheAiReviewItemResult Kept(WhatsAppNicheReviewItem review, string reason, string? suggestedSlug, WhatsAppNicheAiDecision? decision)
        => new(
            review.Id,
            "kept",
            reason,
            suggestedSlug,
            [],
            decision?.ProductName ?? review.ProductName,
            decision?.Confidence,
            []);

    public static WhatsAppNicheAiReviewItemResult Prepared(WhatsAppNicheReviewItem review, IReadOnlyList<string> slugs, WhatsAppNicheAiDecision decision)
        => new(review.Id, "prepared", decision.Reason, decision.Slug, slugs, decision.ProductName, decision.Confidence, []);

    public static WhatsAppNicheAiReviewItemResult Approved(WhatsAppNicheReviewItem review, IReadOnlyList<string> slugs, WhatsAppNicheAiDecision decision, IReadOnlyList<WhatsAppNicheRouteResult> routeResults)
        => new(review.Id, "approved", decision.Reason, decision.Slug, slugs, decision.ProductName, decision.Confidence, routeResults);
}
