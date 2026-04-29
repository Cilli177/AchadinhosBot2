using System.Text;
using System.Text.RegularExpressions;
using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Configuration;
using AchadinhosBot.Next.Domain.Settings;
using AchadinhosBot.Next.Infrastructure.ProductData;
using AchadinhosBot.Next.Infrastructure.Media;
using Microsoft.Extensions.Options;

namespace AchadinhosBot.Next.Infrastructure.Instagram;

public sealed class InstagramPostComposer : IInstagramPostComposer
{
    private static readonly Regex UrlRegex = new(@"https?://[^\s]+", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
    private readonly IMessageProcessor _messageProcessor;
    private readonly ICouponSelector _couponSelector;
    private readonly OpenAiInstagramPostGenerator _openAiGenerator;
    private readonly GeminiInstagramPostGenerator _geminiGenerator;
    private readonly DeepSeekInstagramPostGenerator _deepSeekGenerator;
    private readonly NemotronInstagramPostGenerator _nemotronGenerator;
    private readonly QwenInstagramPostGenerator _qwenGenerator;
    private readonly VilaNvidiaGenerator _vilaGenerator;
    private readonly ISettingsStore _settingsStore;
    private readonly OfficialProductDataService _officialProductDataService;
    private readonly IPromotionalCardGenerator _promotionalCardGenerator;
    private readonly IMediaStore _mediaStore;
    private readonly WebhookOptions _webhookOptions;

    public InstagramPostComposer(
        IMessageProcessor messageProcessor,
        ICouponSelector couponSelector,
        OpenAiInstagramPostGenerator openAiGenerator,
        GeminiInstagramPostGenerator geminiGenerator,
        DeepSeekInstagramPostGenerator deepSeekGenerator,
        NemotronInstagramPostGenerator nemotronGenerator,
        QwenInstagramPostGenerator qwenGenerator,
        VilaNvidiaGenerator vilaGenerator,
        ISettingsStore settingsStore,
        OfficialProductDataService officialProductDataService,
        IPromotionalCardGenerator promotionalCardGenerator,
        IMediaStore mediaStore,
        IOptions<WebhookOptions> webhookOptions)
    {
        _messageProcessor = messageProcessor;
        _couponSelector = couponSelector;
        _openAiGenerator = openAiGenerator;
        _geminiGenerator = geminiGenerator;
        _deepSeekGenerator = deepSeekGenerator;
        _nemotronGenerator = nemotronGenerator;
        _qwenGenerator = qwenGenerator;
        _vilaGenerator = vilaGenerator;
        _settingsStore = settingsStore;
        _officialProductDataService = officialProductDataService;
        _promotionalCardGenerator = promotionalCardGenerator;
        _mediaStore = mediaStore;
        _webhookOptions = webhookOptions.Value;
    }

    public async Task<string> BuildAsync(string productInput, string? offerContext, InstagramPostSettings settings, CancellationToken cancellationToken)
    {
        var input = productInput?.Trim() ?? string.Empty;
        input = StripTriggerPrefix(input, settings.Triggers);
        if (string.IsNullOrWhiteSpace(input))
        {
            return "N\u00e3o consegui identificar o produto. Envie o nome ou o link.";
        }

        var baseText = input;
        string? link = null;
        if (UrlRegex.IsMatch(input))
        {
            var result = await _messageProcessor.ProcessAsync(input, "InstagramPost", cancellationToken);
            baseText = result.ConvertedText ?? input;
            link = ExtractFirstUrl(baseText);
        }

        var allSettings = await _settingsStore.GetAsync(cancellationToken);
        var couponLine = await BuildCouponLineAsync(allSettings, link, cancellationToken);

        OfficialProductDataResult? officialData = null;
        if (!string.IsNullOrWhiteSpace(link) || !string.IsNullOrWhiteSpace(input))
        {
            officialData = await _officialProductDataService.TryGetBestAsync(input, link, cancellationToken);
        }
        if (officialData is null && !string.IsNullOrWhiteSpace(offerContext))
        {
            officialData = await _officialProductDataService.TryGetBestAsync(offerContext, null, cancellationToken);
        }

        if (settings.UseAi)
        {
            var openAi = allSettings.OpenAI ?? new OpenAISettings();
            var gemini = allSettings.Gemini ?? new GeminiSettings();
            var gemma4 = GeminiInstagramPostGenerator.WithGeminiKeyFallback(allSettings.Gemma4, allSettings.Gemini);
            var deepSeek = allSettings.DeepSeek ?? new DeepSeekSettings();
            var nemotron = allSettings.Nemotron ?? new NemotronSettings();
            var qwen = allSettings.Qwen ?? new QwenSettings();
            var vila = allSettings.VilaNvidia ?? new VilaNvidiaSettings();

            var provider = string.IsNullOrWhiteSpace(settings.AiProvider) ? "gemini" : settings.AiProvider.Trim().ToLowerInvariant();
            var results = new List<string>();
            var openAiResult = string.Empty;
            var geminiResult = string.Empty;
            var gemma4Result = string.Empty;
            var deepSeekResult = string.Empty;
            var nemotronResult = string.Empty;
            var qwenResult = string.Empty;
            var vilaResult = string.Empty;

            if (provider is "deepseek")
            {
                deepSeekResult = (await _deepSeekGenerator.GenerateAsync(input, offerContext, link, settings, deepSeek, cancellationToken))?.Trim() ?? string.Empty;
                if (!string.IsNullOrWhiteSpace(deepSeekResult))
                {
                    results.Add(deepSeekResult);
                }
            }

            if (provider is "nemotron")
            {
                nemotronResult = (await _nemotronGenerator.GenerateAsync(input, offerContext, link, settings, nemotron, cancellationToken))?.Trim() ?? string.Empty;
                if (!string.IsNullOrWhiteSpace(nemotronResult))
                {
                    results.Add(nemotronResult);
                }
            }

            if (provider is "qwen")
            {
                qwenResult = (await _qwenGenerator.GenerateAsync(input, offerContext, link, settings, qwen, cancellationToken))?.Trim() ?? string.Empty;
                if (!string.IsNullOrWhiteSpace(qwenResult))
                {
                    results.Add(qwenResult);
                }
            }

            if (provider is "vila")
            {
                vilaResult = (await _vilaGenerator.GenerateFreeformAsync(string.Join("\n\n", new[] { input, offerContext, link }.Where(x => !string.IsNullOrWhiteSpace(x))), vila, cancellationToken))?.Trim() ?? string.Empty;
                if (!string.IsNullOrWhiteSpace(vilaResult))
                {
                    results.Add(vilaResult);
                }
            }

            if (provider is "openai" or "both" && results.Count == 0)
            {
                openAiResult = (await _openAiGenerator.GenerateAsync(input, offerContext, link, settings, openAi, cancellationToken))?.Trim() ?? string.Empty;
                if (!string.IsNullOrWhiteSpace(openAiResult))
                {
                    results.Add(provider == "both" ? $"=== OPENAI ===\n{openAiResult}" : openAiResult);
                }
            }

            if (provider is "gemini" or "both")
            {
                geminiResult = (await _geminiGenerator.GenerateAsync(input, offerContext, link, settings, gemini, cancellationToken))?.Trim() ?? string.Empty;
                if (!string.IsNullOrWhiteSpace(geminiResult))
                {
                    results.Add(provider == "both" ? $"=== GEMINI ===\n{geminiResult}" : geminiResult);
                }
            }

            if (provider is "gemma4")
            {
                gemma4Result = (await _geminiGenerator.GenerateAsync(input, offerContext, link, settings, gemma4, cancellationToken))?.Trim() ?? string.Empty;
                if (!string.IsNullOrWhiteSpace(gemma4Result))
                {
                    results.Add(gemma4Result);
                }
            }

            if (provider is "all")
            {
                openAiResult = (await _openAiGenerator.GenerateAsync(input, offerContext, link, settings, openAi, cancellationToken))?.Trim() ?? string.Empty;
                if (!string.IsNullOrWhiteSpace(openAiResult))
                {
                    results.Add($"=== OPENAI ===\n{openAiResult}");
                }

                geminiResult = (await _geminiGenerator.GenerateAsync(input, offerContext, link, settings, gemini, cancellationToken))?.Trim() ?? string.Empty;
                if (!string.IsNullOrWhiteSpace(geminiResult))
                {
                    results.Add($"=== GEMINI ===\n{geminiResult}");
                }

                gemma4Result = (await _geminiGenerator.GenerateAsync(input, offerContext, link, settings, gemma4, cancellationToken))?.Trim() ?? string.Empty;
                if (!string.IsNullOrWhiteSpace(gemma4Result))
                {
                    results.Add($"=== GEMMA4 ===\n{gemma4Result}");
                }

                vilaResult = (await _vilaGenerator.GenerateFreeformAsync(string.Join("\n\n", new[] { input, offerContext, link }.Where(x => !string.IsNullOrWhiteSpace(x))), vila, cancellationToken))?.Trim() ?? string.Empty;
                if (!string.IsNullOrWhiteSpace(vilaResult))
                {
                    results.Add($"=== VILA ===\n{vilaResult}");
                }

                deepSeekResult = (await _deepSeekGenerator.GenerateAsync(input, offerContext, link, settings, deepSeek, cancellationToken))?.Trim() ?? string.Empty;
                if (!string.IsNullOrWhiteSpace(deepSeekResult))
                {
                    results.Add($"=== DEEPSEEK ===\n{deepSeekResult}");
                }

                nemotronResult = (await _nemotronGenerator.GenerateAsync(input, offerContext, link, settings, nemotron, cancellationToken))?.Trim() ?? string.Empty;
                if (!string.IsNullOrWhiteSpace(nemotronResult))
                {
                    results.Add($"=== NEMOTRON ===\n{nemotronResult}");
                }

                qwenResult = (await _qwenGenerator.GenerateAsync(input, offerContext, link, settings, qwen, cancellationToken))?.Trim() ?? string.Empty;
                if (!string.IsNullOrWhiteSpace(qwenResult))
                {
                    results.Add($"=== QWEN ===\n{qwenResult}");
                }
            }

            // Fallback cruzado: prioriza Nemotron como motor principal e usa os demais como reserva.
            if (results.Count == 0)
            {
                if (!string.IsNullOrWhiteSpace(nemotron.ApiKey) && nemotron.ApiKey != "********")
                {
                    nemotronResult = (await _nemotronGenerator.GenerateAsync(input, offerContext, link, settings, nemotron, cancellationToken))?.Trim() ?? string.Empty;
                    if (!string.IsNullOrWhiteSpace(nemotronResult))
                    {
                        results.Add(nemotronResult);
                    }
                }

                if (results.Count == 0 && !string.IsNullOrWhiteSpace(deepSeek.ApiKey) && deepSeek.ApiKey != "********")
                {
                    deepSeekResult = (await _deepSeekGenerator.GenerateAsync(input, offerContext, link, settings, deepSeek, cancellationToken))?.Trim() ?? string.Empty;
                    if (!string.IsNullOrWhiteSpace(deepSeekResult))
                    {
                        results.Add(deepSeekResult);
                    }
                }

                if (results.Count == 0 && provider == "gemini")
                {
                    openAiResult = (await _openAiGenerator.GenerateAsync(input, offerContext, link, settings, openAi, cancellationToken))?.Trim() ?? string.Empty;
                    if (!string.IsNullOrWhiteSpace(openAiResult))
                    {
                        results.Add(openAiResult);
                    }
                }
                else if (results.Count == 0 && provider == "openai")
                {
                    geminiResult = (await _geminiGenerator.GenerateAsync(input, offerContext, link, settings, gemini, cancellationToken))?.Trim() ?? string.Empty;
                    if (!string.IsNullOrWhiteSpace(geminiResult))
                    {
                        results.Add(geminiResult);
                    }
                }
                else if (results.Count == 0 && provider == "nemotron")
                {
                    deepSeekResult = (await _deepSeekGenerator.GenerateAsync(input, offerContext, link, settings, deepSeek, cancellationToken))?.Trim() ?? string.Empty;
                    if (!string.IsNullOrWhiteSpace(deepSeekResult))
                    {
                        results.Add(deepSeekResult);
                    }
                }
                else if (results.Count == 0 && provider == "qwen")
                {
                    nemotronResult = (await _nemotronGenerator.GenerateAsync(input, offerContext, link, settings, nemotron, cancellationToken))?.Trim() ?? string.Empty;
                    if (!string.IsNullOrWhiteSpace(nemotronResult))
                    {
                        results.Add(nemotronResult);
                    }
                }

                if (results.Count == 0 && provider != "openai")
                {
                    openAiResult = (await _openAiGenerator.GenerateAsync(input, offerContext, link, settings, openAi, cancellationToken))?.Trim() ?? string.Empty;
                    if (!string.IsNullOrWhiteSpace(openAiResult))
                    {
                        results.Add(openAiResult);
                    }
                }

                if (results.Count == 0 && provider != "gemini")
                {
                    geminiResult = (await _geminiGenerator.GenerateAsync(input, offerContext, link, settings, gemini, cancellationToken))?.Trim() ?? string.Empty;
                    if (!string.IsNullOrWhiteSpace(geminiResult))
                    {
                        results.Add(geminiResult);
                    }
                }

                if (results.Count == 0 && provider != "qwen")
                {
                    qwenResult = (await _qwenGenerator.GenerateAsync(input, offerContext, link, settings, qwen, cancellationToken))?.Trim() ?? string.Empty;
                    if (!string.IsNullOrWhiteSpace(qwenResult))
                    {
                        results.Add(qwenResult);
                    }
                }

                if (results.Count == 0 && provider != "vila")
                {
                    vilaResult = (await _vilaGenerator.GenerateFreeformAsync(string.Join("\n\n", new[] { input, offerContext, link }.Where(x => !string.IsNullOrWhiteSpace(x))), vila, cancellationToken))?.Trim() ?? string.Empty;
                    if (!string.IsNullOrWhiteSpace(vilaResult))
                    {
                        results.Add(vilaResult);
                    }
                }
            }

            if (results.Count > 0)
            {
                var merged = string.Join("\n\n", results);
                if (allSettings.CouponHub.Enabled && allSettings.CouponHub.AppendToInstagramCaptions && !string.IsNullOrWhiteSpace(couponLine))
                {
                    merged += $"\n\nCupom recomendado: {couponLine}";
                }

                if (officialData is not null)
                {
                    try
                    {
                        var discountText = officialData.DiscountPercent > 0 ? $"-{officialData.DiscountPercent}%" : null;
                        var cardBytes = await _promotionalCardGenerator.GenerateCardAsync(
                            officialData.Title ?? "Oferta Especial",
                            officialData.CurrentPrice ?? "Confira",
                            officialData.PreviousPrice,
                            discountText,
                            officialData.Images?.FirstOrDefault() ?? string.Empty,
                            cancellationToken);
                        
                        if (cardBytes is not null && cardBytes.Length > 0)
                        {
                            var mediaId = _mediaStore.Add(cardBytes, "image/jpeg");
                            var port = _webhookOptions.Port <= 0 ? 5000 : _webhookOptions.Port;
                            var mediaUrl = !string.IsNullOrWhiteSpace(_webhookOptions.PublicBaseUrl)
                                ? _webhookOptions.PublicBaseUrl.TrimEnd('/') + $"/media/{mediaId}"
                                : $"http://localhost:{port}/media/{mediaId}";
                            
                            merged += $"\n\n[Cartão Promocional Gerado: {mediaUrl}]";
                        }
                    }
                    catch
                    {
                        // Ignore generation errors to not crash the AI generation flow
                    }
                }

                return merged;
            }

            return "Nao consegui gerar legenda com IA no momento. Tente novamente em instantes.";
        }

        var cleanBaseText = RemoveCouponAppendix(baseText);
        var productName = RemoveUrls(cleanBaseText);
        if (string.IsNullOrWhiteSpace(productName))
        {
            productName = "Produto em destaque";
        }

        var sb = new StringBuilder();
        sb.AppendLine("POST PARA INSTAGRAM");
        sb.AppendLine($"Produto: {productName.Trim()}");
        if (!string.IsNullOrWhiteSpace(link))
        {
            sb.AppendLine($"Link afiliado: {link}");
        }
        sb.AppendLine();

        var variations = Math.Clamp(settings.VariationsCount, 1, 5);
        var captionCandidates = new List<(int Index, string Caption, int Score)>();
        
        for (var i = 0; i < variations; i++)
        {
            var caption = BuildCaptionVariation(productName, link, i, couponLine, officialData);
            var score = ScoreCaption(caption);
            captionCandidates.Add((i + 1, caption, score));

            sb.AppendLine($"Legenda {i + 1} (pronta para copiar):");
            sb.AppendLine(caption);
            sb.AppendLine();
        }

        if (captionCandidates.Count > 0)
        {
            var best = captionCandidates
                .OrderByDescending(x => x.Score)
                .ThenBy(x => x.Index)
                .First();
            sb.AppendLine($"Melhor varia\u00e7\u00e3o sugerida: Legenda {best.Index} (score {best.Score})");
            sb.AppendLine();
        }

        sb.AppendLine("Hashtags sugeridas:");
        sb.AppendLine(BuildHashtags(productName));
        sb.AppendLine();
        sb.AppendLine("Sugest\u00f5es de imagem:");
        sb.AppendLine(BuildImageIdeas(productName));

        var contextMode = settings.OfferContextMode;
        if (contextMode == InstagramOfferContextMode.Off && settings.UseOfferContext)
        {
            contextMode = InstagramOfferContextMode.ExtraPost;
        }

        if (!string.IsNullOrWhiteSpace(offerContext) &&
            !string.Equals(offerContext, productInput, StringComparison.OrdinalIgnoreCase))
        {
            if (contextMode == InstagramOfferContextMode.Suggestion)
            {
                sb.AppendLine();
                sb.AppendLine("Sugest\u00e3o r\u00e1pida (baseado na oferta):");
                sb.AppendLine(BuildContextSuggestion(offerContext!));
            }
            else if (contextMode == InstagramOfferContextMode.ExtraPost)
            {
                sb.AppendLine();
                sb.AppendLine("Post extra (baseado na oferta):");
                sb.AppendLine(BuildContextCaption(productName, offerContext!, link));
            }
        }

        if (!string.IsNullOrWhiteSpace(settings.FooterText))
        {
            sb.AppendLine();
            sb.AppendLine(settings.FooterText);
        }

        return sb.ToString().Trim();
    }

    public async Task<string> SuggestHashtagsAsync(string productName, InstagramPostSettings settings, CancellationToken cancellationToken)
    {
        var input = productName?.Trim() ?? string.Empty;
        if (string.IsNullOrWhiteSpace(input))
        {
            return "#achadinhos #ofertas #promo\u00e7\u00e3o #dicas #compras";
        }

        var allSettings = await _settingsStore.GetAsync(cancellationToken);
        if (settings.UseAi)
        {
            var openAi = allSettings.OpenAI ?? new OpenAISettings();
            var aiResult = await _openAiGenerator.GenerateHashtagsAsync(input, openAi, cancellationToken);
            if (!string.IsNullOrWhiteSpace(aiResult))
            {
                return aiResult;
            }
        }

        return BuildHashtags(input);
    }

    private static string StripTriggerPrefix(string text, List<string> triggers)
    {
        if (string.IsNullOrWhiteSpace(text)) return text;
        if (triggers is null || triggers.Count == 0) return text;

        var trimmed = text.Trim();
        foreach (var trigger in triggers)
        {
            if (string.IsNullOrWhiteSpace(trigger)) continue;
            if (trimmed.StartsWith(trigger, StringComparison.OrdinalIgnoreCase))
            {
                var remaining = trimmed[trigger.Length..].Trim();
                remaining = remaining.Trim('-', ':', '—', '–');
                return remaining;
            }
        }

        return trimmed;
    }

    private static string BuildCaptionVariation(string productName, string? link, int index, string? couponLine, OfficialProductDataResult? data)
    {
        var sb = new StringBuilder();
        var priceLine = "";
        
        if (data != null)
        {
            if (!string.IsNullOrWhiteSpace(data.CurrentPrice))
            {
                if (!string.IsNullOrWhiteSpace(data.PreviousPrice) && data.DiscountPercent > 0)
                {
                    priceLine = $"\U0001F525 DE R$ {data.PreviousPrice} POR APENAS {data.CurrentPrice} (-{data.DiscountPercent}%)";
                }
                else
                {
                    priceLine = $"\U0001F4B0 Pre\u00e7o: {data.CurrentPrice}";
                }
            }
        }

        switch (index % 3)
        {
            case 0: // Professional / Clean
                sb.AppendLine("\u2705 OPORTUNIDADE: " + productName.ToUpperInvariant());
                if (!string.IsNullOrWhiteSpace(priceLine)) sb.AppendLine(priceLine);
                if (!string.IsNullOrWhiteSpace(data?.EstimatedDelivery)) sb.AppendLine($"\U0001F69A {data.EstimatedDelivery}");
                if (!string.IsNullOrWhiteSpace(couponLine)) sb.AppendLine($"\U0001F3F7\uFE0F Cupom: {couponLine}");
                sb.AppendLine();
                sb.AppendLine("\u26A0\uFE0F Estoque limitado! Garanta o seu agora.");
                sb.AppendLine();
                sb.AppendLine("\U0001F4AC Comente EU QUERO para receber o link!");
                if (!string.IsNullOrWhiteSpace(link)) sb.AppendLine($"\U0001F449 LINK: {link}");
                break;

            case 1: // Urgent / Promotional
                sb.AppendLine("\u26A1\uFE0F OFERTA REL\u00c2MPAGO: " + productName);
                if (!string.IsNullOrWhiteSpace(priceLine)) sb.AppendLine(priceLine);
                sb.AppendLine("\U0001F440 Menor pre\u00e7o dos \u00faltimos dias!");
                if (!string.IsNullOrWhiteSpace(couponLine)) sb.AppendLine($"\U0001F3F7\uFE0F Use o cupom: {couponLine}");
                sb.AppendLine();
                sb.AppendLine("\U0001F449 LINK NO PERFIL OU COMENTE \"EU QUERO\"");
                if (!string.IsNullOrWhiteSpace(link)) sb.AppendLine($"\U0001F517 LINK: {link}");
                break;

            case 2: // Social Proof / Quality
                sb.AppendLine("\u2B50\uFE0F QUERIDINHO DO MOMENTO: " + productName);
                if (!string.IsNullOrWhiteSpace(priceLine)) sb.AppendLine(priceLine);
                sb.AppendLine("\u2728 Alta qualidade e \u00f3timas avalia\u00e7\u00f5es!");
                if (!string.IsNullOrWhiteSpace(data?.EstimatedDelivery)) sb.AppendLine($"\U0001F4E6 {data.EstimatedDelivery}");
                sb.AppendLine();
                sb.AppendLine("\U0001F4CC Salve para n\u00e3o esquecer!");
                sb.AppendLine("\U0001F449 Envio o LINK no Direct, \u00e9 s\u00f3 comentar: EU QUERO");
                if (!string.IsNullOrWhiteSpace(link)) sb.AppendLine($"\U0001F517 LINK: {link}");
                break;
        }

        return sb.ToString().Trim();
    }

    private static string BuildContextCaption(string productName, string context, string? link)
    {
        var sb = new StringBuilder();
        sb.AppendLine($"\U0001F680 Oferta em destaque: {productName}");
        sb.AppendLine(context.Trim());
        if (!string.IsNullOrWhiteSpace(link))
        {
            sb.AppendLine($"\U0001F449 {link}");
        }
        return sb.ToString().Trim();
    }

    private static string BuildContextSuggestion(string context)
    {
        var text = RemoveUrls(context).Trim();
        if (string.IsNullOrWhiteSpace(text))
        {
            return "Use a oferta como base para refor\u00e7ar o desconto e o benef\u00edcio principal.";
        }
        if (text.Length > 320)
        {
            text = text[..317] + "...";
        }
        return text;
    }

    private static string BuildHashtags(string productName)
    {
        // 5 standard high-level tags for top-tier affiliates
        var highLevelTags = new[]
        {
            "#achadinhos", "#ofertas", "#promo\u00e7\u00e3o", "#dicas", "#compras"
        };
        
        // Growth and views tags (Explorar/Viral)
        var growthTags = new[]
        {
            "#viral", "#explorar", "#utilidades", "#reelsbrasil", "#comprasonline", "#achadosdasemana", "#casa"
        };
        
        var words = productName
            .Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Take(4)
            .Select(w => $"#{Regex.Replace(w, @"[^\w]", string.Empty).ToLowerInvariant()}")
            .Where(w => w.Length > 2);

        return string.Join(' ', highLevelTags.Concat(growthTags).Concat(words).Distinct());
    }

    private static string BuildImageIdeas(string productName)
    {
        var name = string.IsNullOrWhiteSpace(productName) ? "produto" : productName.Trim();
        return string.Join('\n', new[]
        {
            $"- Close do {name} em fundo claro, destacando acabamento.",
            "- Foto em uso no dia a dia, mostrando utilidade real.",
            "- Composi\u00e7\u00e3o com itens relacionados (benef\u00edcios em evid\u00eancia)."
        });
    }

    private async Task<string?> BuildCouponLineAsync(AutomationSettings settings, string? link, CancellationToken cancellationToken)
    {
        if (!settings.CouponHub.Enabled || string.IsNullOrWhiteSpace(link))
        {
            return null;
        }

        var store = DetectStoreByLink(link);
        if (string.IsNullOrWhiteSpace(store))
        {
            return null;
        }

        var coupons = await _couponSelector.GetActiveCouponsAsync(store, 1, cancellationToken);
        var coupon = coupons.FirstOrDefault();
        if (coupon is null)
        {
            return null;
        }

        if (!string.IsNullOrWhiteSpace(coupon.Description))
        {
            return $"{coupon.Code.Trim()} ({coupon.Description.Trim()})";
        }

        return coupon.Code.Trim();
    }

    private static string DetectStoreByLink(string link)
    {
        var lower = link.ToLowerInvariant();
        if (lower.Contains("amazon.") || lower.Contains("amzn.to") || lower.Contains("a.co")) return "Amazon";
        if (lower.Contains("mercadolivre") || lower.Contains("mercadolibre") || lower.Contains("meli.co")) return "Mercado Livre";
        if (lower.Contains("shopee") || lower.Contains("shope.ee") || lower.Contains("shp.ee")) return "Shopee";
        if (lower.Contains("shein")) return "Shein";
        return string.Empty;
    }

    private static int ScoreCaption(string caption)
    {
        var score = 0;
        var normalized = caption.ToLowerInvariant();

        if (normalized.Contains("cupom", StringComparison.OrdinalIgnoreCase)) score += 20;
        if (normalized.Contains("eu quero", StringComparison.OrdinalIgnoreCase)) score += 25; // High priority for CTA
        if (normalized.Contains("agora", StringComparison.OrdinalIgnoreCase)) score += 12;
        if (normalized.Contains("oferta", StringComparison.OrdinalIgnoreCase)) score += 10;
        if (normalized.Contains("garanta", StringComparison.OrdinalIgnoreCase)) score += 8;
        if (normalized.Contains("link", StringComparison.OrdinalIgnoreCase)) score += 15; // Increased priority
        if (normalized.Contains("apenas", StringComparison.OrdinalIgnoreCase)) score += 10; // Price focus

        var length = caption.Length;
        if (length is >= 180 and <= 450) score += 15;
        if (length > 650) score -= 15;

        return score;
    }

    private static string? ExtractFirstUrl(string text)
    {
        var match = UrlRegex.Match(text);
        return match.Success ? match.Value : null;
    }

    private static string RemoveUrls(string text)
    {
        return UrlRegex.Replace(text, string.Empty).Trim();
    }

    private static string RemoveCouponAppendix(string text)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            return text;
        }

        var markerIndex = text.IndexOf("Cupons ativos:", StringComparison.OrdinalIgnoreCase);
        if (markerIndex <= 0)
        {
            return text;
        }

        return text[..markerIndex].Trim();
    }
}
