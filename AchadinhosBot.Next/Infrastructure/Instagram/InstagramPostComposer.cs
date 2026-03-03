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

            var provider = string.IsNullOrWhiteSpace(settings.AiProvider) ? "openai" : settings.AiProvider.Trim().ToLowerInvariant();
            var results = new List<string>();
            var openAiResult = string.Empty;
            var geminiResult = string.Empty;

            if (provider is "openai" or "both")
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

            // Fallback cruzado: evita cair para o texto generico quando o provider principal falha (ex.: limite de cota).
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
                            discountText,
                            officialData.Images?.FirstOrDefault(),
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
        var tones = new[]
        {
            "Qualidade e custo-benef\u00edcio",
            "Promo\u00e7\u00e3o imperd\u00edvel",
            "Oferta especial",
            "Escolha inteligente",
            "Destaque do dia"
        };
        var captionCandidates = new List<(int Index, string Caption, int Score)>();
        for (var i = 0; i < variations; i++)
        {
            var tone = tones[i % tones.Length];
            var caption = BuildCaption(productName, link, tone, couponLine);
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

    private static string BuildCaption(string productName, string? link, string tone, string? couponLine)
    {
        var sb = new StringBuilder();
        sb.AppendLine($"\u2728 {tone} para voc\u00ea!");
        sb.AppendLine($"\u2705 {productName}");
        sb.AppendLine("\U0001F69A Envio r\u00e1pido e \u00f3tima avalia\u00e7\u00e3o");
        sb.AppendLine("\U0001F4B3 Parcelamento facilitado");
        if (!string.IsNullOrWhiteSpace(couponLine))
        {
            sb.AppendLine($"\U0001F3F7\uFE0F Cupom: {couponLine}");
        }
        sb.AppendLine("\U0001F3AF Garanta o seu agora");
        if (!string.IsNullOrWhiteSpace(link))
        {
            sb.AppendLine($"\U0001F449 {link}");
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
        var baseTags = new[]
        {
            "#ofertas", "#promo", "#achadinhos", "#comprasonline", "#descontos", "#economia"
        };
        var words = productName
            .Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Take(3)
            .Select(w => $"#{Regex.Replace(w, @"[^\w]", string.Empty).ToLowerInvariant()}");
        return string.Join(' ', baseTags.Concat(words).Distinct());
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
        if (normalized.Contains("agora", StringComparison.OrdinalIgnoreCase)) score += 12;
        if (normalized.Contains("oferta", StringComparison.OrdinalIgnoreCase)) score += 10;
        if (normalized.Contains("garanta", StringComparison.OrdinalIgnoreCase)) score += 8;
        if (normalized.Contains("link", StringComparison.OrdinalIgnoreCase)) score += 8;

        var length = caption.Length;
        if (length is >= 180 and <= 380) score += 15;
        if (length > 550) score -= 10;

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
