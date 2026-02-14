using System.Text;
using System.Text;
using System.Text.RegularExpressions;
using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Domain.Settings;

namespace AchadinhosBot.Next.Infrastructure.Instagram;

public sealed class InstagramPostComposer : IInstagramPostComposer
{
    private static readonly Regex UrlRegex = new(@"https?://[^\s]+", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
    private readonly IMessageProcessor _messageProcessor;
    private readonly OpenAiInstagramPostGenerator _openAiGenerator;
    private readonly GeminiInstagramPostGenerator _geminiGenerator;
    private readonly ISettingsStore _settingsStore;

    public InstagramPostComposer(
        IMessageProcessor messageProcessor,
        OpenAiInstagramPostGenerator openAiGenerator,
        GeminiInstagramPostGenerator geminiGenerator,
        ISettingsStore settingsStore)
    {
        _messageProcessor = messageProcessor;
        _openAiGenerator = openAiGenerator;
        _geminiGenerator = geminiGenerator;
        _settingsStore = settingsStore;
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

        if (settings.UseAi)
        {
            var allSettings = await _settingsStore.GetAsync(cancellationToken);
            var openAi = allSettings.OpenAI ?? new OpenAISettings();
            var gemini = allSettings.Gemini ?? new GeminiSettings();

            var provider = string.IsNullOrWhiteSpace(settings.AiProvider) ? "openai" : settings.AiProvider.Trim().ToLowerInvariant();
            var results = new List<string>();

            if (provider is "openai" or "both")
            {
                var openAiResult = await _openAiGenerator.GenerateAsync(input, offerContext, link, settings, openAi, cancellationToken);
                if (!string.IsNullOrWhiteSpace(openAiResult))
                {
                    results.Add(provider == "both" ? $"=== OPENAI ===\n{openAiResult.Trim()}" : openAiResult.Trim());
                }
            }

            if (provider is "gemini" or "both")
            {
                var geminiResult = await _geminiGenerator.GenerateAsync(input, offerContext, link, settings, gemini, cancellationToken);
                if (!string.IsNullOrWhiteSpace(geminiResult))
                {
                    results.Add(provider == "both" ? $"=== GEMINI ===\n{geminiResult.Trim()}" : geminiResult.Trim());
                }
            }

            if (results.Count > 0)
            {
                return string.Join("\n\n", results);
            }
        }

        var productName = RemoveUrls(baseText);
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
        for (var i = 0; i < variations; i++)
        {
            var tone = tones[i % tones.Length];
            sb.AppendLine($"Legenda {i + 1} (pronta para copiar):");
            sb.AppendLine(BuildCaption(productName, link, tone));
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

    private static string BuildCaption(string productName, string? link, string tone)
    {
        var sb = new StringBuilder();
        sb.AppendLine($"\u2728 {tone} para voc\u00ea!");
        sb.AppendLine($"\u2705 {productName}");
        sb.AppendLine("\U0001F69A Envio r\u00e1pido e \u00f3tima avalia\u00e7\u00e3o");
        sb.AppendLine("\U0001F4B3 Parcelamento facilitado");
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

    private static string? ExtractFirstUrl(string text)
    {
        var match = UrlRegex.Match(text);
        return match.Success ? match.Value : null;
    }

    private static string RemoveUrls(string text)
    {
        return UrlRegex.Replace(text, string.Empty).Trim();
    }
}
