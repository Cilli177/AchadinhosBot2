using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Domain.Settings;

namespace AchadinhosBot.Next.Infrastructure.Instagram;

public sealed class OpenAiInstagramPostGenerator
{
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly ILogger<OpenAiInstagramPostGenerator> _logger;
    private readonly IInstagramAiLogStore _logStore;
    private readonly InstagramLinkMetaService _metaService;
    private readonly InstagramImageDownloadService _imageDownloadService;

    public OpenAiInstagramPostGenerator(
        IHttpClientFactory httpClientFactory,
        ILogger<OpenAiInstagramPostGenerator> logger,
        IInstagramAiLogStore logStore,
        InstagramLinkMetaService metaService,
        InstagramImageDownloadService imageDownloadService)
    {
        _httpClientFactory = httpClientFactory;
        _logger = logger;
        _logStore = logStore;
        _metaService = metaService;
        _imageDownloadService = imageDownloadService;
    }

    public async Task<string?> GenerateAsync(string productInput, string? offerContext, string? affiliateLink, InstagramPostSettings instaSettings, OpenAISettings aiSettings, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(aiSettings.ApiKey) || aiSettings.ApiKey == "********")
        {
            return null;
        }

        var model = string.IsNullOrWhiteSpace(aiSettings.Model) ? "gpt-4o-mini" : aiSettings.Model.Trim();
        var baseUrl = string.IsNullOrWhiteSpace(aiSettings.BaseUrl) ? "https://api.openai.com/v1" : aiSettings.BaseUrl.Trim();

        var meta = await _metaService.GetMetaAsync(affiliateLink ?? productInput, cancellationToken);
        var images = meta.Images;
        if (instaSettings.UseImageDownload && images.Count > 0)
        {
            var downloaded = await _imageDownloadService.DownloadAsync(images, cancellationToken);
            if (downloaded.Count > 0)
            {
                images = downloaded;
            }
        }
        var effectiveInput = ResolveEffectiveInput(productInput, meta.Title, affiliateLink ?? productInput);
        var effectiveContext = !string.IsNullOrWhiteSpace(offerContext) ? offerContext : meta.Description;
        var prompt = BuildPrompt(effectiveInput, effectiveContext, affiliateLink, images, meta.Title, meta.Description, instaSettings);

        var payload = new
        {
            model,
            input = new[]
            {
                new { role = "system", content = "Voce cria posts profissionais para Instagram em portugues do Brasil." },
                new { role = "user", content = prompt }
            },
            temperature = aiSettings.Temperature,
            max_output_tokens = aiSettings.MaxOutputTokens
        };

        var started = DateTimeOffset.UtcNow;
        try
        {
            var client = _httpClientFactory.CreateClient("openai");
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", aiSettings.ApiKey);
            using var response = await client.PostAsync(
                $"{baseUrl.TrimEnd('/')}/responses",
                new StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json"),
                cancellationToken);

            var body = await response.Content.ReadAsStringAsync(cancellationToken);
            if (!response.IsSuccessStatusCode)
            {
                _logger.LogWarning("OpenAI respondeu erro {Status}: {Body}", response.StatusCode, body);
                return null;
            }

            var text = ExtractOutputText(body);
            var finalText = AppendImagesIfMissing(text, images);
            var (score, notes) = EvaluateQuality(finalText);
            await _logStore.AppendAsync(BuildLogEntry(instaSettings, aiSettings.Model, "openai", productInput, affiliateLink, images.Count, images, finalText, null, started, score, notes), cancellationToken);
            return finalText;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Falha ao gerar post via OpenAI");
            await _logStore.AppendAsync(BuildLogEntry(instaSettings, aiSettings.Model, "openai", productInput, affiliateLink, 0, Array.Empty<string>(), null, ex.Message, started, 0, "Erro na geracao"), cancellationToken);
            return null;
        }
    }

    internal static string BuildPrompt(string productInput, string? offerContext, string? affiliateLink, List<string> images, string? title, string? description, InstagramPostSettings instaSettings)
    {
        if (instaSettings.UseShortProductName)
        {
            productInput = ShortenProductName(productInput);
        }

        var format = new StringBuilder();
        format.AppendLine("Formato obrigatório (sem texto extra):");
        format.AppendLine("POST PARA INSTAGRAM");
        format.AppendLine("Produto: <nome do produto>");
        format.AppendLine("Link afiliado: <link ou vazio>");
        format.AppendLine();
        var variations = Math.Clamp(instaSettings.VariationsCount, 1, 5);
        for (var i = 1; i <= variations; i++)
        {
            format.AppendLine($"Legenda {i} (pronta para copiar):");
            format.AppendLine("<texto>");
            format.AppendLine();
        }
        format.AppendLine("Hashtags sugeridas:");
        format.AppendLine("<hashtags>");
        format.AppendLine();
        format.AppendLine("Sugestoes de imagem:");
        format.AppendLine("- <item>");
        format.AppendLine("- <item>");
        format.AppendLine("- <item>");
        if (instaSettings.UseBenefitBullets)
        {
            format.AppendLine();
            format.AppendLine("Beneficios em bullet points:");
            format.AppendLine("- <beneficio>");
            format.AppendLine("- <beneficio>");
            format.AppendLine("- <beneficio>");
        }
        if (images.Count > 0)
        {
            format.AppendLine();
            format.AppendLine("Imagens encontradas (URLs):");
            format.AppendLine("<url>");
        }

        var contextMode = instaSettings.OfferContextMode;
        if (contextMode == InstagramOfferContextMode.Off && instaSettings.UseOfferContext)
        {
            contextMode = InstagramOfferContextMode.ExtraPost;
        }

        if (contextMode == InstagramOfferContextMode.Suggestion)
        {
            format.AppendLine();
            format.AppendLine("Sugestao rapida (baseado na oferta):");
            format.AppendLine("<texto curto>");
        }
        else if (contextMode == InstagramOfferContextMode.ExtraPost)
        {
            format.AppendLine();
            format.AppendLine("Post extra (baseado na oferta):");
            format.AppendLine("<texto>");
        }

        var template = string.IsNullOrWhiteSpace(instaSettings.PromptTemplate)
            ? "{{format}}\n\nDados:\nEntrada: {{input}}\nLink afiliado: {{link}}\nContexto da oferta: {{context}}\nRodape: {{footer}}\n"
            : instaSettings.PromptTemplate;

        var prompt = template
            .Replace("{{format}}", format.ToString().Trim(), StringComparison.OrdinalIgnoreCase)
            .Replace("{{input}}", productInput, StringComparison.OrdinalIgnoreCase)
            .Replace("{{link}}", affiliateLink ?? string.Empty, StringComparison.OrdinalIgnoreCase)
            .Replace("{{context}}", offerContext ?? string.Empty, StringComparison.OrdinalIgnoreCase)
            .Replace("{{footer}}", instaSettings.FooterText ?? string.Empty, StringComparison.OrdinalIgnoreCase)
            .Replace("{{images}}", images.Count > 0 ? string.Join('\n', images) : string.Empty, StringComparison.OrdinalIgnoreCase)
            .Replace("{{title}}", title ?? string.Empty, StringComparison.OrdinalIgnoreCase)
            .Replace("{{description}}", description ?? string.Empty, StringComparison.OrdinalIgnoreCase);

        if (instaSettings.UseUltraPrompt)
        {
            prompt = "Voce e um copywriter premium de afiliados no Brasil, especializado em high ticket.\n" +
                     "Crie um post extremamente profissional, convincente e elegante.\n" +
                     "Evite genericidade, repeticions e frases vazias. Use linguagem humana.\n" +
                     "Crie legendas CLARAMENTE diferentes entre si.\n" +
                     "Nao invente preco, garantia ou beneficios nao informados.\n\n" +
                     prompt;
        }

        return prompt;
    }

    private static string ShortenProductName(string input)
    {
        if (string.IsNullOrWhiteSpace(input)) return input;
        var cleaned = Regex.Replace(input, @"https?://\S+", string.Empty).Trim();
        if (cleaned.Length <= 90) return cleaned;
        var words = cleaned.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        var sb = new StringBuilder();
        foreach (var w in words)
        {
            if (sb.Length + w.Length + 1 > 85) break;
            if (sb.Length > 0) sb.Append(' ');
            sb.Append(w);
        }
        return sb.Length == 0 ? cleaned[..Math.Min(cleaned.Length, 85)] : sb.ToString();
    }

    private static bool IsLinkOnly(string input)
    {
        if (string.IsNullOrWhiteSpace(input)) return false;
        var cleaned = Regex.Replace(input, @"https?://\S+", string.Empty).Trim();
        return string.IsNullOrWhiteSpace(cleaned);
    }

    internal static string ResolveEffectiveInput(string productInput, string? metaTitle, string? sourceLink)
    {
        if (!IsLinkOnly(productInput) || string.IsNullOrWhiteSpace(metaTitle))
        {
            return productInput;
        }

        var title = metaTitle.Trim();
        if (title.Length < 6)
        {
            return productInput;
        }

        if (Uri.TryCreate(sourceLink, UriKind.Absolute, out var uri))
        {
            var host = uri.Host.ToLowerInvariant();
            var shortenerHosts = new[] { "bit.ly", "tinyurl.com", "compre.link", "t.co", "linktr.ee" };
            if (shortenerHosts.Any(s => host.Contains(s, StringComparison.OrdinalIgnoreCase)))
            {
                return productInput;
            }

            if (title.Contains(host, StringComparison.OrdinalIgnoreCase))
            {
                return productInput;
            }
        }

        return title;
    }

    private async Task<(string? Title, string? Description)> TryFetchPageMetaAsync(string? link, CancellationToken cancellationToken)
    {
        var meta = await _metaService.GetMetaAsync(link ?? string.Empty, cancellationToken);
        return (meta.Title, meta.Description);
    }

    private async Task<List<string>> TryFetchImageUrlsAsync(string? link, CancellationToken cancellationToken)
    {
        return (await _metaService.GetMetaAsync(link ?? string.Empty, cancellationToken)).Images;
    }

    private static string? ExtractOutputText(string json)
    {
        try
        {
            using var doc = JsonDocument.Parse(json);
            if (!doc.RootElement.TryGetProperty("output", out var output) || output.ValueKind != JsonValueKind.Array)
            {
                return null;
            }

            var sb = new StringBuilder();
            foreach (var item in output.EnumerateArray())
            {
                if (!item.TryGetProperty("content", out var content) || content.ValueKind != JsonValueKind.Array)
                {
                    continue;
                }

                foreach (var c in content.EnumerateArray())
                {
                    if (c.TryGetProperty("type", out var type) && type.GetString() == "output_text" &&
                        c.TryGetProperty("text", out var text))
                    {
                        sb.Append(text.GetString());
                    }
                }
            }

            var result = sb.ToString().Trim();
            return string.IsNullOrWhiteSpace(result) ? null : result;
        }
        catch
        {
            return null;
        }
    }

    private static string? AppendImagesIfMissing(string? text, List<string> images)
    {
        if (string.IsNullOrWhiteSpace(text) || images.Count == 0)
        {
            return text;
        }

        if (text.Contains("Imagens encontradas", StringComparison.OrdinalIgnoreCase))
        {
            return text;
        }

        var sb = new StringBuilder();
        sb.AppendLine(text.Trim());
        sb.AppendLine();
        sb.AppendLine("Imagens encontradas (URLs):");
        foreach (var url in images)
        {
            sb.AppendLine(url);
        }
        return sb.ToString().Trim();
    }

    private static Domain.Logs.InstagramAiLogEntry BuildLogEntry(
        InstagramPostSettings settings,
        string model,
        string provider,
        string input,
        string? link,
        int imageCount,
        IReadOnlyCollection<string> imageUrls,
        string? output,
        string? error,
        DateTimeOffset started,
        int qualityScore,
        string qualityNotes)
    {
        var snippet = input.Length > 140 ? input[..140] + "..." : input;
        return new Domain.Logs.InstagramAiLogEntry
        {
            Provider = provider,
            Model = model,
            Success = string.IsNullOrWhiteSpace(error),
            Error = error,
            Variations = settings.VariationsCount,
            PromptPreset = settings.PromptPreset,
            UltraPrompt = settings.UseUltraPrompt,
            ShortName = settings.UseShortProductName,
            BenefitBullets = settings.UseBenefitBullets,
            InputSnippet = snippet,
            Link = link,
            ImageCount = imageCount,
            ImageUrls = imageUrls?.Take(6).ToList() ?? new List<string>(),
            OutputLength = output?.Length ?? 0,
            DurationMs = (long)(DateTimeOffset.UtcNow - started).TotalMilliseconds,
            QualityScore = qualityScore,
            QualityNotes = qualityNotes
        };
    }

    private static (int Score, string Notes) EvaluateQuality(string? text)
    {
        if (string.IsNullOrWhiteSpace(text)) return (0, "sem texto");
        var score = 100;
        var notes = new List<string>();
        if (text.Length < 300) { score -= 20; notes.Add("texto curto"); }
        if (!text.Contains("Legenda 1", StringComparison.OrdinalIgnoreCase)) { score -= 10; notes.Add("sem legenda 1"); }
        if (!text.Contains("Hashtags", StringComparison.OrdinalIgnoreCase)) { score -= 10; notes.Add("sem hashtags"); }
        if (!text.Contains("CTA", StringComparison.OrdinalIgnoreCase) && !text.Contains("👉")) { score -= 10; notes.Add("cta fraco"); }
        return (Math.Max(score, 0), string.Join(", ", notes));
    }
}
