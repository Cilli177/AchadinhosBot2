using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Domain.Settings;

namespace AchadinhosBot.Next.Infrastructure.Instagram;

public sealed class GeminiInstagramPostGenerator
{
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly ILogger<GeminiInstagramPostGenerator> _logger;
    private readonly IInstagramAiLogStore _logStore;
    private readonly InstagramLinkMetaService _metaService;
    private readonly InstagramImageDownloadService _imageDownloadService;

    public GeminiInstagramPostGenerator(
        IHttpClientFactory httpClientFactory,
        ILogger<GeminiInstagramPostGenerator> logger,
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

    public async Task<string?> GenerateAsync(string productInput, string? offerContext, string? affiliateLink, InstagramPostSettings instaSettings, GeminiSettings geminiSettings, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(geminiSettings.ApiKey) || geminiSettings.ApiKey == "********")
        {
            return null;
        }

        var model = string.IsNullOrWhiteSpace(geminiSettings.Model) ? "gemini-2.5-flash" : geminiSettings.Model.Trim();
        var baseUrl = string.IsNullOrWhiteSpace(geminiSettings.BaseUrl) ? "https://generativelanguage.googleapis.com/v1beta" : geminiSettings.BaseUrl.Trim();

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
        var effectiveInput = OpenAiInstagramPostGenerator.ResolveEffectiveInput(productInput, meta.Title, affiliateLink ?? productInput);
        var effectiveContext = !string.IsNullOrWhiteSpace(offerContext) ? offerContext : meta.Description;
        var prompt = OpenAiInstagramPostGenerator.BuildPrompt(effectiveInput, effectiveContext, affiliateLink, images, meta.Title, meta.Description, instaSettings);

        var payload = new
        {
            contents = new[]
            {
                new
                {
                    role = "user",
                    parts = new[] { new { text = prompt } }
                }
            }
        };

        var started = DateTimeOffset.UtcNow;
        try
        {
            var client = _httpClientFactory.CreateClient("gemini");
            var url = $"{baseUrl.TrimEnd('/')}/models/{model}:generateContent?key={Uri.EscapeDataString(geminiSettings.ApiKey)}";
            using var response = await client.PostAsync(url, new StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json"), cancellationToken);
            var body = await response.Content.ReadAsStringAsync(cancellationToken);
            if (!response.IsSuccessStatusCode)
            {
                _logger.LogWarning("Gemini respondeu erro {Status}: {Body}", response.StatusCode, body);
                await _logStore.AppendAsync(BuildLogEntry(instaSettings, geminiSettings.Model, "gemini", productInput, affiliateLink, images.Count, images, null, body, started, 0, "Erro na geracao"), cancellationToken);
                return null;
            }

            var text = ExtractOutputText(body);
            var finalText = AppendImagesIfMissing(text, images);
            var (score, notes) = EvaluateQuality(finalText);
            await _logStore.AppendAsync(BuildLogEntry(instaSettings, geminiSettings.Model, "gemini", productInput, affiliateLink, images.Count, images, finalText, null, started, score, notes), cancellationToken);
            return finalText;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Falha ao gerar post via Gemini");
            await _logStore.AppendAsync(BuildLogEntry(instaSettings, geminiSettings.Model, "gemini", productInput, affiliateLink, 0, Array.Empty<string>(), null, ex.Message, started, 0, "Erro na geracao"), cancellationToken);
            return null;
        }
    }

    private static string? ExtractOutputText(string json)
    {
        try
        {
            using var doc = JsonDocument.Parse(json);
            if (!doc.RootElement.TryGetProperty("candidates", out var candidates) || candidates.ValueKind != JsonValueKind.Array)
            {
                return null;
            }

            foreach (var cand in candidates.EnumerateArray())
            {
                if (!cand.TryGetProperty("content", out var content) || content.ValueKind != JsonValueKind.Object)
                {
                    continue;
                }
                if (!content.TryGetProperty("parts", out var parts) || parts.ValueKind != JsonValueKind.Array)
                {
                    continue;
                }
                var sb = new StringBuilder();
                foreach (var part in parts.EnumerateArray())
                {
                    if (part.TryGetProperty("text", out var text))
                    {
                        sb.Append(text.GetString());
                    }
                }
                var result = sb.ToString().Trim();
                if (!string.IsNullOrWhiteSpace(result))
                {
                    return result;
                }
            }

            return null;
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

    private async Task<List<string>> TryFetchImageUrlsAsync(string? link, CancellationToken cancellationToken)
        => (await _metaService.GetMetaAsync(link ?? string.Empty, cancellationToken)).Images;

    private static bool IsLinkOnly(string input)
    {
        if (string.IsNullOrWhiteSpace(input)) return false;
        var cleaned = Regex.Replace(input, @"https?://\S+", string.Empty).Trim();
        return string.IsNullOrWhiteSpace(cleaned);
    }

    private async Task<(string? Title, string? Description)> TryFetchPageMetaAsync(string? link, CancellationToken cancellationToken)
    {
        var meta = await _metaService.GetMetaAsync(link ?? string.Empty, cancellationToken);
        return (meta.Title, meta.Description);
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
