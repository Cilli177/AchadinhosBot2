using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Domain.Settings;

using AchadinhosBot.Next.Infrastructure.ProductData;

namespace AchadinhosBot.Next.Infrastructure.Instagram;

public sealed class GeminiInstagramPostGenerator
{
    private static int _currentKeyIndex = -1;
    
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly ILogger<GeminiInstagramPostGenerator> _logger;
    private readonly IInstagramAiLogStore _logStore;
    private readonly InstagramLinkMetaService _metaService;
    private readonly InstagramImageDownloadService _imageDownloadService;
    private readonly OfficialProductDataService _officialService;

    public GeminiInstagramPostGenerator(
        IHttpClientFactory httpClientFactory,
        ILogger<GeminiInstagramPostGenerator> logger,
        IInstagramAiLogStore logStore,
        InstagramLinkMetaService metaService,
        InstagramImageDownloadService imageDownloadService,
        OfficialProductDataService officialService)
    {
        _httpClientFactory = httpClientFactory;
        _logger = logger;
        _logStore = logStore;
        _metaService = metaService;
        _imageDownloadService = imageDownloadService;
        _officialService = officialService;
    }

    public async Task<string?> GenerateAsync(string productInput, string? offerContext, string? affiliateLink, InstagramPostSettings instaSettings, GeminiSettings geminiSettings, CancellationToken cancellationToken)
    {
        var apiKeys = GetGeminiApiKeys(geminiSettings);
        if (apiKeys.Count == 0)
        {
            return null;
        }

        var model = string.IsNullOrWhiteSpace(geminiSettings.Model) ? "gemini-2.5-flash" : geminiSettings.Model.Trim();
        var baseUrl = string.IsNullOrWhiteSpace(geminiSettings.BaseUrl) ? "https://generativelanguage.googleapis.com/v1beta" : geminiSettings.BaseUrl.Trim();

        var officialData = await _officialService.TryGetBestAsync(productInput, affiliateLink, cancellationToken);
        var meta = await _metaService.GetMetaAsync(affiliateLink ?? productInput, cancellationToken);
        
        List<string> images = meta.Images ?? new List<string>();
        if ((officialData?.Images?.Count ?? 0) > 0)
        {
            images = officialData!.Images;
        }
        if (instaSettings.UseImageDownload && images.Count > 0)
        {
            var downloaded = await _imageDownloadService.DownloadAsync(images, cancellationToken);
            if (downloaded.Count > 0)
            {
                images = downloaded;
            }
        }
        
        var officialContext = string.Empty;
        if (officialData != null)
        {
            officialContext = $"Produto: {officialData.Title}\nPreço Atual: {officialData.CurrentPrice}";
            if (!string.IsNullOrWhiteSpace(officialData.PreviousPrice)) officialContext += $"\nPreço Anterior: {officialData.PreviousPrice}";
            if (officialData.DiscountPercent > 0) officialContext += $"\nDesconto: {officialData.DiscountPercent}%";
            if (!string.IsNullOrWhiteSpace(officialData.EstimatedDelivery)) officialContext += $"\nEntrega: {officialData.EstimatedDelivery}";
        }

        var effectiveInput = OpenAiInstagramPostGenerator.ResolveEffectiveInput(productInput, officialData?.Title ?? meta.Title, affiliateLink ?? productInput);
        var effectiveContext = !string.IsNullOrWhiteSpace(offerContext) ? offerContext : (string.IsNullOrWhiteSpace(officialContext) ? meta.Description : officialContext);
        
        var title = officialData?.Title ?? meta.Title;
        var description = string.IsNullOrWhiteSpace(officialContext) ? meta.Description : officialContext;

        var prompt = OpenAiInstagramPostGenerator.BuildPrompt(effectiveInput, effectiveContext, affiliateLink, images, title, description, instaSettings);

        var payload = new
        {
            contents = new[]
            {
                new
                {
                    role = "user",
                    parts = new[] { new { text = prompt } }
                }
            },
            generationConfig = new
            {
                maxOutputTokens = Math.Clamp(geminiSettings.MaxOutputTokens <= 0 ? 1200 : geminiSettings.MaxOutputTokens, 200, 4096)
            }
        };

        var started = DateTimeOffset.UtcNow;
        try
        {
            var client = _httpClientFactory.CreateClient("gemini");
            string? lastErrorBody = null;
            
            var startIndex = unchecked((int)((uint)Interlocked.Increment(ref _currentKeyIndex) % (uint)apiKeys.Count));

            for (var i = 0; i < apiKeys.Count; i++)
            {
                var keyIndex = (startIndex + i) % apiKeys.Count;
                var apiKey = apiKeys[keyIndex];
                var url = $"{baseUrl.TrimEnd('/')}/models/{model}:generateContent?key={Uri.EscapeDataString(apiKey)}";
                using var response = await client.PostAsync(url, new StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json"), cancellationToken);
                var body = await response.Content.ReadAsStringAsync(cancellationToken);
                
                if (!response.IsSuccessStatusCode)
                {
                    lastErrorBody = body;
                    var canTryNext = i < apiKeys.Count - 1 && ShouldTryNextGeminiKey(response.StatusCode, body);
                    if (canTryNext)
                    {
                        // Use keyIndex instead of i for accurate logging
                        _logger.LogWarning("Gemini chave {KeyIndex}/{Total} falhou com {Status}. Tentando proxima chave.", keyIndex + 1, apiKeys.Count, response.StatusCode);
                        continue;
                    }

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

            await _logStore.AppendAsync(BuildLogEntry(instaSettings, geminiSettings.Model, "gemini", productInput, affiliateLink, images.Count, images, null, lastErrorBody, started, 0, "Erro na geracao"), cancellationToken);
            return null;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Falha ao gerar post via Gemini");
            await _logStore.AppendAsync(BuildLogEntry(instaSettings, geminiSettings.Model, "gemini", productInput, affiliateLink, 0, Array.Empty<string>(), null, ex.Message, started, 0, "Erro na geracao"), cancellationToken);
            return null;
        }
    }

    private static List<string> GetGeminiApiKeys(GeminiSettings settings)
    {
        var keys = new List<string>();
        if (!string.IsNullOrWhiteSpace(settings.ApiKey) && settings.ApiKey != "********")
        {
            keys.Add(settings.ApiKey.Trim());
        }

        if (settings.ApiKeys is not null)
        {
            foreach (var key in settings.ApiKeys)
            {
                if (string.IsNullOrWhiteSpace(key))
                {
                    continue;
                }

                var trimmed = key.Trim();
                if (trimmed == "********")
                {
                    continue;
                }

                keys.Add(trimmed);
            }
        }

        return keys
            .Distinct(StringComparer.Ordinal)
            .ToList();
    }

    private static bool ShouldTryNextGeminiKey(System.Net.HttpStatusCode statusCode, string? body)
    {
        var status = (int)statusCode;
        if (status is 401 or 403 or 429 or 500 or 502 or 503 or 504)
        {
            return true;
        }

        if (status == 400 && !string.IsNullOrWhiteSpace(body))
        {
            return body.Contains("RESOURCE_EXHAUSTED", StringComparison.OrdinalIgnoreCase) ||
                   body.Contains("quota", StringComparison.OrdinalIgnoreCase) ||
                   body.Contains("rate limit", StringComparison.OrdinalIgnoreCase);
        }

        return false;
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
