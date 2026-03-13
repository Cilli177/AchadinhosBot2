using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Domain.Settings;
using AchadinhosBot.Next.Infrastructure.ProductData;

namespace AchadinhosBot.Next.Infrastructure.Instagram;

public sealed class DeepSeekInstagramPostGenerator
{
    private static int _currentKeyIndex = -1;
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly ILogger<DeepSeekInstagramPostGenerator> _logger;
    private readonly IInstagramAiLogStore _logStore;
    private readonly InstagramLinkMetaService _metaService;
    private readonly InstagramImageDownloadService _imageDownloadService;
    private readonly OfficialProductDataService _officialService;

    public DeepSeekInstagramPostGenerator(
        IHttpClientFactory httpClientFactory,
        ILogger<DeepSeekInstagramPostGenerator> logger,
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

    public async Task<string?> GenerateAsync(string productInput, string? offerContext, string? affiliateLink, InstagramPostSettings instaSettings, DeepSeekSettings aiSettings, CancellationToken cancellationToken)
    {
        var apiKeys = GetApiKeys(aiSettings);
        if (apiKeys.Count == 0)
        {
            return null;
        }

        var model = string.IsNullOrWhiteSpace(aiSettings.Model) ? "deepseek-chat" : aiSettings.Model.Trim();
        var baseUrl = string.IsNullOrWhiteSpace(aiSettings.BaseUrl) ? "https://api.deepseek.com" : aiSettings.BaseUrl.Trim();

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

        // Standard OpenAI Chat Completion payload
        var payload = new
        {
            model,
            messages = new[]
            {
                new { role = "system", content = "Voce cria posts profissionais para Instagram em portugues do Brasil." },
                new { role = "user", content = prompt }
            },
            temperature = aiSettings.Temperature,
            max_tokens = aiSettings.MaxOutputTokens
        };

        var started = DateTimeOffset.UtcNow;
        try
        {
            var url = $"{baseUrl.TrimEnd('/')}/v1/chat/completions";
            if (baseUrl.Contains("api.deepseek.com", StringComparison.OrdinalIgnoreCase))
            {
                url = "https://api.deepseek.com/chat/completions";
            }

            var body = await PostWithKeyRotationAsync(apiKeys, url, payload, cancellationToken);
            if (string.IsNullOrWhiteSpace(body))
            {
                return null;
            }

            var text = ExtractChatOutputText(body);
            var finalText = AppendImagesIfMissing(text, images);
            var (score, notes) = EvaluateQuality(finalText);
            await _logStore.AppendAsync(BuildLogEntry(instaSettings, model, "deepseek", productInput, affiliateLink, images.Count, images, finalText, null, started, score, notes), cancellationToken);
            return finalText;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Falha ao gerar post via DeepSeek");
            await _logStore.AppendAsync(BuildLogEntry(instaSettings, model, "deepseek", productInput, affiliateLink, 0, Array.Empty<string>(), null, ex.Message, started, 0, "Erro na geracao"), cancellationToken);
            return null;
        }
    }

    public async Task<string?> GenerateFreeformAsync(string prompt, DeepSeekSettings aiSettings, CancellationToken cancellationToken)
    {
        var apiKeys = GetApiKeys(aiSettings);
        if (apiKeys.Count == 0 || string.IsNullOrWhiteSpace(prompt))
        {
            return null;
        }

        var model = string.IsNullOrWhiteSpace(aiSettings.Model) ? "deepseek-chat" : aiSettings.Model.Trim();
        var baseUrl = string.IsNullOrWhiteSpace(aiSettings.BaseUrl) ? "https://api.deepseek.com" : aiSettings.BaseUrl.Trim();
        var payload = new
        {
            model,
            messages = new[]
            {
                new { role = "system", content = "Responda em portugues do Brasil com clareza e sem formatacao extra desnecessaria." },
                new { role = "user", content = prompt.Trim() }
            },
            temperature = aiSettings.Temperature,
            max_tokens = aiSettings.MaxOutputTokens
        };

        try
        {
            var url = $"{baseUrl.TrimEnd('/')}/v1/chat/completions";
            if (baseUrl.Contains("api.deepseek.com", StringComparison.OrdinalIgnoreCase))
            {
                url = "https://api.deepseek.com/chat/completions";
            }

            var body = await PostWithKeyRotationAsync(apiKeys, url, payload, cancellationToken);
            if (string.IsNullOrWhiteSpace(body))
            {
                return null;
            }

            return ExtractChatOutputText(body)?.Trim();
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Falha ao gerar resposta livre via DeepSeek");
            return null;
        }
    }

    private async Task<string?> PostWithKeyRotationAsync(IReadOnlyList<string> apiKeys, string url, object payload, CancellationToken cancellationToken)
    {
        var client = _httpClientFactory.CreateClient("deepseek");
        var startIndex = unchecked((int)((uint)Interlocked.Increment(ref _currentKeyIndex) % (uint)apiKeys.Count));
        string? lastBody = null;

        for (var i = 0; i < apiKeys.Count; i++)
        {
            var keyIndex = (startIndex + i) % apiKeys.Count;
            using var request = new HttpRequestMessage(HttpMethod.Post, url);
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", apiKeys[keyIndex]);
            request.Content = new StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json");

            using var response = await client.SendAsync(request, cancellationToken);
            var body = await response.Content.ReadAsStringAsync(cancellationToken);
            if (!response.IsSuccessStatusCode)
            {
                lastBody = body;
                if (i < apiKeys.Count - 1 && ShouldTryNextKey(response.StatusCode, body))
                {
                    continue;
                }

                _logger.LogWarning("DeepSeek respondeu erro {Status}: {Body}", response.StatusCode, body);
                return null;
            }

            return body;
        }

        _logger.LogWarning("DeepSeek falhou em todas as chaves: {Body}", lastBody);
        return null;
    }

    private static List<string> GetApiKeys(DeepSeekSettings settings)
    {
        var keys = new List<string>();
        if (!string.IsNullOrWhiteSpace(settings.ApiKey) && settings.ApiKey != "********")
        {
            keys.Add(settings.ApiKey.Trim());
        }

        if (settings.ApiKeys is not null)
        {
            keys.AddRange(settings.ApiKeys
                .Where(x => !string.IsNullOrWhiteSpace(x))
                .Select(x => x.Trim())
                .Where(x => x != "********"));
        }

        return keys.Distinct(StringComparer.Ordinal).ToList();
    }

    private static bool ShouldTryNextKey(System.Net.HttpStatusCode statusCode, string? body)
    {
        var status = (int)statusCode;
        if (status is 401 or 403 or 429 or 500 or 502 or 503 or 504)
        {
            return true;
        }

        return !string.IsNullOrWhiteSpace(body) &&
               (body.Contains("quota", StringComparison.OrdinalIgnoreCase) ||
                body.Contains("rate limit", StringComparison.OrdinalIgnoreCase) ||
                body.Contains("exhaust", StringComparison.OrdinalIgnoreCase));
    }

    private static string? ExtractChatOutputText(string json)
    {
        try
        {
            using var doc = JsonDocument.Parse(json);
            if (!doc.RootElement.TryGetProperty("choices", out var choices) || choices.ValueKind != JsonValueKind.Array || choices.GetArrayLength() == 0)
            {
                return null;
            }

            var first = choices[0];
            if (first.TryGetProperty("message", out var message) && message.TryGetProperty("content", out var content))
            {
                return content.GetString();
            }

            return null;
        }
        catch
        {
            return null;
        }
    }

    private static AchadinhosBot.Next.Domain.Logs.InstagramAiLogEntry BuildLogEntry(
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
        return new AchadinhosBot.Next.Domain.Logs.InstagramAiLogEntry
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

    private static string? AppendImagesIfMissing(string? text, IReadOnlyCollection<string>? images)
    {
        if (string.IsNullOrWhiteSpace(text) || images == null || images.Count == 0)
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
