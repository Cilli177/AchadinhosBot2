using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Domain.Settings;
using AchadinhosBot.Next.Infrastructure.ProductData;

namespace AchadinhosBot.Next.Infrastructure.Instagram;

public sealed class QwenInstagramPostGenerator
{
    private static int _currentKeyIndex = -1;

    private readonly IHttpClientFactory _httpClientFactory;
    private readonly ILogger<QwenInstagramPostGenerator> _logger;
    private readonly IInstagramAiLogStore _logStore;
    private readonly InstagramLinkMetaService _metaService;
    private readonly InstagramImageDownloadService _imageDownloadService;
    private readonly OfficialProductDataService _officialService;

    public QwenInstagramPostGenerator(
        IHttpClientFactory httpClientFactory,
        ILogger<QwenInstagramPostGenerator> logger,
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

    public async Task<string?> GenerateAsync(string productInput, string? offerContext, string? affiliateLink, InstagramPostSettings instaSettings, QwenSettings aiSettings, CancellationToken cancellationToken)
    {
        var apiKeys = GetApiKeys(aiSettings);
        if (apiKeys.Count == 0)
        {
            return null;
        }

        var model = string.IsNullOrWhiteSpace(aiSettings.Model) ? "qwen3.5-plus" : aiSettings.Model.Trim();
        var baseUrl = string.IsNullOrWhiteSpace(aiSettings.BaseUrl)
            ? "https://dashscope-intl.aliyuncs.com/compatible-mode/v1"
            : aiSettings.BaseUrl.Trim();

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
            officialContext = $"Produto: {officialData.Title}\nPreco Atual: {officialData.CurrentPrice}";
            if (!string.IsNullOrWhiteSpace(officialData.PreviousPrice)) officialContext += $"\nPreco Anterior: {officialData.PreviousPrice}";
            if (officialData.DiscountPercent > 0) officialContext += $"\nDesconto: {officialData.DiscountPercent}%";
            if (!string.IsNullOrWhiteSpace(officialData.EstimatedDelivery)) officialContext += $"\nEntrega: {officialData.EstimatedDelivery}";
        }

        var effectiveInput = OpenAiInstagramPostGenerator.ResolveEffectiveInput(productInput, officialData?.Title ?? meta.Title, affiliateLink ?? productInput);
        var effectiveContext = !string.IsNullOrWhiteSpace(offerContext) ? offerContext : (string.IsNullOrWhiteSpace(officialContext) ? meta.Description : officialContext);
        var title = officialData?.Title ?? meta.Title;
        var description = string.IsNullOrWhiteSpace(officialContext) ? meta.Description : officialContext;
        var prompt = OpenAiInstagramPostGenerator.BuildPrompt(effectiveInput, effectiveContext, affiliateLink, images, title, description, instaSettings);

        var payload = BuildChatPayload(
            model,
            aiSettings.Temperature,
            aiSettings.MaxOutputTokens,
            "Voce cria posts profissionais para Instagram em portugues do Brasil.",
            prompt.Trim(),
            aiSettings.EnableThinking);

        var started = DateTimeOffset.UtcNow;
        var finalText = await PostForTextAsync(apiKeys, baseUrl, payload, cancellationToken);
        if (string.IsNullOrWhiteSpace(finalText))
        {
            await _logStore.AppendAsync(BuildLogEntry(instaSettings, model, "qwen", productInput, affiliateLink, images.Count, images, null, "Falha na geracao", started, 0, "Erro na geracao"), cancellationToken);
            return null;
        }

        finalText = AppendImagesIfMissing(finalText, images);
        var (score, notes) = EvaluateQuality(finalText);
        await _logStore.AppendAsync(BuildLogEntry(instaSettings, model, "qwen", productInput, affiliateLink, images.Count, images, finalText, null, started, score, notes), cancellationToken);
        return finalText;
    }

    public Task<string?> GenerateFreeformAsync(string prompt, QwenSettings aiSettings, CancellationToken cancellationToken)
        => GenerateChatAsync(prompt, "Responda em portugues do Brasil com clareza e sem formatacao extra desnecessaria.", aiSettings, cancellationToken);

    public async Task<string?> AnalyzeImagesAsync(string prompt, IReadOnlyCollection<string> imageUrls, QwenSettings aiSettings, CancellationToken cancellationToken)
    {
        var apiKeys = GetApiKeys(aiSettings);
        if (apiKeys.Count == 0 || string.IsNullOrWhiteSpace(prompt) || imageUrls.Count == 0)
        {
            return null;
        }

        var model = string.IsNullOrWhiteSpace(aiSettings.VisionModel) ? "qwen3-vl-plus" : aiSettings.VisionModel.Trim();
        var baseUrl = string.IsNullOrWhiteSpace(aiSettings.BaseUrl)
            ? "https://dashscope-intl.aliyuncs.com/compatible-mode/v1"
            : aiSettings.BaseUrl.Trim();

        var content = new List<object> { new { type = "text", text = prompt.Trim() } };
        foreach (var imageUrl in imageUrls.Where(url => !string.IsNullOrWhiteSpace(url)).Take(4))
        {
            content.Add(new { type = "image_url", image_url = new { url = imageUrl.Trim() } });
        }

        var payload = new
        {
            model,
            messages = new object[]
            {
                new { role = "system", content = "Voce analisa imagens de ofertas e responde em portugues do Brasil." },
                new { role = "user", content = content.ToArray() }
            },
            temperature = aiSettings.Temperature,
            max_tokens = Math.Clamp(aiSettings.MaxOutputTokens <= 0 ? 4096 : aiSettings.MaxOutputTokens, 200, 8192),
            stream = false,
            enable_thinking = aiSettings.EnableThinking
        };

        var result = await PostForTextAsync(apiKeys, baseUrl, payload, cancellationToken);
        if (!string.IsNullOrWhiteSpace(result))
        {
            return result;
        }

        if (!model.Equals("qwen-vl-plus", StringComparison.OrdinalIgnoreCase))
        {
            var fallbackPayload = new
            {
                model = "qwen-vl-plus",
                messages = new object[]
                {
                    new { role = "system", content = "Voce analisa imagens de ofertas e responde em portugues do Brasil." },
                    new { role = "user", content = content.ToArray() }
                },
                temperature = aiSettings.Temperature,
                max_tokens = Math.Clamp(aiSettings.MaxOutputTokens <= 0 ? 4096 : aiSettings.MaxOutputTokens, 200, 8192),
                stream = false,
                enable_thinking = aiSettings.EnableThinking
            };

            _logger.LogInformation("Qwen vision fallback ativado: tentando qwen-vl-plus apos falha com {Model}.", model);
            return await PostForTextAsync(apiKeys, baseUrl, fallbackPayload, cancellationToken);
        }

        return null;
    }

    public async Task<string?> GenerateAgenticAsync(string prompt, object[]? tools, QwenSettings aiSettings, CancellationToken cancellationToken)
    {
        var apiKeys = GetApiKeys(aiSettings);
        if (apiKeys.Count == 0 || string.IsNullOrWhiteSpace(prompt))
        {
            return null;
        }

        var model = string.IsNullOrWhiteSpace(aiSettings.Model) ? "qwen3.5-plus" : aiSettings.Model.Trim();
        var baseUrl = string.IsNullOrWhiteSpace(aiSettings.BaseUrl)
            ? "https://dashscope-intl.aliyuncs.com/compatible-mode/v1"
            : aiSettings.BaseUrl.Trim();

        var payload = new
        {
            model,
            messages = new object[]
            {
                new { role = "system", content = "Voce e um agente operacional de ofertas. Use ferramentas quando fizer sentido e responda em portugues do Brasil." },
                new { role = "user", content = prompt.Trim() }
            },
            tools = tools ?? Array.Empty<object>(),
            tool_choice = tools is { Length: > 0 } ? "auto" : null,
            temperature = aiSettings.Temperature,
            max_tokens = Math.Clamp(aiSettings.MaxOutputTokens <= 0 ? 4096 : aiSettings.MaxOutputTokens, 200, 8192),
            stream = false,
            enable_thinking = aiSettings.EnableThinking
        };

        return await PostForTextAsync(apiKeys, baseUrl, payload, cancellationToken);
    }

    private Task<string?> GenerateChatAsync(string prompt, string systemPrompt, QwenSettings aiSettings, CancellationToken cancellationToken)
    {
        var apiKeys = GetApiKeys(aiSettings);
        if (apiKeys.Count == 0 || string.IsNullOrWhiteSpace(prompt))
        {
            return Task.FromResult<string?>(null);
        }

        var model = string.IsNullOrWhiteSpace(aiSettings.Model) ? "qwen3.5-plus" : aiSettings.Model.Trim();
        var baseUrl = string.IsNullOrWhiteSpace(aiSettings.BaseUrl)
            ? "https://dashscope-intl.aliyuncs.com/compatible-mode/v1"
            : aiSettings.BaseUrl.Trim();

        var payload = BuildChatPayload(
            model,
            aiSettings.Temperature,
            aiSettings.MaxOutputTokens,
            systemPrompt,
            prompt.Trim(),
            aiSettings.EnableThinking);

        return PostForTextAsync(apiKeys, baseUrl, payload, cancellationToken);
    }

    private async Task<string?> PostForTextAsync(IReadOnlyList<string> apiKeys, string baseUrl, object payload, CancellationToken cancellationToken)
    {
        var client = _httpClientFactory.CreateClient("qwen");
        var startIndex = unchecked((int)((uint)Interlocked.Increment(ref _currentKeyIndex) % (uint)apiKeys.Count));
        string? lastBody = null;

        for (var i = 0; i < apiKeys.Count; i++)
        {
            var keyIndex = (startIndex + i) % apiKeys.Count;
            var apiKey = apiKeys[keyIndex];
            using var request = new HttpRequestMessage(HttpMethod.Post, $"{baseUrl.TrimEnd('/')}/chat/completions");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", apiKey);
            request.Content = new StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json");

            using var response = await client.SendAsync(request, cancellationToken);
            var body = await response.Content.ReadAsStringAsync(cancellationToken);
            if (!response.IsSuccessStatusCode)
            {
                lastBody = body;
                if (i < apiKeys.Count - 1 && ShouldTryNextKey(response.StatusCode, body))
                {
                    _logger.LogWarning("Qwen chave {KeyIndex}/{Total} falhou com {Status}. Tentando proxima chave.", keyIndex + 1, apiKeys.Count, response.StatusCode);
                    continue;
                }

                _logger.LogWarning("Qwen respondeu erro {Status}: {Body}", response.StatusCode, body);
                return null;
            }

            return ExtractChatOutputText(body)?.Trim();
        }

        _logger.LogWarning("Qwen falhou em todas as chaves: {Body}", lastBody);
        return null;
    }

    private static object BuildChatPayload(string model, double temperature, int maxTokens, string systemPrompt, string prompt, bool enableThinking)
        => new
        {
            model,
            messages = new object[]
            {
                new { role = "system", content = systemPrompt },
                new { role = "user", content = prompt }
            },
            temperature,
            max_tokens = Math.Clamp(maxTokens <= 0 ? 4096 : maxTokens, 200, 8192),
            stream = false,
            enable_thinking = enableThinking
        };

    private static List<string> GetApiKeys(QwenSettings settings)
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

    private static bool ShouldTryNextKey(HttpStatusCode statusCode, string? body)
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
                return content.ValueKind == JsonValueKind.String ? content.GetString() : content.ToString();
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
        var score = 40;
        if (text.Contains("Comente", StringComparison.OrdinalIgnoreCase)) score += 15;
        if (text.Contains("R$", StringComparison.OrdinalIgnoreCase)) score += 10;
        if (text.Length > 180) score += 10;
        if (text.Split('\n').Length >= 4) score += 10;
        return (Math.Min(score, 100), "avaliacao heuristica qwen");
    }
}
