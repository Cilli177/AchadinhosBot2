using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using AchadinhosBot.Next.Domain.Settings;

namespace AchadinhosBot.Next.Infrastructure.Instagram;

public sealed class VilaNvidiaGenerator
{
    private static int _currentKeyIndex = -1;

    private readonly IHttpClientFactory _httpClientFactory;
    private readonly ILogger<VilaNvidiaGenerator> _logger;

    public VilaNvidiaGenerator(
        IHttpClientFactory httpClientFactory,
        ILogger<VilaNvidiaGenerator> logger)
    {
        _httpClientFactory = httpClientFactory;
        _logger = logger;
    }

    public Task<string?> GenerateFreeformAsync(string prompt, VilaNvidiaSettings settings, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(prompt))
        {
            return Task.FromResult<string?>(null);
        }

        var payload = BuildPayload(
            ResolveModel(settings),
            prompt.Trim(),
            temperature: settings.Temperature,
            topP: settings.TopP,
            maxTokens: settings.MaxOutputTokens,
            enableThinking: settings.EnableThinking);

        return PostForTextAsync(GetApiKeys(settings), ResolveBaseUrl(settings), payload, cancellationToken);
    }

    public Task<string?> AnalyzeImagesAsync(string prompt, IReadOnlyCollection<string> imageUrls, VilaNvidiaSettings settings, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(prompt) || imageUrls.Count == 0)
        {
            return Task.FromResult<string?>(null);
        }

        var content = new List<object>
        {
            new { type = "text", text = prompt.Trim() }
        };

        foreach (var imageUrl in imageUrls.Where(url => !string.IsNullOrWhiteSpace(url)).Take(4))
        {
            content.Add(new
            {
                type = "image_url",
                image_url = new { url = imageUrl.Trim() }
            });
        }

        var payload = new
        {
            model = ResolveModel(settings),
            messages = new object[]
            {
                new { role = "system", content = "Voce analisa imagens de ofertas e responde em portugues do Brasil." },
                new { role = "user", content = content.ToArray() }
            },
            max_tokens = Math.Clamp(settings.MaxOutputTokens <= 0 ? 4096 : settings.MaxOutputTokens, 200, 16384),
            temperature = settings.Temperature,
            top_p = settings.TopP,
            stream = false,
            chat_template_kwargs = new { enable_thinking = settings.EnableThinking }
        };

        return PostForTextAsync(GetApiKeys(settings), ResolveBaseUrl(settings), payload, cancellationToken);
    }

    public async Task<(int Score, bool IsMatch, string Reason)?> EvaluateImageMatchAsync(
        string productName,
        string caption,
        string imageUrl,
        VilaNvidiaSettings settings,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(productName) || string.IsNullOrWhiteSpace(imageUrl))
        {
            return null;
        }

        var shortCaption = (caption ?? string.Empty).Trim();
        if (shortCaption.Length > 280)
        {
            shortCaption = shortCaption[..280];
        }

        var prompt =
            "Valide se a imagem representa o produto informado. " +
            $"Produto: {productName}. " +
            $"Legenda resumida: {shortCaption}. " +
            "Responda somente JSON valido no formato " +
            "{\"score\":0-100,\"isMatch\":true|false,\"reason\":\"texto curto\",\"styleNotes\":\"texto curto opcional\"}.";

        var raw = await AnalyzeImagesAsync(prompt, new[] { imageUrl }, settings, cancellationToken);
        if (string.IsNullOrWhiteSpace(raw))
        {
            return null;
        }

        try
        {
            var json = ExtractFirstJsonObject(raw) ?? raw.Trim();
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;
            var score = root.TryGetProperty("score", out var scoreNode) && scoreNode.TryGetInt32(out var parsedScore)
                ? parsedScore
                : 0;
            score = Math.Clamp(score, 0, 100);

            var isMatch = root.TryGetProperty("isMatch", out var matchNode) && matchNode.ValueKind is JsonValueKind.True or JsonValueKind.False
                ? matchNode.GetBoolean()
                : score >= 55;

            var reason = root.TryGetProperty("reason", out var reasonNode) ? reasonNode.GetString() : null;
            if (root.TryGetProperty("styleNotes", out var styleNode) && styleNode.ValueKind == JsonValueKind.String)
            {
                var style = styleNode.GetString()?.Trim();
                if (!string.IsNullOrWhiteSpace(style))
                {
                    reason = string.IsNullOrWhiteSpace(reason) ? style : $"{reason.Trim()} | estilo: {style}";
                }
            }

            reason = string.IsNullOrWhiteSpace(reason) ? $"vila_match={isMatch}" : reason.Trim();
            return (score, isMatch, reason);
        }
        catch
        {
            return null;
        }
    }

    private async Task<string?> PostForTextAsync(IReadOnlyList<string> apiKeys, string baseUrl, object payload, CancellationToken cancellationToken)
    {
        if (apiKeys.Count == 0)
        {
            return null;
        }

        var client = _httpClientFactory.CreateClient("default");
        var startIndex = unchecked((int)((uint)Interlocked.Increment(ref _currentKeyIndex) % (uint)apiKeys.Count));
        string? lastBody = null;

        for (var i = 0; i < apiKeys.Count; i++)
        {
            var keyIndex = (startIndex + i) % apiKeys.Count;
            using var request = new HttpRequestMessage(HttpMethod.Post, $"{baseUrl.TrimEnd('/')}/chat/completions");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", apiKeys[keyIndex]);
            request.Content = new StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json");

            using var response = await client.SendAsync(request, cancellationToken);
            var body = await response.Content.ReadAsStringAsync(cancellationToken);
            if (!response.IsSuccessStatusCode)
            {
                lastBody = body;
                if (i < apiKeys.Count - 1 && ShouldTryNextKey(response.StatusCode, body))
                {
                    _logger.LogWarning("VILA chave {KeyIndex}/{Total} falhou com {Status}. Tentando proxima chave.", keyIndex + 1, apiKeys.Count, response.StatusCode);
                    continue;
                }

                _logger.LogWarning("VILA respondeu erro {Status}: {Body}", response.StatusCode, body);
                return null;
            }

            return ExtractChatOutputText(body)?.Trim();
        }

        _logger.LogWarning("VILA falhou em todas as chaves: {Body}", lastBody);
        return null;
    }

    private static object BuildPayload(string model, string prompt, double temperature, double topP, int maxTokens, bool enableThinking)
        => new
        {
            model,
            messages = new object[]
            {
                new { role = "system", content = "Voce responde em portugues do Brasil com clareza e sem formatacao desnecessaria." },
                new { role = "user", content = prompt }
            },
            max_tokens = Math.Clamp(maxTokens <= 0 ? 4096 : maxTokens, 200, 16384),
            temperature,
            top_p = topP,
            stream = false,
            chat_template_kwargs = new { enable_thinking = enableThinking }
        };

    private static string ResolveModel(VilaNvidiaSettings settings)
        => string.IsNullOrWhiteSpace(settings.Model) ? "nvidia/vila" : settings.Model.Trim();

    private static string ResolveBaseUrl(VilaNvidiaSettings settings)
        => string.IsNullOrWhiteSpace(settings.BaseUrl) ? "https://integrate.api.nvidia.com/v1" : settings.BaseUrl.Trim();

    private static List<string> GetApiKeys(VilaNvidiaSettings settings)
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

        return keys.Distinct(StringComparer.Ordinal).ToList();
    }

    private static bool ShouldTryNextKey(HttpStatusCode statusCode, string? body)
    {
        var status = (int)statusCode;
        if (status is 401 or 403 or 429 or 500 or 502 or 503 or 504)
        {
            return true;
        }

        if (status == 400 && !string.IsNullOrWhiteSpace(body))
        {
            return body.Contains("quota", StringComparison.OrdinalIgnoreCase) ||
                   body.Contains("rate", StringComparison.OrdinalIgnoreCase) ||
                   body.Contains("temporarily", StringComparison.OrdinalIgnoreCase);
        }

        return false;
    }

    private static string? ExtractChatOutputText(string json)
    {
        using var doc = JsonDocument.Parse(json);
        if (!doc.RootElement.TryGetProperty("choices", out var choices) || choices.ValueKind != JsonValueKind.Array)
        {
            return null;
        }

        foreach (var choice in choices.EnumerateArray())
        {
            if (!choice.TryGetProperty("message", out var message))
            {
                continue;
            }

            if (message.TryGetProperty("content", out var content))
            {
                if (content.ValueKind == JsonValueKind.String)
                {
                    return content.GetString();
                }

                if (content.ValueKind == JsonValueKind.Array)
                {
                    var parts = content.EnumerateArray()
                        .Select(part =>
                        {
                            if (part.ValueKind == JsonValueKind.String)
                            {
                                return part.GetString();
                            }

                            if (part.TryGetProperty("text", out var textNode))
                            {
                                return textNode.GetString();
                            }

                            return null;
                        })
                        .Where(x => !string.IsNullOrWhiteSpace(x));

                    var joined = string.Join("\n", parts!);
                    if (!string.IsNullOrWhiteSpace(joined))
                    {
                        return joined;
                    }
                }
            }
        }

        return null;
    }

    private static string? ExtractFirstJsonObject(string text)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            return null;
        }

        var start = text.IndexOf('{');
        if (start < 0)
        {
            return null;
        }

        var depth = 0;
        for (var i = start; i < text.Length; i++)
        {
            var c = text[i];
            if (c == '{') depth++;
            if (c == '}') depth--;
            if (depth == 0)
            {
                return text[start..(i + 1)];
            }
        }

        return null;
    }
}
