using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Domain.Settings;

using AchadinhosBot.Next.Infrastructure.ProductData;

namespace AchadinhosBot.Next.Infrastructure.Instagram;

public sealed class OpenAiInstagramPostGenerator
{
    private static int _currentKeyIndex = -1;
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly ILogger<OpenAiInstagramPostGenerator> _logger;
    private readonly IInstagramAiLogStore _logStore;
    private readonly InstagramLinkMetaService _metaService;
    private readonly InstagramImageDownloadService _imageDownloadService;
    private readonly OfficialProductDataService _officialService;

    public OpenAiInstagramPostGenerator(
        IHttpClientFactory httpClientFactory,
        ILogger<OpenAiInstagramPostGenerator> logger,
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

    public async Task<string?> GenerateAsync(string productInput, string? offerContext, string? affiliateLink, InstagramPostSettings instaSettings, OpenAISettings aiSettings, CancellationToken cancellationToken)
    {
        var apiKeys = GetApiKeys(aiSettings);
        if (apiKeys.Count == 0)
        {
            return null;
        }

        var model = string.IsNullOrWhiteSpace(aiSettings.Model) ? "gpt-4o-mini" : aiSettings.Model.Trim();
        var baseUrl = string.IsNullOrWhiteSpace(aiSettings.BaseUrl) ? "https://api.openai.com/v1" : aiSettings.BaseUrl.Trim();

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

        var effectiveInput = ResolveEffectiveInput(productInput, officialData?.Title ?? meta.Title, affiliateLink ?? productInput);
        var effectiveContext = !string.IsNullOrWhiteSpace(offerContext) ? offerContext : (string.IsNullOrWhiteSpace(officialContext) ? meta.Description : officialContext);
        
        var title = officialData?.Title ?? meta.Title;
        var description = string.IsNullOrWhiteSpace(officialContext) ? meta.Description : officialContext;

        var prompt = BuildPrompt(effectiveInput, effectiveContext, affiliateLink, images, title, description, instaSettings);

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
            var body = await PostWithKeyRotationAsync(apiKeys, $"{baseUrl.TrimEnd('/')}/responses", payload, cancellationToken);
            if (string.IsNullOrWhiteSpace(body))
            {
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

    public async Task<string?> GenerateFreeformAsync(string prompt, OpenAISettings aiSettings, CancellationToken cancellationToken)
    {
        var apiKeys = GetApiKeys(aiSettings);
        if (apiKeys.Count == 0 || string.IsNullOrWhiteSpace(prompt))
        {
            return null;
        }

        var model = string.IsNullOrWhiteSpace(aiSettings.Model) ? "gpt-4o-mini" : aiSettings.Model.Trim();
        var baseUrl = string.IsNullOrWhiteSpace(aiSettings.BaseUrl) ? "https://api.openai.com/v1" : aiSettings.BaseUrl.Trim();
        var payload = new
        {
            model,
            input = new[]
            {
                new { role = "system", content = "Responda em portugues do Brasil com clareza e sem formatacao extra desnecessaria." },
                new { role = "user", content = prompt.Trim() }
            },
            temperature = aiSettings.Temperature,
            max_output_tokens = aiSettings.MaxOutputTokens
        };

        try
        {
            var body = await PostWithKeyRotationAsync(apiKeys, $"{baseUrl.TrimEnd('/')}/responses", payload, cancellationToken);
            if (string.IsNullOrWhiteSpace(body))
            {
                return null;
            }

            return ExtractOutputText(body)?.Trim();
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Falha ao gerar resposta livre via OpenAI");
            return null;
        }
    }

    public async Task<string?> GenerateHashtagsAsync(string productInput, OpenAISettings aiSettings, CancellationToken cancellationToken)
    {
        var apiKeys = GetApiKeys(aiSettings);
        if (apiKeys.Count == 0)
        {
            return null;
        }

        var model = string.IsNullOrWhiteSpace(aiSettings.Model) ? "gpt-4o-mini" : aiSettings.Model.Trim();
        var baseUrl = string.IsNullOrWhiteSpace(aiSettings.BaseUrl) ? "https://api.openai.com/v1" : aiSettings.BaseUrl.Trim();

        var payload = new
        {
            model,
            messages = new[]
            {
                new { role = "system", content = "Voc\u00ea \u00e9 um especialista em growth e copywriter premium de afiliados. Gere uma lista de 15 a 20 hashtags de alto n\u00edvel, misturando as mais virais do momento com hashtags espec\u00edficas para atrair compradores reais e visualiza\u00e7\u00f5es no Explorar. Responda apenas as hashtags separadas por espa\u00e7o." },
                new { role = "user", content = $"Produto: {productInput}\n\nGere as hashtags de alto n\u00edvel para este produto:" }
            },
            temperature = 0.8,
            max_tokens = 150
        };

        try
        {
            var body = await PostWithKeyRotationAsync(apiKeys, $"{baseUrl.TrimEnd('/')}/chat/completions", payload, cancellationToken);
            if (string.IsNullOrWhiteSpace(body)) return null;

            using var doc = JsonDocument.Parse(body);
            if (doc.RootElement.TryGetProperty("choices", out var choices) && choices.GetArrayLength() > 0)
            {
                var content = choices[0].GetProperty("message").GetProperty("content").GetString();
                return content?.Trim();
            }
            return null;
        }
        catch
        {
            return null;
        }
    }

    private async Task<string?> PostWithKeyRotationAsync(IReadOnlyList<string> apiKeys, string url, object payload, CancellationToken cancellationToken)
    {
        var client = _httpClientFactory.CreateClient("openai");
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

                _logger.LogWarning("OpenAI respondeu erro {Status}: {Body}", response.StatusCode, body);
                return null;
            }

            return body;
        }

        _logger.LogWarning("OpenAI falhou em todas as chaves: {Body}", lastBody);
        return null;
    }

    private static List<string> GetApiKeys(OpenAISettings settings)
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
            ? "{{format}}\n\nDiretrizes obrigatorias:\n- Escreva como um copywriter premium de ofertas no Brasil.\n- Entregue na area de legenda apenas copy publicavel. Nao inclua titulos como \"POST PARA INSTAGRAM\", \"Legenda 1\", \"Hashtags sugeridas\", \"Sugestoes de imagem\", observacoes internas ou explicacoes.\n- Gere legendas mais profissionais, com gancho forte na abertura e CTA claro no final.\n- Use beneficios concretos, preco, desconto, cupom e prazo somente quando estiverem no contexto.\n- Nao invente urgencia, estoque, frete gratis, parcelamento ou condicoes nao informadas.\n- Cada legenda deve ter angulo diferente: autoridade, oportunidade, desejo, praticidade ou comparacao.\n- Evite texto generico. Nada de introducoes vazias como \"olha isso\" ou \"imperdivel\" sem contexto.\n- Evite excesso de emojis. No maximo 3 bem colocados.\n- Deixe a leitura pronta para Instagram, com blocos curtos e escaneaveis.\n- Inclua CTA de comentario ou direct de forma natural.\n- Se precisar registrar comentarios, riscos ou sugestoes, deixe isso fora da legenda.\n\nDados:\nEntrada: {{input}}\nLink afiliado: {{link}}\nContexto da oferta: {{context}}\nRodape: {{footer}}\n"
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
            prompt = "Voc\u00ea \u00e9 um expert em growth e copywriter premium de afiliados no Brasil, n\u00edvel autoridade.\n" +
                     "Crie um post de alt\u00edssima qualidade, elegante, comercialmente forte e pronto para conversao.\n" +
                     "Nas hashtags, inclua obrigatoriamente padr\u00f5es de alto n\u00edvel como #achadinhos #ofertas #promo\u00e7\u00e3o #compras #dicas e varia\u00e7\u00f5es virais.\n" +
                     "Evite genericidade e use um tom que gere desejo imediato sem parecer spam. Linguagem humana, comercial e engajadora.\n" +
                     "Crie legendas CLARAMENTE diferentes entre si, cada uma com angulo proprio e CTA forte.\n" +
                     "Priorize: gancho inicial forte, beneficio real, prova de valor, fechamento com CTA.\n" +
                     "Se houver preco, desconto, cupom ou entrega no contexto, incorpore esses dados com naturalidade.\n" +
                     "Retorne apenas as legendas publicaveis. Nao inclua notas do agente, cabecalhos, listas de hashtags avulsas ou sugestoes de imagem misturadas com a copy.\n" +
                     "N\u00e3o invente dados que n\u00e3o foram fornecidos.\n\n" +
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
