using System.Text.Json;
using AchadinhosBot.Next.Domain.Settings;
using AchadinhosBot.Next.Infrastructure.Instagram;

namespace AchadinhosBot.Next.Application.Services;

public sealed class WhatsAppNicheAiClassifier
{
    private static readonly HashSet<string> AllowedSlugs =
    [
        WhatsAppNicheDefinitions.Casa,
        WhatsAppNicheDefinitions.Beleza,
        WhatsAppNicheDefinitions.FitnessHealth,
        WhatsAppNicheDefinitions.Moda,
        WhatsAppNicheDefinitions.Tech
    ];

    private readonly OpenAiInstagramPostGenerator _openAiGenerator;
    private readonly GeminiInstagramPostGenerator _geminiGenerator;
    private readonly DeepSeekInstagramPostGenerator _deepSeekGenerator;
    private readonly NemotronInstagramPostGenerator _nemotronGenerator;
    private readonly QwenInstagramPostGenerator _qwenGenerator;
    private readonly VilaNvidiaGenerator _vilaGenerator;

    public WhatsAppNicheAiClassifier(
        OpenAiInstagramPostGenerator openAiGenerator,
        GeminiInstagramPostGenerator geminiGenerator,
        DeepSeekInstagramPostGenerator deepSeekGenerator,
        NemotronInstagramPostGenerator nemotronGenerator,
        QwenInstagramPostGenerator qwenGenerator,
        VilaNvidiaGenerator vilaGenerator)
    {
        _openAiGenerator = openAiGenerator;
        _geminiGenerator = geminiGenerator;
        _deepSeekGenerator = deepSeekGenerator;
        _nemotronGenerator = nemotronGenerator;
        _qwenGenerator = qwenGenerator;
        _vilaGenerator = vilaGenerator;
    }

    public async Task<WhatsAppNicheAiDecision?> ClassifyAsync(string text, string? heuristicTitle, AutomationSettings settings, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(text) || settings.InstagramPosts?.UseAi != true)
        {
            return null;
        }

        var provider = string.IsNullOrWhiteSpace(settings.InstagramPosts.AiProvider)
            ? "openai"
            : settings.InstagramPosts.AiProvider.Trim().ToLowerInvariant();

        var prompt = $$"""
        Voce classifica ofertas de varejo para grupos de WhatsApp.
        Responda APENAS JSON valido, sem markdown.

        Slugs permitidos:
        - casa
        - beleza
        - fitness_health
        - moda
        - tech
        - review

        Como analisar:
        - Analise o ANUNCIO COMPLETO antes de decidir. O titulo heuristico pode estar ausente, generico ou ser apenas frase de chamariz.
        - Use todas as pistas: nome do produto, emojis, loja, preco, linhas de "De/Por", CTA ("Compre aqui", "Pegar oferta"), descricao, imagem quando informada e link principal.
        - Ignore rodape institucional, bio, "Mais ofertas no grupo VIP", aviso de promocao, links de destaque/bio e textos de tracking.
        - Cupom detectado dentro de uma oferta nao muda o nicho do produto. Exemplo: sanduicheira com cupom continua "casa"; tenis com cupom continua "moda".
        - Se o anuncio for apenas cupom/campanha sem produto concreto, classifique como campanha ampla usando "casa" com alta confianca.
        - Se houver comparativo de precos ou dois links, escolha o nicho do produto principal anunciado, nao do link de cupom nem do rodape.
        - Recupere o nome real do produto a partir do anuncio completo. Nunca use preco, slogan, "Mercado Livre", "Amazon", "Shopee", "Teste aqui" ou linha de cupom como productName.
        - Se a imagem informada contradizer claramente o texto do produto, use "review" e explique imagem_inconsistente.

        Regras de nicho:
        - "casa": eletrodomesticos, moveis, cozinha, limpeza, cama, banho, organizacao, ferramentas domesticas, alimentos/mercado e bebidas enquanto nao houver nicho proprio.
        - "beleza": perfume, skincare, maquiagem, cabelo, higiene e cosmeticos.
        - "fitness_health": whey, creatina, suplementos e nutricao esportiva.
        - "moda": roupas, calcados e acessorios de vestir.
        - "tech": celular, notebook, audio, games, eletronicos, componentes de computador e bicicleta eletrica/mobilidade eletrica.
        - Album/figurinhas da Copa e cupons soltos podem ser usados como campanha ampla; se precisar escolher um slug unico, use "casa" com alta confianca.
        - Use "review" para automotivo fora de mobilidade eletrica, produtos sem nome claro ou qualquer caso realmente duvidoso.
        - Se o nome tiver "Vodka Man", "Whisky Silver" ou texto parecido mas for perfume/deo colonia, classifique como beleza.
        - Tente recuperar o nome real do produto, nao slogans, precos ou linhas de cupom.

        Schema:
        {
          "productName": "nome curto do produto",
          "slug": "casa|beleza|fitness_health|moda|tech|review",
          "confidence": 0-100,
          "reason": "motivo curto"
        }

        Titulo heuristico atual, se houver: {{heuristicTitle ?? "(ausente)"}}

        Contexto/anuncio completo:
        {{text}}
        """;

        var raw = await GenerateAsync(prompt, provider, settings, ct);
        if (string.IsNullOrWhiteSpace(raw))
        {
            return null;
        }

        try
        {
            using var doc = JsonDocument.Parse(ExtractJsonObject(raw));
            var root = doc.RootElement;
            var slug = GetString(root, "slug");
            var productName = GetString(root, "productName");
            var confidence = GetInt(root, "confidence");
            var reason = GetString(root, "reason") ?? "ai_no_reason";
            if (string.IsNullOrWhiteSpace(slug))
            {
                return null;
            }

            slug = slug.Trim().ToLowerInvariant();
            if (slug == "review")
            {
                return new WhatsAppNicheAiDecision(productName, null, confidence, reason, true, provider);
            }

            if (!AllowedSlugs.Contains(slug))
            {
                return null;
            }

            return new WhatsAppNicheAiDecision(productName, slug, confidence, reason, confidence < 85, provider);
        }
        catch
        {
            return null;
        }
    }

    private static string ExtractJsonObject(string raw)
    {
        var value = raw.Trim();
        if (value.StartsWith("```", StringComparison.Ordinal))
        {
            var firstLineBreak = value.IndexOf('\n');
            if (firstLineBreak >= 0)
            {
                value = value[(firstLineBreak + 1)..];
            }

            var fence = value.LastIndexOf("```", StringComparison.Ordinal);
            if (fence >= 0)
            {
                value = value[..fence];
            }
        }

        var start = value.IndexOf('{');
        var end = value.LastIndexOf('}');
        if (start >= 0 && end > start)
        {
            value = value[start..(end + 1)];
        }

        return value.Trim();
    }

    private async Task<string?> GenerateAsync(string prompt, string provider, AutomationSettings settings, CancellationToken ct)
        => provider switch
        {
            "gemini" => await _geminiGenerator.GenerateFreeformAsync(prompt, settings.Gemini ?? new GeminiSettings(), ct),
            "gemma4" => await _geminiGenerator.GenerateFreeformAsync(prompt, GeminiInstagramPostGenerator.WithGeminiKeyFallback(settings.Gemma4, settings.Gemini).AsAdvanced(), ct),
            "deepseek" => await _deepSeekGenerator.GenerateFreeformAsync(prompt, settings.DeepSeek ?? new DeepSeekSettings(), ct),
            "nemotron" => await _nemotronGenerator.GenerateFreeformAsync(prompt, settings.Nemotron ?? new NemotronSettings(), ct),
            "qwen" => await _qwenGenerator.GenerateFreeformAsync(prompt, settings.Qwen ?? new QwenSettings(), ct),
            "vila" => await _vilaGenerator.GenerateFreeformAsync(prompt, settings.VilaNvidia ?? new VilaNvidiaSettings(), ct),
            _ => await _openAiGenerator.GenerateFreeformAsync(prompt, settings.OpenAI ?? new OpenAISettings(), ct)
        };

    private static string? GetString(JsonElement root, string propertyName)
        => root.TryGetProperty(propertyName, out var value) && value.ValueKind == JsonValueKind.String
            ? value.GetString()?.Trim()
            : null;

    private static int GetInt(JsonElement root, string propertyName)
        => root.TryGetProperty(propertyName, out var value) && value.TryGetInt32(out var parsed)
            ? Math.Clamp(parsed, 0, 100)
            : 0;
}

public sealed record WhatsAppNicheAiDecision(
    string? ProductName,
    string? Slug,
    int Confidence,
    string Reason,
    bool RequiresReview,
    string Provider);
