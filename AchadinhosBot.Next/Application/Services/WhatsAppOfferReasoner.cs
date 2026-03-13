using System.Text.Json;
using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Domain.Agents;
using AchadinhosBot.Next.Domain.Logs;
using AchadinhosBot.Next.Domain.Settings;
using AchadinhosBot.Next.Infrastructure.Instagram;

namespace AchadinhosBot.Next.Application.Services;

public sealed class WhatsAppOfferReasoner : IWhatsAppOfferReasoner
{
    private readonly OpenAiInstagramPostGenerator _openAiGenerator;
    private readonly GeminiInstagramPostGenerator _geminiGenerator;
    private readonly DeepSeekInstagramPostGenerator _deepSeekGenerator;
    private readonly NemotronInstagramPostGenerator _nemotronGenerator;
    private readonly QwenInstagramPostGenerator _qwenGenerator;
    private readonly VilaNvidiaGenerator _vilaGenerator;

    public WhatsAppOfferReasoner(
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

    public async Task<WhatsAppOfferAiDecision?> ReasonAsync(
        WhatsAppOutboundLogEntry message,
        WhatsAppOfferSuggestion heuristicSuggestion,
        AutomationSettings settings,
        CancellationToken cancellationToken)
    {
        var instagramSettings = settings.InstagramPosts ?? new InstagramPostSettings();
        if (!instagramSettings.UseAi)
        {
            return null;
        }

        var provider = string.IsNullOrWhiteSpace(instagramSettings.AiProvider)
            ? "openai"
            : instagramSettings.AiProvider.Trim().ToLowerInvariant();

        var prompt = $$"""
        Voce e um agente operacional de afiliados.
        Sua tarefa e decidir a melhor proxima acao para uma oferta publicada no WhatsApp.
        Responda APENAS em JSON valido, sem markdown e sem texto extra.

        Schema esperado:
        {
          "recommendedAction": "create_instagram_draft|add_to_catalog|review_and_publish|review|no_action",
          "instagramScore": 0-100,
          "catalogScore": 0-100,
          "suggestedKeyword": "texto_curto",
          "reasoning": "explicacao curta em portugues",
          "risks": ["risco 1", "risco 2"]
        }

        Contexto da oferta:
        - produto: {{heuristicSuggestion.ProductName}}
        - texto whatsapp: {{message.Text}}
        - link: {{heuristicSuggestion.OfferUrl}}
        - imagem: {{heuristicSuggestion.HasImage}}
        - tipo de midia: {{heuristicSuggestion.MediaKind}}
        - formato sugerido: {{heuristicSuggestion.SuggestedPostType}}
        - cliques recentes: {{heuristicSuggestion.RecentClicks}}
        - existe draft: {{heuristicSuggestion.HasExistingDraft}}
        - draft status: {{heuristicSuggestion.ExistingDraftStatus}}
        - em catalogo dev: {{heuristicSuggestion.InCatalogDev}}
        - em catalogo prod: {{heuristicSuggestion.InCatalogProd}}

        Heuristica atual:
        - recommendedAction: {{heuristicSuggestion.RecommendedAction}}
        - instagramScore: {{heuristicSuggestion.InstagramScore}}
        - catalogScore: {{heuristicSuggestion.CatalogScore}}
        - suggestedKeyword: {{heuristicSuggestion.SuggestedKeyword}}
        - reasons: {{string.Join(" | ", heuristicSuggestion.Reasons)}}
        - risks: {{string.Join(" | ", heuristicSuggestion.Risks)}}
        - memoria operacional: {{BuildMemoryDirective(heuristicSuggestion)}}

        Regras:
        - nao sugerir add_to_catalog se nao houver draft publicado.
        - nao sugerir create_instagram_draft se ja existir draft correspondente.
        - se houver feedback rejected recente para esta oferta, evite repetir a mesma acao sem novo sinal forte.
        - se houver feedback edited recente, prefira review em vez de acao agressiva.
        - use o formato sugerido como sinal operacional: video tende a reel, texto puro tende a catalogo ou review.
        - seja conservador.
        - prefira manter a heuristica se o contexto estiver incompleto.
        """;

        var raw = await GenerateAsync(prompt, provider, settings, cancellationToken);
        if (string.IsNullOrWhiteSpace(raw))
        {
            return null;
        }

        try
        {
            using var doc = JsonDocument.Parse(raw);
            var root = doc.RootElement;
            return new WhatsAppOfferAiDecision
            {
                RecommendedAction = GetString(root, "recommendedAction") ?? WhatsAppOfferScoutActions.Review,
                InstagramScore = ClampScore(GetInt(root, "instagramScore")),
                CatalogScore = ClampScore(GetInt(root, "catalogScore")),
                SuggestedKeyword = GetString(root, "suggestedKeyword") ?? heuristicSuggestion.SuggestedKeyword,
                Reasoning = GetString(root, "reasoning") ?? string.Empty,
                Risks = GetStringArray(root, "risks"),
                Provider = provider
            };
        }
        catch
        {
            return null;
        }
    }

    private async Task<string?> GenerateAsync(string prompt, string provider, AutomationSettings settings, CancellationToken cancellationToken)
    {
        return provider switch
        {
            "gemini" => await _geminiGenerator.GenerateFreeformAsync(prompt, settings.Gemini ?? new GeminiSettings(), cancellationToken),
            "deepseek" => await _deepSeekGenerator.GenerateFreeformAsync(prompt, settings.DeepSeek ?? new DeepSeekSettings(), cancellationToken),
            "nemotron" => await _nemotronGenerator.GenerateFreeformAsync(prompt, settings.Nemotron ?? new NemotronSettings(), cancellationToken),
            "qwen" => await _qwenGenerator.GenerateFreeformAsync(prompt, settings.Qwen ?? new QwenSettings(), cancellationToken),
            "vila" => await _vilaGenerator.GenerateFreeformAsync(prompt, settings.VilaNvidia ?? new VilaNvidiaSettings(), cancellationToken),
            _ => await _openAiGenerator.GenerateFreeformAsync(prompt, settings.OpenAI ?? new OpenAISettings(), cancellationToken)
        };
    }

    private static string? GetString(JsonElement root, string propertyName)
        => root.TryGetProperty(propertyName, out var value) && value.ValueKind == JsonValueKind.String
            ? value.GetString()?.Trim()
            : null;

    private static int GetInt(JsonElement root, string propertyName)
        => root.TryGetProperty(propertyName, out var value) && value.TryGetInt32(out var parsed)
            ? parsed
            : 0;

    private static List<string> GetStringArray(JsonElement root, string propertyName)
    {
        if (!root.TryGetProperty(propertyName, out var value) || value.ValueKind != JsonValueKind.Array)
        {
            return new List<string>();
        }

        return value.EnumerateArray()
            .Where(x => x.ValueKind == JsonValueKind.String)
            .Select(x => x.GetString()?.Trim() ?? string.Empty)
            .Where(x => !string.IsNullOrWhiteSpace(x))
            .ToList();
    }

    private static string BuildMemoryDirective(WhatsAppOfferSuggestion suggestion)
    {
        if (string.IsNullOrWhiteSpace(suggestion.LastOperatorFeedback) &&
            string.IsNullOrWhiteSpace(suggestion.LastAppliedAction) &&
            !suggestion.LastDecisionAt.HasValue)
        {
            return "sem memoria relevante";
        }

        return string.Join(" | ", new[]
        {
            !string.IsNullOrWhiteSpace(suggestion.LastOperatorFeedback) ? $"ultimo_feedback={suggestion.LastOperatorFeedback}" : null,
            !string.IsNullOrWhiteSpace(suggestion.LastAppliedAction) ? $"ultima_acao={suggestion.LastAppliedAction}" : null,
            !string.IsNullOrWhiteSpace(suggestion.LastOperatorNote) ? $"nota={suggestion.LastOperatorNote}" : null,
            suggestion.LastDecisionAt.HasValue ? $"ultima_decisao_utc={suggestion.LastDecisionAt.Value:O}" : null
        }.Where(x => !string.IsNullOrWhiteSpace(x)));
    }

    private static int ClampScore(int value) => Math.Clamp(value, 0, 100);
}
