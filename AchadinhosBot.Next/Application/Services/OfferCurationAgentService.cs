using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Domain.Agents;
using AchadinhosBot.Next.Domain.Instagram;
using AchadinhosBot.Next.Domain.Models;

namespace AchadinhosBot.Next.Application.Services;

public sealed class OfferCurationAgentService : IOfferCurationAgentService
{
    private readonly IInstagramPublishStore _publishStore;
    private readonly ICatalogOfferStore _catalogOfferStore;
    private readonly IClickLogStore _clickLogStore;

    public OfferCurationAgentService(
        IInstagramPublishStore publishStore,
        ICatalogOfferStore catalogOfferStore,
        IClickLogStore clickLogStore)
    {
        _publishStore = publishStore;
        _catalogOfferStore = catalogOfferStore;
        _clickLogStore = clickLogStore;
    }

    public async Task<OfferCurationResult> CurateAsync(OfferCurationRequest request, CancellationToken cancellationToken)
    {
        var hoursWindow = Math.Clamp(request.HoursWindow, 1, 24 * 30);
        var maxItems = Math.Clamp(request.MaxItems, 1, 50);
        var start = DateTimeOffset.UtcNow.AddHours(-hoursWindow);

        var drafts = await _publishStore.ListAsync(cancellationToken);
        var clickLogs = await _clickLogStore.QueryAsync(null, null, 5000, cancellationToken);
        var catalogDev = await _catalogOfferStore.GetByDraftIdAsync(cancellationToken, CatalogTargets.Dev);
        var catalogProd = await _catalogOfferStore.GetByDraftIdAsync(cancellationToken, CatalogTargets.Prod);

        var scopedDrafts = drafts
            .Where(d => request.DraftIds.Count == 0 || request.DraftIds.Contains(d.Id, StringComparer.OrdinalIgnoreCase))
            .Where(d => d.CreatedAt >= start || (d.ScheduledFor.HasValue && d.ScheduledFor.Value >= start))
            .Where(d => ShouldInclude(d, request))
            .OrderByDescending(d => d.CreatedAt)
            .Take(200)
            .ToList();

        var suggestions = scopedDrafts
            .Select(d => BuildSuggestion(d, clickLogs, catalogDev, catalogProd))
            .Where(s => !string.Equals(s.RecommendedAction, OfferCurationActions.NoAction, StringComparison.OrdinalIgnoreCase))
            .OrderByDescending(s => s.Score)
            .ThenByDescending(s => s.RecentClicks)
            .Take(maxItems)
            .ToList();

        var usedFallbackWindow = false;
        if (suggestions.Count == 0 && request.DraftIds.Count == 0)
        {
            usedFallbackWindow = true;
            scopedDrafts = drafts
                .Where(d => d.CreatedAt >= DateTimeOffset.UtcNow.AddDays(-30) || (d.ScheduledFor.HasValue && d.ScheduledFor.Value >= DateTimeOffset.UtcNow.AddDays(-30)))
                .Where(d => ShouldInclude(d, request))
                .OrderByDescending(d => d.CreatedAt)
                .Take(200)
                .ToList();

            suggestions = scopedDrafts
                .Select(d => BuildSuggestion(d, clickLogs, catalogDev, catalogProd))
                .Where(s => !string.Equals(s.RecommendedAction, OfferCurationActions.NoAction, StringComparison.OrdinalIgnoreCase))
                .OrderByDescending(s => s.Score)
                .ThenByDescending(s => s.RecentClicks)
                .Take(maxItems)
                .ToList();
        }

        return new OfferCurationResult
        {
            EvaluatedDrafts = scopedDrafts.Count,
            SuggestedActions = suggestions.Count,
            Suggestions = suggestions,
            Summary = BuildSummary(hoursWindow, scopedDrafts.Count, suggestions, usedFallbackWindow)
        };
    }

    private static bool ShouldInclude(InstagramPublishDraft draft, OfferCurationRequest request)
    {
        return draft.Status.ToLowerInvariant() switch
        {
            "published" => request.IncludePublished,
            "scheduled" => request.IncludeScheduled,
            "approved" => request.IncludeDrafts,
            "draft" => request.IncludeDrafts,
            _ => request.IncludeDrafts
        };
    }

    private static OfferCurationSuggestion BuildSuggestion(
        InstagramPublishDraft draft,
        IReadOnlyList<Domain.Logs.ClickLogEntry> clickLogs,
        IReadOnlyDictionary<string, CatalogOfferItem> catalogDev,
        IReadOnlyDictionary<string, CatalogOfferItem> catalogProd)
    {
        var inCatalogDev = catalogDev.ContainsKey(draft.Id);
        var inCatalogProd = catalogProd.ContainsKey(draft.Id);
        var recentClicks = CountClicks(clickLogs, draft);
        var resolvedOfferUrl = ResolveEffectiveOfferUrl(draft);
        var hasOfferUrl = !string.IsNullOrWhiteSpace(resolvedOfferUrl);
        var hasMedia = HasMedia(draft);
        var isPublished = string.Equals(draft.Status, "published", StringComparison.OrdinalIgnoreCase);
        var isScheduled = string.Equals(draft.Status, "scheduled", StringComparison.OrdinalIgnoreCase);
        var isDraft = string.Equals(draft.Status, "draft", StringComparison.OrdinalIgnoreCase);
        var isApproved = string.Equals(draft.Status, "approved", StringComparison.OrdinalIgnoreCase);
        var isHighlightedOnBio = draft.IsBioHighlighted;

        var reasons = new List<string>();
        var risks = new List<string>();
        var score = 0;
        var action = OfferCurationActions.NoAction;
        var suggestedTarget = CatalogTargets.None;

        if (isPublished)
        {
            score += 35;
            reasons.Add("Ja foi publicado e pode gerar reaproveitamento de catalogo e bio.");
        }

        if (recentClicks > 0)
        {
            score += Math.Min(recentClicks * 4, 24);
            reasons.Add($"Recebeu {recentClicks} clique(s) recentes e merece prioridade operacional.");
        }

        if (!inCatalogDev && !inCatalogProd && isPublished)
        {
            score += 20;
            reasons.Add("Ainda nao entrou no catalogo e pode virar trafego recorrente.");
            action = OfferCurationActions.AddToCatalog;
            suggestedTarget = CatalogTargets.Prod;
        }

        if (inCatalogDev || inCatalogProd)
        {
            score += 10;
            reasons.Add("Ja existe no catalogo, podendo entrar em destaque ou refresh.");
        }

        if (isHighlightedOnBio)
        {
            score += 8;
            reasons.Add("Ja esta sinalizado como destaque na bio.");
        }

        if (recentClicks >= 3 && isPublished && !isHighlightedOnBio)
        {
            score += 15;
            reasons.Add("Tem sinais de tracao para destaque na bio.");
            action = OfferCurationActions.HighlightOnBio;
        }

        if ((isDraft || isApproved) && hasOfferUrl && !string.IsNullOrWhiteSpace(draft.Caption))
        {
            score += isApproved ? 24 : 14;
            reasons.Add(isApproved
                ? "Rascunho ja aprovado e pronto para conferencia final."
                : "Rascunho com link e legenda prontos para revisao operacional.");

            if (hasMedia)
            {
                score += 12;
                reasons.Add("Midia associada ao rascunho, o que facilita publicacao.");
                action = OfferCurationActions.ReviewAndPublish;
            }
            else
            {
                action = OfferCurationActions.Review;
            }
        }

        if (isScheduled)
        {
            score += 8;
            reasons.Add("Existe agendamento pendente que merece monitoramento.");
            if (action == OfferCurationActions.NoAction)
            {
                action = OfferCurationActions.Review;
            }
        }

        if (!hasOfferUrl)
        {
            risks.Add("Sem link de oferta valido.");
            score -= 20;
        }

        if (!hasMedia)
        {
            risks.Add("Sem midia associada.");
            score -= 10;
        }

        if (string.IsNullOrWhiteSpace(draft.Caption))
        {
            risks.Add("Sem legenda final.");
            score -= 8;
        }

        if (draft.Error is { Length: > 0 })
        {
            risks.Add($"Ultimo erro conhecido: {draft.Error}");
            score -= 12;
        }

        if (action == OfferCurationActions.NoAction &&
            score > 0 &&
            (hasOfferUrl || hasMedia || isApproved || isPublished || isScheduled))
        {
            reasons.Add("Vale revisao manual mesmo sem automacao imediata.");
            action = OfferCurationActions.Review;
        }

        return new OfferCurationSuggestion
        {
            DraftId = draft.Id,
            ProductName = draft.ProductName,
            Status = draft.Status,
            PostType = draft.PostType,
            RecommendedAction = action,
            Score = Math.Max(score, 0),
            RecentClicks = recentClicks,
            InCatalogDev = inCatalogDev,
            InCatalogProd = inCatalogProd,
            SuggestedCatalogTarget = suggestedTarget,
            HasOfferUrl = hasOfferUrl,
            HasMedia = hasMedia,
            IsHighlightedOnBio = isHighlightedOnBio,
            BioHighlightedAt = draft.BioHighlightedAt,
            CreatedAt = draft.CreatedAt,
            ScheduledFor = draft.ScheduledFor,
            Reasons = reasons,
            Risks = risks
        };
    }

    private static int CountClicks(IReadOnlyList<Domain.Logs.ClickLogEntry> clickLogs, InstagramPublishDraft draft)
    {
        var resolvedOfferUrl = ResolveEffectiveOfferUrl(draft);
        return clickLogs.Count(log =>
            (!string.IsNullOrWhiteSpace(log.DraftId) && string.Equals(log.DraftId, draft.Id, StringComparison.OrdinalIgnoreCase)) ||
            (!string.IsNullOrWhiteSpace(resolvedOfferUrl) && string.Equals(log.TargetUrl, resolvedOfferUrl, StringComparison.OrdinalIgnoreCase)) ||
            (!string.IsNullOrWhiteSpace(draft.MediaId) && string.Equals(log.MediaId, draft.MediaId, StringComparison.OrdinalIgnoreCase)));
    }

    private static bool HasMedia(InstagramPublishDraft draft)
        => !string.IsNullOrWhiteSpace(draft.VideoUrl) || (draft.ImageUrls?.Count ?? 0) > 0;

    private static string? ResolveEffectiveOfferUrl(InstagramPublishDraft draft)
    {
        if (!string.IsNullOrWhiteSpace(draft.OfferUrl))
        {
            return draft.OfferUrl;
        }

        var ctaLink = draft.Ctas?
            .Select(x => x.Link)
            .FirstOrDefault(x => !string.IsNullOrWhiteSpace(x));
        if (!string.IsNullOrWhiteSpace(ctaLink))
        {
            return ctaLink;
        }

        if (!string.IsNullOrWhiteSpace(draft.AutoReplyLink))
        {
            return draft.AutoReplyLink;
        }

        return null;
    }

    private static string BuildSummary(int hoursWindow, int evaluatedDrafts, IReadOnlyList<OfferCurationSuggestion> suggestions, bool usedFallbackWindow)
    {
        if (suggestions.Count == 0)
        {
            return $"Nenhuma recomendacao relevante encontrada na janela de {hoursWindow}h.";
        }

        var addToCatalog = suggestions.Count(x => string.Equals(x.RecommendedAction, OfferCurationActions.AddToCatalog, StringComparison.OrdinalIgnoreCase));
        var highlight = suggestions.Count(x => string.Equals(x.RecommendedAction, OfferCurationActions.HighlightOnBio, StringComparison.OrdinalIgnoreCase));
        var review = suggestions.Count(x => string.Equals(x.RecommendedAction, OfferCurationActions.ReviewAndPublish, StringComparison.OrdinalIgnoreCase) ||
                                            string.Equals(x.RecommendedAction, OfferCurationActions.Review, StringComparison.OrdinalIgnoreCase));

        var windowLabel = usedFallbackWindow
            ? $"{hoursWindow}h (expandido automaticamente para 30 dias por falta de sinais recentes)"
            : $"{hoursWindow}h";

        return $"Agente avaliou {evaluatedDrafts} draft(s) em {windowLabel} e encontrou {suggestions.Count} recomendacao(oes): {addToCatalog} para catalogo, {highlight} para destaque e {review} para revisao operacional.";
    }
}
