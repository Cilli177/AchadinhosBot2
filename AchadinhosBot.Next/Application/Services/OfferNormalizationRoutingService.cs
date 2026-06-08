using System.Globalization;
using System.Text.RegularExpressions;
using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Domain.Instagram;
using AchadinhosBot.Next.Domain.Models;
using AchadinhosBot.Next.Domain.Offers;

namespace AchadinhosBot.Next.Application.Services;

public sealed class OfferNormalizationRoutingService
{
    private readonly IInstagramPublishStore _publishStore;
    private readonly ICatalogOfferStore _catalogOfferStore;
    private readonly IOfferAutomationIntentStore _automationIntentStore;

    public OfferNormalizationRoutingService(
        IInstagramPublishStore publishStore,
        ICatalogOfferStore catalogOfferStore,
        IOfferAutomationIntentStore automationIntentStore)
    {
        _publishStore = publishStore;
        _catalogOfferStore = catalogOfferStore;
        _automationIntentStore = automationIntentStore;
    }

    public async Task<OfferNormalizationRun> MaterializeAsync(
        OfferNormalizationRun run,
        string actor,
        CancellationToken cancellationToken)
    {
        return run.SelectedTarget switch
        {
            OfferNormalizationTargets.Catalog => await MaterializeCatalogAsync(run, actor, cancellationToken),
            OfferNormalizationTargets.Queue => await MaterializeQueueAsync(run, actor, cancellationToken),
            _ => MaterializeReview(run)
        };
    }

    private async Task<OfferNormalizationRun> MaterializeCatalogAsync(
        OfferNormalizationRun run,
        string actor,
        CancellationToken cancellationToken)
    {
        var drafts = new List<InstagramPublishDraft>();
        for (var index = 0; index < run.NormalizedOffers.Count; index++)
        {
            var draft = BuildCatalogDraft(run, run.NormalizedOffers[index], index);
            var existing = await _publishStore.GetAsync(draft.Id, cancellationToken);
            if (existing is null)
            {
                await _publishStore.SaveAsync(draft, cancellationToken);
            }
            else
            {
                draft.CreatedAt = existing.CreatedAt;
                await _publishStore.UpdateAsync(draft, cancellationToken);
            }

            drafts.Add(draft);
        }

        var syncResult = await _catalogOfferStore.SyncExplicitDraftsAsync(drafts, cancellationToken);
        run.AssistedDelivery = new OfferNormalizationDeliveryReference
        {
            Kind = OfferNormalizationTargets.Catalog,
            Status = OfferNormalizationStatuses.SentToCatalog,
            TargetScope = CatalogTargets.Dev,
            UpdatedAtUtc = DateTimeOffset.UtcNow,
            ReferenceIds = drafts.Select(x => x.Id).ToList(),
            Summary = $"{drafts.Count} draft(s) assistidos sincronizados no catálogo dev. Criados: {syncResult.Created}. Atualizados: {syncResult.Updated}."
        };
        run.NextStepHint = "Itens enviados ao catálogo assistido em dev. Revise no catálogo e promova manualmente apenas o que estiver pronto.";
        run.Summary = $"{run.Summary} {run.AssistedDelivery.Summary}".Trim();
        run.Operator = actor;
        return run;
    }

    private async Task<OfferNormalizationRun> MaterializeQueueAsync(
        OfferNormalizationRun run,
        string actor,
        CancellationToken cancellationToken)
    {
        var existing = await _automationIntentStore.GetByNormalizationRunIdAsync(run.Id, cancellationToken);
        var intent = existing ?? new OfferAutomationIntent
        {
            NormalizationRunId = run.Id,
            CreatedAtUtc = DateTimeOffset.UtcNow
        };

        intent.Operator = actor;
        intent.OfferCount = run.NormalizedOffers.Count;
        intent.Notes = string.IsNullOrWhiteSpace(run.Notes) ? null : run.Notes;
        intent.Status = "prepared";
        intent.Summary = $"{run.NormalizedOffers.Count} oferta(s) preparadas para automação posterior.";

        var savedIntent = await _automationIntentStore.SaveAsync(intent, cancellationToken);
        run.AssistedDelivery = new OfferNormalizationDeliveryReference
        {
            Kind = OfferNormalizationTargets.Queue,
            Status = OfferNormalizationStatuses.QueuedForAutomation,
            TargetScope = "audit",
            UpdatedAtUtc = savedIntent.UpdatedAtUtc,
            ReferenceIds = [savedIntent.Id],
            Summary = $"Intento auditável registrado para automação posterior. Referência: {savedIntent.Id[..8]}."
        };
        run.NextStepHint = "Execução registrada na fila auditável. Use esta referência para acoplar uma automação posterior sem perder a trilha operacional.";
        run.Summary = $"{run.Summary} {run.AssistedDelivery.Summary}".Trim();
        run.Operator = actor;
        return run;
    }

    private static OfferNormalizationRun MaterializeReview(OfferNormalizationRun run)
    {
        var previousReferences = run.AssistedDelivery?.ReferenceIds?.ToList() ?? [];
        run.AssistedDelivery = new OfferNormalizationDeliveryReference
        {
            Kind = OfferNormalizationTargets.Review,
            Status = OfferNormalizationStatuses.ReviewRequired,
            UpdatedAtUtc = DateTimeOffset.UtcNow,
            TargetScope = run.AssistedDelivery?.TargetScope,
            ReferenceIds = previousReferences,
            Summary = previousReferences.Count > 0
                ? "Execução mantida em revisão. Encaminhamentos anteriores permanecem auditáveis no histórico."
                : "Execução mantida em revisão aguardando curadoria humana."
        };
        run.NextStepHint = "Revise gaps, confirme links e só depois encaminhe para catálogo assistido ou fila auditável.";
        return run;
    }

    private static InstagramPublishDraft BuildCatalogDraft(OfferNormalizationRun run, CanonicalOfferRecord offer, int index)
    {
        var imageUrls = ResolveImageUrls(offer);
        var caption = BuildCaption(offer);
        var offerUrl = offer.ProductUrl?.Trim() ?? string.Empty;

        return new InstagramPublishDraft
        {
            Id = BuildDraftId(run.Id, index),
            CreatedAt = run.CreatedAtUtc,
            ProductName = string.IsNullOrWhiteSpace(offer.ProductName) ? $"Oferta {index + 1}" : offer.ProductName.Trim(),
            Caption = caption,
            CaptionOptions = string.IsNullOrWhiteSpace(caption) ? [] : [caption],
            SelectedCaptionIndex = 1,
            OfferUrl = offerUrl,
            AutoReplyEnabled = !string.IsNullOrWhiteSpace(offerUrl),
            AutoReplyLink = string.IsNullOrWhiteSpace(offerUrl) ? null : offerUrl,
            Store = NormalizeNullable(offer.StoreName),
            CurrentPrice = FormatMoney(offer.PromoPrice),
            PreviousPrice = FormatMoney(offer.OriginalPrice),
            DiscountPercent = offer.DiscountPercent.HasValue ? (int)Math.Round(offer.DiscountPercent.Value) : null,
            SourceDataOrigin = $"offer-normalization:{run.Id}",
            ImageUrls = imageUrls,
            SelectedImageIndexes = imageUrls.Count == 0 ? [] : Enumerable.Range(1, imageUrls.Count).ToList(),
            Ctas = string.IsNullOrWhiteSpace(offerUrl)
                ? []
                : [new InstagramCtaOption
                {
                    Keyword = BuildKeyword(offer, index),
                    Link = offerUrl,
                    Label = "Comprar"
                }],
            SendToCatalog = true,
            CatalogTarget = CatalogTargets.Dev,
            CatalogIntentLocked = true,
            Status = "draft"
        };
    }

    private static string BuildDraftId(string runId, int index)
        => $"offernorm-{runId}-{index + 1:D2}";

    private static string BuildKeyword(CanonicalOfferRecord offer, int index)
    {
        var source = $"{offer.ProductName} {offer.StoreName}".Trim();
        var normalized = Regex.Replace(source.ToLowerInvariant(), "[^a-z0-9]+", string.Empty);
        if (string.IsNullOrWhiteSpace(normalized))
        {
            return $"oferta{index + 1:D2}";
        }

        return normalized.Length <= 18 ? normalized : normalized[..18];
    }

    private static string BuildCaption(CanonicalOfferRecord offer)
    {
        var lines = new List<string>();
        if (!string.IsNullOrWhiteSpace(offer.ProductName))
        {
            lines.Add(offer.ProductName.Trim());
        }

        var priceLine = BuildPriceLine(offer);
        if (!string.IsNullOrWhiteSpace(priceLine))
        {
            lines.Add(priceLine);
        }

        if (!string.IsNullOrWhiteSpace(offer.StoreName))
        {
            lines.Add($"Loja: {offer.StoreName.Trim()}");
        }

        if (!string.IsNullOrWhiteSpace(offer.Category))
        {
            lines.Add($"Categoria: {offer.Category.Trim()}");
        }

        if (!string.IsNullOrWhiteSpace(offer.ProductUrl))
        {
            lines.Add(offer.ProductUrl.Trim());
        }

        return string.Join(Environment.NewLine, lines.Where(x => !string.IsNullOrWhiteSpace(x)));
    }

    private static string BuildPriceLine(CanonicalOfferRecord offer)
    {
        var parts = new List<string>();
        var promo = FormatMoney(offer.PromoPrice);
        var original = FormatMoney(offer.OriginalPrice);
        if (!string.IsNullOrWhiteSpace(promo))
        {
            parts.Add($"Oferta: {promo}");
        }

        if (!string.IsNullOrWhiteSpace(original) && !string.Equals(original, promo, StringComparison.OrdinalIgnoreCase))
        {
            parts.Add($"De: {original}");
        }

        if (offer.DiscountPercent.HasValue)
        {
            parts.Add($"Desconto: {offer.DiscountPercent.Value.ToString("0.#", CultureInfo.InvariantCulture)}%");
        }

        return string.Join(" | ", parts);
    }

    private static string? FormatMoney(decimal? value)
    {
        if (!value.HasValue)
        {
            return null;
        }

        return value.Value.ToString("'R$' #,##0.00", CultureInfo.GetCultureInfo("pt-BR"));
    }

    private static string? NormalizeNullable(string? value)
        => string.IsNullOrWhiteSpace(value) ? null : value.Trim();

    private static List<string> ResolveImageUrls(CanonicalOfferRecord offer)
    {
        var results = new List<string>();
        foreach (var key in new[] { "imageurl", "image_url", "image", "img", "photo", "thumbnail", "imageurl1" })
        {
            if (offer.ExtraFields.TryGetValue(key, out var value) && Uri.TryCreate(value, UriKind.Absolute, out _))
            {
                results.Add(value!);
            }
        }

        return results.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
    }
}
