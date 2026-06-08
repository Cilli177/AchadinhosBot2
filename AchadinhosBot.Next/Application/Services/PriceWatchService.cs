using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;
using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Configuration;
using AchadinhosBot.Next.Domain.Logs;
using AchadinhosBot.Next.Domain.Models;
using AchadinhosBot.Next.Domain.PriceWatch;
using AchadinhosBot.Next.Infrastructure.ProductData;
using Microsoft.Extensions.Options;

namespace AchadinhosBot.Next.Application.Services;

public sealed partial class PriceWatchService
{
    private readonly IPriceWatchStore _store;
    private readonly ICatalogOfferStore _catalogStore;
    private readonly OfficialProductDataService _productDataService;
    private readonly IAffiliateLinkService _affiliateLinkService;
    private readonly ILinkTrackingStore _linkTrackingStore;
    private readonly IWhatsAppGateway _whatsAppGateway;
    private readonly IOptions<WebhookOptions> _webhookOptions;
    private readonly ILogger<PriceWatchService> _logger;

    public PriceWatchService(
        IPriceWatchStore store,
        ICatalogOfferStore catalogStore,
        OfficialProductDataService productDataService,
        IAffiliateLinkService affiliateLinkService,
        ILinkTrackingStore linkTrackingStore,
        IWhatsAppGateway whatsAppGateway,
        IOptions<WebhookOptions> webhookOptions,
        ILogger<PriceWatchService> logger)
    {
        _store = store;
        _catalogStore = catalogStore;
        _productDataService = productDataService;
        _affiliateLinkService = affiliateLinkService;
        _linkTrackingStore = linkTrackingStore;
        _whatsAppGateway = whatsAppGateway;
        _webhookOptions = webhookOptions;
        _logger = logger;
    }

    public async Task<PriceWatchItem> CreateAsync(PriceWatchCreateRequest request, string optInSource, CancellationToken ct)
    {
        var contactJid = NormalizeContactJid(request.ContactJid);
        if (string.IsNullOrWhiteSpace(contactJid))
        {
            throw new ArgumentException("Contato WhatsApp obrigatorio.", nameof(request));
        }

        var item = new PriceWatchItem
        {
            ContactJid = contactJid,
            ContactName = request.ContactName?.Trim(),
            InstanceName = string.IsNullOrWhiteSpace(request.InstanceName) ? null : request.InstanceName.Trim(),
            ProductUrl = NormalizeUrl(request.ProductUrl),
            CatalogQuery = request.CatalogQuery?.Trim(),
            SearchTerm = request.SearchTerm?.Trim(),
            DesiredPrice = request.DesiredPrice,
            AcceptSimilarProducts = request.AcceptSimilarProducts,
            IntervalHours = Math.Clamp(request.IntervalHours ?? 12, 1, 168),
            NearTargetPercent = request.NearTargetPercent is > 0 ? Math.Clamp(request.NearTargetPercent.Value, 1m, 25m) : 5m,
            OptInSource = string.IsNullOrWhiteSpace(optInSource) ? "admin" : optInSource.Trim(),
            Status = PriceWatchStatuses.Active,
            NextCheckAt = DateTimeOffset.UtcNow
        };

        if (!string.IsNullOrWhiteSpace(item.ProductUrl))
        {
            item.SourceType = PriceWatchSourceTypes.Link;
        }
        else if (!string.IsNullOrWhiteSpace(item.CatalogQuery))
        {
            item.SourceType = PriceWatchSourceTypes.Catalog;
        }
        else if (!string.IsNullOrWhiteSpace(item.SearchTerm))
        {
            item.SourceType = PriceWatchSourceTypes.Search;
            item.Status = PriceWatchStatuses.PendingReview;
            item.LastError = "Busca textual exige revisao antes de envio automatico.";
        }
        else
        {
            throw new ArgumentException("Informe link do produto, item do catalogo ou termo de busca.", nameof(request));
        }

        var candidate = await ResolveCandidateAsync(item, ct);
        if (candidate is not null)
        {
            item.ProductName = candidate.ProductName;
            item.Store = candidate.Store;
            item.LastFoundPrice = candidate.Price;
            item.LastFoundPriceText = candidate.PriceText;
            item.LastFoundAt = DateTimeOffset.UtcNow;
            item.LastOfferUrl = candidate.OfferUrl;
        }

        await _store.SaveAsync(item, ct);
        return item;
    }

    public Task<IReadOnlyList<PriceWatchItem>> ListAsync(CancellationToken ct, string? status = null, string? contactJid = null)
        => _store.ListAsync(ct, status, string.IsNullOrWhiteSpace(contactJid) ? null : NormalizeContactJid(contactJid));

    public Task<IReadOnlyList<PriceWatchReviewItem>> ListReviewsAsync(CancellationToken ct, string? status = "pending")
        => _store.ListReviewsAsync(ct, status);

    public async Task<IReadOnlyList<PriceWatchRunResult>> RunDueAsync(int limit, CancellationToken ct)
    {
        var due = await _store.ListDueAsync(DateTimeOffset.UtcNow, limit, ct);
        var results = new List<PriceWatchRunResult>();
        foreach (var item in due)
        {
            results.Add(await RunAsync(item, forceSend: false, ct));
        }

        return results;
    }

    public async Task<PriceWatchRunResult> RunNowAsync(string id, CancellationToken ct)
    {
        var item = await _store.GetAsync(id, ct);
        if (item is null)
        {
            return new(false, id, false, false, "Radar nao encontrado.", Error: "not_found");
        }

        return await RunAsync(item, forceSend: false, ct);
    }

    public async Task<bool> PauseAsync(string id, CancellationToken ct)
    {
        var item = await _store.GetAsync(id, ct);
        if (item is null) return false;
        item.Status = PriceWatchStatuses.Paused;
        item.UpdatedAt = DateTimeOffset.UtcNow;
        await _store.UpdateAsync(item, ct);
        return true;
    }

    public async Task<bool> ResumeAsync(string id, CancellationToken ct)
    {
        var item = await _store.GetAsync(id, ct);
        if (item is null) return false;
        item.Status = PriceWatchStatuses.Active;
        item.NextCheckAt = DateTimeOffset.UtcNow;
        item.UpdatedAt = DateTimeOffset.UtcNow;
        await _store.UpdateAsync(item, ct);
        return true;
    }

    public Task<int> PauseByContactAsync(string contactJid, CancellationToken ct)
        => _store.PauseByContactAsync(NormalizeContactJid(contactJid), ct);

    public async Task<PriceWatchItem?> SetAcceptSimilarByContactAsync(string contactJid, bool acceptSimilar, CancellationToken ct)
    {
        var items = await _store.ListAsync(ct, contactJid: NormalizeContactJid(contactJid));
        var item = items.FirstOrDefault(x => string.Equals(x.Status, PriceWatchStatuses.Active, StringComparison.OrdinalIgnoreCase));
        if (item is null)
        {
            return null;
        }

        item.AcceptSimilarProducts = acceptSimilar;
        item.UpdatedAt = DateTimeOffset.UtcNow;
        await _store.UpdateAsync(item, ct);
        return item;
    }

    public async Task<PriceWatchRunResult> ApproveReviewAsync(string reviewId, CancellationToken ct)
    {
        var review = await _store.GetReviewAsync(reviewId, ct);
        if (review is null)
        {
            return new(false, reviewId, false, false, "Revisao nao encontrada.", Error: "not_found");
        }

        var item = await _store.GetAsync(review.WatchId, ct);
        if (item is null)
        {
            return new(false, review.WatchId, false, false, "Radar da revisao nao encontrado.", Error: "watch_not_found");
        }

        review.Status = "approved";
        review.DecidedAt = DateTimeOffset.UtcNow;
        await _store.UpdateReviewAsync(review, ct);

        item.Status = PriceWatchStatuses.Active;
        item.ProductUrl = review.CandidateUrl;
        item.ProductName = review.CandidateProductName;
        item.Store = review.CandidateStore;
        item.LastFoundPrice = review.CandidatePrice;
        item.LastFoundPriceText = review.CandidatePriceText;
        item.LastFoundAt = DateTimeOffset.UtcNow;
        item.NextCheckAt = DateTimeOffset.UtcNow;
        await _store.UpdateAsync(item, ct);
        return await RunAsync(item, forceSend: true, ct);
    }

    private async Task<PriceWatchRunResult> RunAsync(PriceWatchItem item, bool forceSend, CancellationToken ct)
    {
        if (!string.Equals(item.Status, PriceWatchStatuses.Active, StringComparison.OrdinalIgnoreCase))
        {
            return new(true, item.Id, false, false, $"Radar em status {item.Status}.");
        }

        var now = DateTimeOffset.UtcNow;
        try
        {
            var candidate = await ResolveCandidateAsync(item, ct);
            if (candidate is null || candidate.Price is null)
            {
                await MarkFailureAsync(item, "Preco confiavel nao encontrado.", ct);
                return new(false, item.Id, false, false, "Preco confiavel nao encontrado.", Error: "price_not_found");
            }

            item.ProductName = FirstNonEmpty(candidate.ProductName, item.ProductName);
            item.Store = FirstNonEmpty(candidate.Store, item.Store);
            item.LastFoundPrice = candidate.Price;
            item.LastFoundPriceText = candidate.PriceText;
            item.LastFoundAt = now;
            item.LastOfferUrl = candidate.OfferUrl;

            if (candidate.Confidence < 0.9)
            {
                var review = new PriceWatchReviewItem
                {
                    WatchId = item.Id,
                    Reason = candidate.MatchReason,
                    CandidateProductName = candidate.ProductName,
                    CandidateUrl = candidate.OfferUrl,
                    CandidateStore = candidate.Store,
                    CandidatePrice = candidate.Price,
                    CandidatePriceText = candidate.PriceText
                };
                item.Status = PriceWatchStatuses.PendingReview;
                item.LastError = "Match duvidoso enviado para revisao.";
                item.UpdatedAt = now;
                await _store.UpdateAsync(item, ct);
                await _store.SaveReviewAsync(review, ct);
                return new(true, item.Id, false, true, "Match duvidoso enviado para revisao.", CurrentPrice: candidate.Price);
            }

            var decision = forceSend
                ? new PriceWatchDecisionResult(true, "aprovado_admin")
                : PriceWatchDecision.Decide(candidate.Price, item.LastSentPrice, item.DesiredPrice, item.NearTargetPercent, item.LastSentAt, now);

            if (!decision.ShouldSend)
            {
                item.ConsecutiveFailures = 0;
                item.LastError = null;
                item.NextCheckAt = now.AddHours(item.IntervalHours);
                item.UpdatedAt = now;
                await _store.UpdateAsync(item, ct);
                return new(true, item.Id, false, false, decision.Reason, CurrentPrice: candidate.Price, PreviousSentPrice: item.LastSentPrice);
            }

            var conversion = await _affiliateLinkService.ConvertAsync(candidate.OfferUrl, ct, "price_watch", forceResolution: true);
            if (!conversion.Success || !conversion.IsAffiliated || string.IsNullOrWhiteSpace(conversion.ConvertedUrl))
            {
                var error = FirstNonEmpty(conversion.ValidationError, conversion.Error, "Falha ao validar afiliado.");
                await MarkFailureAsync(item, error, ct);
                return new(false, item.Id, false, false, "Conversao afiliada invalida.", CurrentPrice: candidate.Price, Error: error);
            }

            var tracking = await CreateTrackingAsync(item, candidate, conversion, ct);
            var text = BuildMessage(item, candidate, tracking.TrackingUrl, decision.Reason);
            var send = await _whatsAppGateway.SendTextAsync(item.InstanceName, item.ContactJid, text, ct);
            if (!send.Success)
            {
                await MarkFailureAsync(item, send.Message ?? "Falha ao enfileirar WhatsApp.", ct);
                return new(false, item.Id, false, false, "Falha ao enviar WhatsApp.", CurrentPrice: candidate.Price, Error: send.Message);
            }

            item.LastSentPrice = candidate.Price;
            item.LastSentPriceText = candidate.PriceText;
            item.LastSentAt = now;
            item.LastAffiliateUrl = conversion.ConvertedUrl;
            item.LastTrackingUrl = tracking.TrackingUrl;
            item.LastTrackingId = tracking.TrackingId;
            item.ConsecutiveFailures = 0;
            item.LastError = null;
            item.NextCheckAt = now.AddHours(item.IntervalHours);
            item.UpdatedAt = now;
            await _store.UpdateAsync(item, ct);
            return new(true, item.Id, true, false, decision.Reason, candidate.Price, item.LastSentPrice, tracking.TrackingUrl);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Falha ao executar PriceWatch {WatchId}.", item.Id);
            await MarkFailureAsync(item, ex.Message, ct);
            return new(false, item.Id, false, false, "Erro no Radar de Preco.", Error: ex.Message);
        }
    }

    private async Task<PriceWatchCandidate?> ResolveCandidateAsync(PriceWatchItem item, CancellationToken ct)
    {
        if (string.Equals(item.SourceType, PriceWatchSourceTypes.Catalog, StringComparison.OrdinalIgnoreCase))
        {
            var catalog = await _catalogStore.FindByCodeAsync(item.CatalogQuery ?? string.Empty, ct);
            if (catalog is null || !catalog.Active)
            {
                return null;
            }

            var catalogOfferUrl = FirstNonEmpty(catalog.AffiliateTargetUrl, catalog.OfferUrl, catalog.OriginalProductUrl);
            var price = TryParsePrice(catalog.PriceText);
            return string.IsNullOrWhiteSpace(catalogOfferUrl)
                ? null
                : new PriceWatchCandidate(catalog.ProductName, catalog.Store, catalogOfferUrl!, price, catalog.PriceText, 1.0, "catalogo_validado");
        }

        if (string.Equals(item.SourceType, PriceWatchSourceTypes.Search, StringComparison.OrdinalIgnoreCase))
        {
            if (string.IsNullOrWhiteSpace(item.ProductUrl))
            {
                return new PriceWatchCandidate(item.SearchTerm, null, string.Empty, null, null, 0.1, "busca_textual_requer_revisao");
            }
        }

        var url = FirstNonEmpty(item.ProductUrl, item.LastOfferUrl);
        if (string.IsNullOrWhiteSpace(url))
        {
            return null;
        }

        var data = await _productDataService.TryGetBestAsync(url!, null, ct);
        if (data is null)
        {
            return null;
        }

        var offerUrl = FirstNonEmpty(data.SourceUrl, url);
        return new PriceWatchCandidate(
            data.Title,
            data.Store,
            offerUrl!,
            TryParsePrice(data.CurrentPrice),
            data.CurrentPrice,
            0.98,
            "link_direto");
    }

    private async Task<(string TrackingId, string TrackingUrl)> CreateTrackingAsync(
        PriceWatchItem item,
        PriceWatchCandidate candidate,
        AffiliateLinkResult conversion,
        CancellationToken ct)
    {
        var tracking = await _linkTrackingStore.CreateAsync(new LinkTrackingCreateRequest
        {
            TargetUrl = conversion.ConvertedUrl!,
            Store = conversion.Store,
            OriginChannel = "whatsapp",
            OriginSurface = "price_watch",
            Campaign = "price_watch_direct",
            OfferId = item.Id
        }, ct);

        var trackingId = string.IsNullOrWhiteSpace(tracking.Slug) ? tracking.Id : tracking.Slug;
        return (trackingId, $"{NormalizePublicBaseUrl(_webhookOptions.Value.PublicBaseUrl)}/r/{Uri.EscapeDataString(trackingId)}?src=pw&camp=price_watch_direct");
    }

    private async Task MarkFailureAsync(PriceWatchItem item, string error, CancellationToken ct)
    {
        item.ConsecutiveFailures++;
        item.LastError = error;
        item.NextCheckAt = DateTimeOffset.UtcNow.AddHours(Math.Min(item.IntervalHours, Math.Max(1, item.ConsecutiveFailures)));
        item.UpdatedAt = DateTimeOffset.UtcNow;
        await _store.UpdateAsync(item, ct);
    }

    private static string BuildMessage(PriceWatchItem item, PriceWatchCandidate candidate, string trackingUrl, string reason)
    {
        var sb = new StringBuilder();
        var intro = reason switch
        {
            "preco_alvo" => "Boa, chegou no valor que voce pediu.",
            "perto_do_alvo" => "Achei um preco bem perto do que voce queria.",
            "queda_real" => "O produto que voce esta monitorando baixou.",
            _ => "Radar de Preco encontrou uma oportunidade."
        };

        sb.AppendLine(intro);
        sb.AppendLine();
        sb.AppendLine(candidate.ProductName ?? item.ProductName ?? "Produto monitorado");
        if (!string.IsNullOrWhiteSpace(item.LastSentPriceText))
        {
            sb.AppendLine($"Antes enviado: {item.LastSentPriceText}");
        }
        else if (item.LastFoundPrice is not null)
        {
            sb.AppendLine($"Preco monitorado: {FormatPrice(item.LastFoundPrice.Value)}");
        }

        sb.AppendLine($"Agora: {candidate.PriceText ?? FormatPrice(candidate.Price ?? 0)}");
        if (!string.IsNullOrWhiteSpace(candidate.Store))
        {
            sb.AppendLine($"Loja: {candidate.Store}");
        }

        sb.AppendLine();
        sb.AppendLine(trackingUrl);
        sb.AppendLine();
        sb.Append("Para cancelar esse tipo de alerta, responda PARAR.");
        return sb.ToString();
    }

    public static string NormalizeContactJid(string? value)
    {
        var jid = (value ?? string.Empty).Trim();
        if (string.IsNullOrWhiteSpace(jid))
        {
            return string.Empty;
        }

        if (jid.Contains('@'))
        {
            return jid;
        }

        var digits = DigitsOnlyRegex().Replace(jid, string.Empty);
        return string.IsNullOrWhiteSpace(digits) ? jid : $"{digits}@s.whatsapp.net";
    }

    public static decimal? TryParsePrice(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        var match = PriceRegex().Match(value);
        if (!match.Success)
        {
            return null;
        }

        var normalized = match.Value.Replace("R$", "", StringComparison.OrdinalIgnoreCase).Trim();
        normalized = normalized.Replace(".", "", StringComparison.Ordinal).Replace(",", ".", StringComparison.Ordinal);
        return decimal.TryParse(normalized, NumberStyles.Number, CultureInfo.InvariantCulture, out var parsed)
            ? parsed
            : null;
    }

    private static string FormatPrice(decimal value)
        => value.ToString("C", CultureInfo.GetCultureInfo("pt-BR"));

    private static string? NormalizeUrl(string? value)
    {
        var url = value?.Trim();
        return Uri.TryCreate(url, UriKind.Absolute, out _) ? url : null;
    }

    private static string? FirstNonEmpty(params string?[] values)
        => values.FirstOrDefault(x => !string.IsNullOrWhiteSpace(x))?.Trim();

    private static string NormalizePublicBaseUrl(string? publicBaseUrl)
    {
        var candidate = string.IsNullOrWhiteSpace(publicBaseUrl) ? "https://reidasofertas.ia.br" : publicBaseUrl.Trim().TrimEnd('/');
        if (!Uri.TryCreate(candidate, UriKind.Absolute, out var uri))
        {
            return "https://reidasofertas.ia.br";
        }

        if (uri.Host.Equals("reidasofertas.ia.br", StringComparison.OrdinalIgnoreCase) ||
            uri.Host.EndsWith(".reidasofertas.ia.br", StringComparison.OrdinalIgnoreCase))
        {
            return $"{uri.Scheme}://reidasofertas.ia.br";
        }

        return uri.GetLeftPart(UriPartial.Authority).TrimEnd('/');
    }

    [GeneratedRegex(@"R?\$?\s*(?:\d{1,3}(?:\.\d{3})+|\d+)(?:,\d{2})?|\d+(?:[,.]\d{2})?", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex PriceRegex();

    [GeneratedRegex(@"\D+", RegexOptions.CultureInvariant)]
    private static partial Regex DigitsOnlyRegex();
}
