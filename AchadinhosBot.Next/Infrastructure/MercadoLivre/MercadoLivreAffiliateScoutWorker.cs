using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Application.Services;
using AchadinhosBot.Next.Domain.Settings;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace AchadinhosBot.Next.Infrastructure.MercadoLivre;

public sealed class MercadoLivreAffiliateScoutWorker : BackgroundService
{
    private const string MercadoLivreScoutGroupId = "120363409272515351@g.us";
    private const string OfficialOffersGroupId = "120363405661434395@g.us";

    private readonly MercadoLivreAffiliateScoutClient _scoutClient;
    private readonly ISettingsStore _settingsStore;
    private readonly WhatsAppPublishContentService _publishService;
    private readonly WhatsAppAutomationQueueService _queueService;
    private readonly IWhatsAppGateway _whatsappGateway;
    private readonly MercadoLivreStoryDraftService _storyDraftService;
    private readonly ILogger<MercadoLivreAffiliateScoutWorker> _logger;

    private static readonly TimeSpan RefreshRetryAfter = TimeSpan.FromMinutes(5);
    private readonly Dictionary<string, DateTimeOffset> _sentProductKeys = new(StringComparer.OrdinalIgnoreCase);
    private bool _sentProductKeysLoaded;

    public MercadoLivreAffiliateScoutWorker(
        MercadoLivreAffiliateScoutClient scoutClient,
        ISettingsStore settingsStore,
        WhatsAppPublishContentService publishService,
        WhatsAppAutomationQueueService queueService,
        IWhatsAppGateway whatsappGateway,
        MercadoLivreStoryDraftService storyDraftService,
        ILogger<MercadoLivreAffiliateScoutWorker> logger)
    {
        _scoutClient = scoutClient;
        _settingsStore = settingsStore;
        _publishService = publishService;
        _queueService = queueService;
        _whatsappGateway = whatsappGateway;
        _storyDraftService = storyDraftService;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("MercadoLivreAffiliateScoutWorker iniciado.");

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                var settings = await _settingsStore.GetAsync(stoppingToken);
                var scout = settings.MercadoLivreAffiliateScout ?? new MercadoLivreAffiliateScoutSettings();

                if (scout.Enabled)
                {
                    await RunScoutAsync(scout, stoppingToken);
                }
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Erro no loop do MercadoLivreAffiliateScoutWorker");
            }

            // Get interval from settings, default to 5 minutes min
            var interval = await GetNextIntervalAsync(stoppingToken);
            await Task.Delay(interval, stoppingToken);
        }
    }

    private async Task RunScoutAsync(MercadoLivreAffiliateScoutSettings scout, CancellationToken ct)
    {
        _logger.LogInformation("MercadoLivreAffiliateScoutWorker: Iniciando busca de ofertas...");

        var cycleStartedAt = DateTimeOffset.UtcNow;
        var scoutGroupId = ResolveScoutGroupId(scout);
        var officialGroupId = ResolveOfficialGroupId(scout);
        var instanceName = scout.WhatsAppInstanceName ?? "ZapOfertas";
        if (string.IsNullOrWhiteSpace(scoutGroupId))
        {
            _logger.LogWarning("MercadoLivreAffiliateScoutWorker: grupo operacional nao configurado.");
            return;
        }

        await EnqueueTextMessageAsync(
            "mercadolivre_scout_start",
            "Scout ML iniciado",
            BuildScoutStartMessage(scout, DateTimeOffset.Now),
            instanceName,
            scoutGroupId,
            ct);

        var stats = new MercadoLivreScoutCycleStats();
        var result = await _scoutClient.TestAsync(ct, forceRefreshBeforeScan: true);
        await ProcessScoutResultAsync(result, stats, scout, scoutGroupId, officialGroupId, instanceName, cycleStartedAt, ct);

        if (ShouldRunRefreshRetry(cycleStartedAt, stats.SentOfferCount))
        {
            stats.RefreshRetryUsed = true;
            _logger.LogInformation(
                "MercadoLivreAffiliateScoutWorker: ciclo sem envios apos {Elapsed}. Executando refresh extra.",
                DateTimeOffset.UtcNow - cycleStartedAt);

            var retryResult = await _scoutClient.TestAsync(ct, forceRefreshBeforeScan: true);
            await ProcessScoutResultAsync(retryResult, stats, scout, scoutGroupId, officialGroupId, instanceName, cycleStartedAt, ct);
            result = retryResult;
        }

        DateTimeOffset? summaryScheduledForUtc = stats.LastOfficialScheduledForUtc.HasValue
            ? stats.LastOfficialScheduledForUtc.Value.AddSeconds(15)
            : null;

        await EnqueueTextMessageAsync(
            "mercadolivre_scout_summary",
            "Resumo scout ML",
            BuildScoutSummaryMessage(stats, result.Message),
            instanceName,
            scoutGroupId,
            ct,
            summaryScheduledForUtc);

        _logger.LogInformation("MercadoLivreAffiliateScoutWorker: Ciclo finalizado. {Sent} ofertas enviadas para fila.", stats.SentOfferCount);
    }

    private async Task ProcessScoutResultAsync(
        MercadoLivreAffiliateScoutResult result,
        MercadoLivreScoutCycleStats stats,
        MercadoLivreAffiliateScoutSettings scout,
        string scoutGroupId,
        string? officialGroupId,
        string instanceName,
        DateTimeOffset cycleStartedAt,
        CancellationToken ct)
    {
        stats.FoundCount += result.Offers.Count;

        if (!result.Success)
        {
            _logger.LogInformation("MercadoLivreAffiliateScoutWorker: Falha no scraper. Msg: {Msg}", result.Message);
            return;
        }

        _logger.LogInformation("MercadoLivreAffiliateScoutWorker: Encontradas {Count} ofertas. Filtrando...", result.Offers.Count);

        await LoadSentProductKeysAsync(scout, cycleStartedAt, ct);

        var acceptedOffers = new List<MercadoLivreAffiliateScoutOffer>();
        var acceptedKeysThisResult = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var offer in result.Offers)
        {
            var dedupeKey = BuildDedupeKey(offer);
            var status = GetOfferStatus(offer, scout, cycleStartedAt);
            if (status == MercadoLivreScoutOfferStatus.Accepted)
            {
                if (string.IsNullOrWhiteSpace(dedupeKey) || !acceptedKeysThisResult.Add(dedupeKey))
                {
                    stats.DuplicateCount++;
                    continue;
                }

                stats.AcceptedCount++;
                acceptedOffers.Add(offer);
            }
            else if (status == MercadoLivreScoutOfferStatus.Duplicate)
            {
                stats.DuplicateCount++;
            }
            else
            {
                stats.FilteredCount++;
            }
        }

        var rankedOffers = RankOffersByCommission(acceptedOffers, scout);

        var maxOffersThisRun = ResolveMaxOffersPerRun(scout);
        var offersToSend = rankedOffers
            .Take(Math.Max(0, maxOffersThisRun - stats.SentOfferCount))
            .ToList();
        var throttleOfficialOffers = !string.IsNullOrWhiteSpace(officialGroupId) &&
                                     offersToSend.Count + stats.SentOfficialOfferCount > 3;

        foreach (var offer in offersToSend)
        {
            try
            {
                var offerEnqueued = await ProcessAndSendOfferAsync(
                    offer,
                    scout,
                    scoutGroupId,
                    instanceName,
                    "mercadolivre_scout",
                    $"Oferta ML: {offer.Title}",
                    ct,
                    includeCommission: true);
                if (!offerEnqueued)
                {
                    stats.FailedCount++;
                    continue;
                }

                stats.SentOfferCount++;
                _sentProductKeys[BuildDedupeKey(offer)!] = cycleStartedAt;
                await SaveSentProductKeysAsync(scout, cycleStartedAt, ct);

                if (await ProcessAndSendCommissionAsync(offer, scoutGroupId, instanceName, ct))
                {
                    stats.SentCommissionCount++;
                }
                else
                {
                    stats.FailedCount++;
                }

                if (!string.IsNullOrWhiteSpace(officialGroupId))
                {
                    var officialScheduledForUtc = ResolveOfficialScheduledForUtc(stats.SentOfficialOfferCount, throttleOfficialOffers);
                    if (await ProcessAndSendOfferAsync(
                        offer,
                        scout,
                        officialGroupId,
                        instanceName,
                        "mercadolivre_scout_official",
                        $"Oferta ML oficial: {offer.Title}",
                        ct,
                        officialScheduledForUtc,
                        includeCommission: false))
                    {
                        stats.SentOfficialOfferCount++;
                        if (officialScheduledForUtc.HasValue)
                        {
                            stats.LastOfficialScheduledForUtc = officialScheduledForUtc;
                        }
                    }
                    else
                    {
                        stats.FailedCount++;
                    }
                }
            }
            catch (Exception ex)
            {
                stats.FailedCount++;
                _logger.LogWarning(ex, "Erro ao processar oferta ML: {Title}", offer.Title);
            }
        }

        var storyResult = await _storyDraftService.CreateDraftsAsync(offersToSend, scout, ct);
        stats.StoryDraftCount += storyResult.CreatedCount;
        stats.StoryApprovalSentCount += storyResult.ApprovalSentCount;
        stats.StoryFailedCount += storyResult.FailedCount + storyResult.ApprovalFailedCount;
    }

    internal static DateTimeOffset? ResolveOfficialScheduledForUtc(int officialIndex, bool throttleOfficialOffers)
        => throttleOfficialOffers && officialIndex > 0
            ? DateTimeOffset.UtcNow.AddMinutes(officialIndex * 2)
            : null;

    private static bool ShouldRunRefreshRetry(DateTimeOffset cycleStartedAt, int sentOfferCount)
        => sentOfferCount == 0 && DateTimeOffset.UtcNow - cycleStartedAt >= RefreshRetryAfter;

    private bool IsInvalidOrDuplicate(MercadoLivreAffiliateScoutOffer offer, MercadoLivreAffiliateScoutSettings scout)
        => GetOfferStatus(offer, scout, DateTimeOffset.UtcNow) != MercadoLivreScoutOfferStatus.Accepted;

    private MercadoLivreScoutOfferStatus GetOfferStatus(MercadoLivreAffiliateScoutOffer offer, MercadoLivreAffiliateScoutSettings scout, DateTimeOffset nowUtc)
    {
        var dedupeKey = BuildDedupeKey(offer);
        if (string.IsNullOrWhiteSpace(dedupeKey)) return MercadoLivreScoutOfferStatus.Invalid;
        
        if (_sentProductKeys.TryGetValue(dedupeKey, out var lastSentAtUtc) &&
            IsWithinRepeatWindow(lastSentAtUtc, nowUtc, scout))
        {
            _logger.LogDebug("Oferta ML ja enviada anteriormente: {Key}", dedupeKey);
            return MercadoLivreScoutOfferStatus.Duplicate;
        }

        // 2. Parse price and commission for tiered filtering
        decimal price = TryParsePrice(offer.PriceText);
        decimal comm = TryParseCommission(offer.CommissionText);

        // Tiered filter logic comes from settings so we can tune high-commission rules without redeploying.
        
        var isAccepted = IsAcceptedByCommissionTiers(price, comm, scout);

        if (!isAccepted)
        {
            _logger.LogInformation("Oferta ML ignorada (Filtro Tiered): {Title} | Preco: {Price} | Comm: {Comm}%", offer.Title, price, comm);
            return MercadoLivreScoutOfferStatus.Filtered;
        }

        _logger.LogInformation("Oferta ML ACEITA: {Title} | Preco: {Price} | Comm: {Comm}%", offer.Title, price, comm);
        return MercadoLivreScoutOfferStatus.Accepted;
    }

    internal static bool IsAcceptedByCommissionTiers(decimal price, decimal commissionPercent, MercadoLivreAffiliateScoutSettings scout)
    {
        if (commissionPercent >= scout.MinCommissionPercent)
        {
            return true;
        }

        if (scout.Tier1MinPrice > 0 &&
            price >= scout.Tier1MinPrice &&
            commissionPercent >= scout.Tier1MinCommissionPercent)
        {
            return true;
        }

        if (scout.Tier2MinPrice > 0 &&
            price >= scout.Tier2MinPrice &&
            commissionPercent >= scout.Tier2MinCommissionPercent)
        {
            return true;
        }

        if (scout.Tier3MinPrice > 0 &&
            price >= scout.Tier3MinPrice &&
            commissionPercent >= scout.Tier3MinCommissionPercent)
        {
            return true;
        }

        return false;
    }

    internal static decimal GetEffectiveMinimumCommissionPercent(MercadoLivreAffiliateScoutSettings scout)
    {
        var minimum = scout.MinCommissionPercent;
        if (scout.Tier1MinPrice > 0) minimum = Math.Min(minimum, scout.Tier1MinCommissionPercent);
        if (scout.Tier2MinPrice > 0) minimum = Math.Min(minimum, scout.Tier2MinCommissionPercent);
        if (scout.Tier3MinPrice > 0) minimum = Math.Min(minimum, scout.Tier3MinCommissionPercent);
        return Math.Clamp(minimum, 0m, 100m);
    }

    internal static bool IsWithinRepeatWindow(DateTimeOffset lastSentAtUtc, DateTimeOffset nowUtc, MercadoLivreAffiliateScoutSettings scout)
        => nowUtc - lastSentAtUtc < GetRepeatWindow(scout);

    private static TimeSpan GetRepeatWindow(MercadoLivreAffiliateScoutSettings scout)
        => TimeSpan.FromHours(Math.Clamp(scout.RepeatWindowHours, 1, 168));

    internal static IReadOnlyList<MercadoLivreAffiliateScoutOffer> RankOffersByCommission(
        IEnumerable<MercadoLivreAffiliateScoutOffer> offers,
        MercadoLivreAffiliateScoutSettings scout)
    {
        return offers
            .Select(offer => new
            {
                Offer = offer,
                Price = TryParsePrice(offer.PriceText),
                Commission = TryParseCommission(offer.CommissionText)
            })
            .Where(item => IsAcceptedByCommissionTiers(item.Price, item.Commission, scout))
            .OrderByDescending(item => item.Commission)
            .ThenByDescending(item => item.Price)
            .Select(item => item.Offer)
            .ToList();
    }

    internal static string? BuildDedupeKey(MercadoLivreAffiliateScoutOffer offer)
    {
        var url = FirstNonEmpty(offer.ProductUrl, offer.SharedUrl);
        var productId = ExtractMercadoLivreProductKey(url);
        if (!string.IsNullOrWhiteSpace(productId))
        {
            return productId;
        }

        var title = Regex.Replace(offer.Title ?? string.Empty, @"\s+", " ").Trim().ToLowerInvariant();
        return string.IsNullOrWhiteSpace(title) ? url : $"title:{title}";
    }

    private static string? FirstNonEmpty(params string?[] values)
        => values.FirstOrDefault(value => !string.IsNullOrWhiteSpace(value))?.Trim();

    private static string? ExtractMercadoLivreProductKey(string? url)
    {
        if (string.IsNullOrWhiteSpace(url)) return null;

        var decoded = Uri.UnescapeDataString(url);
        var itemMatch = Regex.Match(decoded, @"(?:item_id[:=]|[/_-])(MLB\d{5,})", RegexOptions.IgnoreCase);
        if (itemMatch.Success) return itemMatch.Groups[1].Value.ToUpperInvariant();

        var productMatch = Regex.Match(decoded, @"/p/(MLB\d{5,})", RegexOptions.IgnoreCase);
        if (productMatch.Success) return productMatch.Groups[1].Value.ToUpperInvariant();

        return null;
    }

    internal static decimal TryParsePrice(string? text)
    {
        if (string.IsNullOrWhiteSpace(text)) return 0;
        try
        {
            // Clean R$, dots as thousand separators and comma as decimal
            // Example: "R$ 1.299,90" -> "1299.90"
            string cleaned = System.Text.RegularExpressions.Regex.Replace(text, @"[^\d,]", "");
            if (decimal.TryParse(cleaned, System.Globalization.CultureInfo.GetCultureInfo("pt-BR"), out var result))
            {
                return result;
            }
        }
        catch { }
        return 0;
    }

    internal static decimal TryParseCommission(string? text)
    {
        if (string.IsNullOrWhiteSpace(text)) return 0;
        try
        {
            // Simple extraction: e.g. "Ganhe 25.5%"
            var match = System.Text.RegularExpressions.Regex.Match(text, @"(\d+[\.,]?\d*)\s*%");
            if (match.Success && decimal.TryParse(match.Groups[1].Value.Replace(",", "."), System.Globalization.CultureInfo.InvariantCulture, out var result))
            {
                return result;
            }
        }
        catch { }
        return 0;
    }

    internal static string BuildScoutMessage(MercadoLivreAffiliateScoutOffer offer, bool includeCommission = true)
    {
        var priceText = string.IsNullOrWhiteSpace(offer.PriceText) ? "confira no link" : offer.PriceText.Trim();
        var commissionText = string.IsNullOrWhiteSpace(offer.CommissionText)
            ? "n\u00e3o informada pelo Mercado Livre"
            : offer.CommissionText.Trim();
        var commissionLine = includeCommission
            ? $"\U0001F4CA Comiss\u00e3o da oferta: *{commissionText}*\n\n"
            : string.Empty;
        var offerUrl = offer.SharedUrl ?? offer.ProductUrl;
        return
            $"\U0001F525 *Achadinho Mercado Livre selecionado!*\n\n" +
            $"*{offer.Title}*\n\n" +
            $"\U0001F4B0 Pre\u00e7o: *{priceText}*" +
            $"\n\n\U0001F6D2 Pegar oferta: {offerUrl}\n\n" +
            commissionLine +
            $"\u26A1 Selecionado automaticamente pelo scout do Rei das Ofertas.";
    }

    internal static string BuildScoutStartMessage(MercadoLivreAffiliateScoutSettings scout, DateTimeOffset startedAt)
    {
        var startedAtBr = ConvertToBrazilTime(startedAt);
        var limit = scout.MaxOffersPerRun <= 0 ? "ilimitado por ciclo" : $"{scout.MaxOffersPerRun} por ciclo";
        return
            $"\U0001F50E *Scout Mercado Livre iniciado*\n\n" +
            $"Hor\u00e1rio BR: *{startedAtBr:dd/MM/yyyy HH:mm} BRT*.\n\n" +
            $"*Filtros ativos:*\n" +
            $"- Comiss\u00e3o geral: *{scout.MinCommissionPercent:0.##}%+*\n" +
            $"- Tier 1: pre\u00e7o *R$ {scout.Tier1MinPrice:0.##}+* e comiss\u00e3o *{scout.Tier1MinCommissionPercent:0.##}%+*\n" +
            $"- Tier 2: pre\u00e7o *R$ {scout.Tier2MinPrice:0.##}+* e comiss\u00e3o *{scout.Tier2MinCommissionPercent:0.##}%+*\n" +
            $"- Tier 3: pre\u00e7o *R$ {scout.Tier3MinPrice:0.##}+* e comiss\u00e3o *{scout.Tier3MinCommissionPercent:0.##}%+*\n" +
            $"- Dedupe: repetir produto s\u00f3 ap\u00f3s *{Math.Clamp(scout.RepeatWindowHours, 1, 168)}h*\n" +
            $"- Limite: *{limit}*\n" +
            $"- Destino: *{ResolveDestinationLabel(scout)}*\n\n" +
            $"Vou enviar as ofertas aprovadas aqui com a comiss\u00e3o logo abaixo de cada oferta.";
    }

    internal static string BuildCommissionNoteMessage(MercadoLivreAffiliateScoutOffer offer)
    {
        var commissionText = string.IsNullOrWhiteSpace(offer.CommissionText)
            ? "n\u00e3o informada pelo Mercado Livre"
            : offer.CommissionText.Trim();

        return $"\U0001F4CA Comiss\u00e3o da oferta acima: *{commissionText}*";
    }

    internal static string BuildScoutSummaryMessage(
        MercadoLivreScoutCycleStats stats,
        string? sourceMessage = null)
    {
        var statusLine = stats.FailedCount > 0
            ? $"\u26A0\uFE0F Finalizei com *{stats.FailedCount}* falha(s) para revisar."
            : "\u2705 Ciclo finalizado com sucesso.";

        var detail = string.IsNullOrWhiteSpace(sourceMessage)
            ? string.Empty
            : $"\n\nDetalhe do scraper: {sourceMessage.Trim()}";

        var refreshLine = stats.RefreshRetryUsed
            ? "\n\U0001F504 Refresh extra: *sim* (segunda tentativa por ciclo longo sem envios)"
            : "\n\U0001F504 Refresh extra: *n\u00e3o*";

        return
            $"{statusLine}\n\n" +
            $"\U0001F4E6 Ofertas buscadas: *{stats.FoundCount}*\n" +
            $"\U0001F3AF Aprovadas pelos filtros: *{stats.AcceptedCount}*\n" +
            $"\U0001F501 Repetidas ignoradas: *{stats.DuplicateCount}*\n" +
            $"\U0001F6AB Fora do filtro: *{stats.FilteredCount}*\n" +
            $"\U0001F4E4 Ofertas enviadas: *{stats.SentOfferCount}*\n" +
            $"\U0001F451 Ofertas enviadas ao Rei das Ofertas: *{stats.SentOfficialOfferCount}*\n" +
            $"\U0001F4CA Comiss\u00f5es anexadas \u00e0s ofertas: *{stats.SentCommissionCount}*\n" +
            $"\U0001F4F2 Stories ML criados: *{stats.StoryDraftCount}*\n" +
            $"\u2705 Aprova\u00e7\u00f5es de story enviadas: *{stats.StoryApprovalSentCount}*" +
            refreshLine +
            detail;
    }

    private async Task<bool> ProcessAndSendOfferAsync(
        MercadoLivreAffiliateScoutOffer offer,
        MercadoLivreAffiliateScoutSettings scout,
        string targetGroupId,
        string instanceName,
        string queueKind,
        string queueLabel,
        CancellationToken ct,
        DateTimeOffset? scheduledForUtc = null,
        bool includeCommission = true)
    {

        _logger.LogInformation("MercadoLivreAffiliateScoutWorker: Roteando oferta para {Group}. AutoPublish={Auto}", 
            targetGroupId == "120363405661434395@g.us" ? "OFICIAL" : "TESTE", 
            scout.AutoPublishToOfficialGroup);
        
        // Prepare content (Link shortening, formatting, image resolving)
        var prepared = await _publishService.PrepareForSendAsync(BuildScoutMessage(offer, includeCommission), offer.ImageUrl, targetGroupId, ct);

        // Enqueue for delivery
        await _queueService.EnqueueAsync(
            queueKind,
            queueLabel,
            async (token) => 
            {
                WhatsAppSendResult sendResult;
                if (prepared.HasImageCandidate && prepared.ResolvedImageBytes != null)
                {
                    sendResult = await _whatsappGateway.SendImageAsync(
                        instanceName, 
                        targetGroupId, 
                        prepared.ResolvedImageBytes, 
                        prepared.Content, 
                        prepared.ResolvedMimeType, 
                        token);
                }
                else if (prepared.HasImageCandidate && !string.IsNullOrWhiteSpace(prepared.ResolvedImageUrl))
                {
                    sendResult = await _whatsappGateway.SendImageUrlAsync(
                        instanceName, 
                        targetGroupId, 
                        prepared.ResolvedImageUrl, 
                        prepared.Content, 
                        prepared.ResolvedMimeType, 
                        "oferta.jpg", 
                        token);
                }
                else
                {
                    sendResult = await _whatsappGateway.SendTextAsync(instanceName, targetGroupId, prepared.Content, token);
                }

                return (sendResult.Success, sendResult.Message ?? (sendResult.Success ? "Enviado com sucesso" : "Falha no envio"));
            }, 
            ct,
            scheduledForUtc);
        
        _logger.LogInformation("Oferta ML enfileirada para {Target}: {Title}", targetGroupId, offer.Title);
        return true;
    }

    private Task<bool> ProcessAndSendCommissionAsync(
        MercadoLivreAffiliateScoutOffer offer,
        string targetGroupId,
        string instanceName,
        CancellationToken ct)
        => Task.FromResult(true);

    private async Task EnqueueTextMessageAsync(
        string kind,
        string label,
        string text,
        string instanceName,
        string targetGroupId,
        CancellationToken ct,
        DateTimeOffset? scheduledForUtc = null)
    {
        await _queueService.EnqueueAsync(
            kind,
            label,
            async token =>
            {
                var sendResult = await _whatsappGateway.SendTextAsync(instanceName, targetGroupId, text, token);
                return (sendResult.Success, sendResult.Message ?? (sendResult.Success ? "Enviado com sucesso" : "Falha no envio"));
            },
            ct,
            scheduledForUtc);
    }

    private static int ResolveMaxOffersPerRun(MercadoLivreAffiliateScoutSettings scout)
    {
        return scout.MaxOffersPerRun <= 0 ? int.MaxValue : scout.MaxOffersPerRun;
    }

    private static string ResolveScoutGroupId(MercadoLivreAffiliateScoutSettings scout)
        => string.IsNullOrWhiteSpace(scout.DestinationGroupId)
            ? MercadoLivreScoutGroupId
            : scout.DestinationGroupId.Trim();

    private static string? ResolveOfficialGroupId(MercadoLivreAffiliateScoutSettings scout)
        => scout.AutoPublishToOfficialGroup ? OfficialOffersGroupId : null;

    private async Task LoadSentProductKeysAsync(MercadoLivreAffiliateScoutSettings scout, DateTimeOffset nowUtc, CancellationToken ct)
    {
        if (_sentProductKeysLoaded)
        {
            PurgeExpiredSentProductKeys(scout, nowUtc);
            return;
        }

        var path = ResolveSeenProductsPath(scout);
        try
        {
            if (File.Exists(path))
            {
                var json = await File.ReadAllTextAsync(path, ct);
                foreach (var entry in ParseSentProductKeysFromJson(json, nowUtc))
                {
                    _sentProductKeys[entry.Key] = entry.Value;
                }
                PurgeExpiredSentProductKeys(scout, nowUtc);
            }

            _logger.LogInformation("MercadoLivreAffiliateScoutWorker: {Count} produtos ja enviados carregados.", _sentProductKeys.Count);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Falha ao carregar dedupe persistente do Mercado Livre: {Path}", path);
        }
        finally
        {
            _sentProductKeysLoaded = true;
        }
    }

    private async Task SaveSentProductKeysAsync(MercadoLivreAffiliateScoutSettings scout, DateTimeOffset nowUtc, CancellationToken ct)
    {
        var path = ResolveSeenProductsPath(scout);
        try
        {
            PurgeExpiredSentProductKeys(scout, nowUtc);
            Directory.CreateDirectory(Path.GetDirectoryName(path) ?? ".");
            var records = _sentProductKeys
                .OrderBy(x => x.Key, StringComparer.OrdinalIgnoreCase)
                .Select(x => new MercadoLivreSentProductRecord(x.Key, x.Value))
                .ToArray();
            var json = JsonSerializer.Serialize(records);
            await File.WriteAllTextAsync(path, json, ct);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Falha ao salvar dedupe persistente do Mercado Livre: {Path}", path);
        }
    }

    internal static Dictionary<string, DateTimeOffset> ParseSentProductKeysFromJson(string json, DateTimeOffset nowUtc)
    {
        var result = new Dictionary<string, DateTimeOffset>(StringComparer.OrdinalIgnoreCase);
        if (string.IsNullOrWhiteSpace(json)) return result;

        using var document = JsonDocument.Parse(json);
        if (document.RootElement.ValueKind != JsonValueKind.Array) return result;

        foreach (var item in document.RootElement.EnumerateArray())
        {
            if (item.ValueKind == JsonValueKind.String)
            {
                var key = item.GetString();
                if (!string.IsNullOrWhiteSpace(key))
                {
                    result[key.Trim()] = nowUtc;
                }
                continue;
            }

            if (item.ValueKind != JsonValueKind.Object) continue;

            var keyValue = item.TryGetProperty("key", out var keyProperty)
                ? keyProperty.GetString()
                : null;
            if (string.IsNullOrWhiteSpace(keyValue)) continue;

            var sentAt = nowUtc;
            if (item.TryGetProperty("lastSentAtUtc", out var sentAtProperty) &&
                sentAtProperty.ValueKind == JsonValueKind.String &&
                DateTimeOffset.TryParse(sentAtProperty.GetString(), out var parsed))
            {
                sentAt = parsed.ToUniversalTime();
            }

            result[keyValue.Trim()] = sentAt;
        }

        return result;
    }

    private void PurgeExpiredSentProductKeys(MercadoLivreAffiliateScoutSettings scout, DateTimeOffset nowUtc)
    {
        var window = GetRepeatWindow(scout);
        var expiredKeys = _sentProductKeys
            .Where(x => nowUtc - x.Value >= window)
            .Select(x => x.Key)
            .ToArray();

        foreach (var key in expiredKeys)
        {
            _sentProductKeys.Remove(key);
        }
    }

    private static DateTimeOffset ConvertToBrazilTime(DateTimeOffset value)
    {
        try
        {
            var zone = TimeZoneInfo.FindSystemTimeZoneById("America/Sao_Paulo");
            return TimeZoneInfo.ConvertTime(value, zone);
        }
        catch (TimeZoneNotFoundException)
        {
            var zone = TimeZoneInfo.FindSystemTimeZoneById("E. South America Standard Time");
            return TimeZoneInfo.ConvertTime(value, zone);
        }
    }

    private static string ResolveDestinationLabel(MercadoLivreAffiliateScoutSettings scout)
        => scout.AutoPublishToOfficialGroup
            ? "Grupo Mercado Livre + Rei das Ofertas oficial"
            : "Grupo Mercado Livre";

    private static string ResolveSeenProductsPath(MercadoLivreAffiliateScoutSettings scout)
    {
        if (!string.IsNullOrWhiteSpace(scout.SeenProductsPath))
        {
            return scout.SeenProductsPath.Trim();
        }

        return Path.Combine(AppContext.BaseDirectory, "data", "mercadolivre-affiliate-scout-seen-products.json");
    }

    private async Task<TimeSpan> GetNextIntervalAsync(CancellationToken ct)
    {
        try
        {
            var settings = await _settingsStore.GetAsync(ct);
            var scout = settings.MercadoLivreAffiliateScout;
            if (scout == null) return TimeSpan.FromMinutes(5);

            int minutes = Math.Clamp(scout.IntervalMinutes, 5, 240);
            int jitter = Math.Clamp(scout.IntervalJitterMinutes, 0, 30);
            
            var baseInterval = TimeSpan.FromMinutes(minutes);
            if (jitter > 0)
            {
                baseInterval += TimeSpan.FromMinutes(Random.Shared.Next(0, jitter));
            }
            return baseInterval;
        }
        catch
        {
            return TimeSpan.FromMinutes(10);
        }
    }
}

internal enum MercadoLivreScoutOfferStatus
{
    Invalid,
    Duplicate,
    Filtered,
    Accepted
}

public sealed class MercadoLivreScoutCycleStats
{
    public int FoundCount { get; set; }
    public int AcceptedCount { get; set; }
    public int DuplicateCount { get; set; }
    public int FilteredCount { get; set; }
    public int SentOfferCount { get; set; }
    public int SentOfficialOfferCount { get; set; }
    public int SentCommissionCount { get; set; }
    public int StoryDraftCount { get; set; }
    public int StoryApprovalSentCount { get; set; }
    public int StoryFailedCount { get; set; }
    public int FailedCount { get; set; }
    public bool RefreshRetryUsed { get; set; }
    public DateTimeOffset? LastOfficialScheduledForUtc { get; set; }
}

public sealed record MercadoLivreSentProductRecord(
    string Key,
    DateTimeOffset LastSentAtUtc);
