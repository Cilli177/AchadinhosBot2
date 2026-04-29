using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Application.Services;
using AchadinhosBot.Next.Domain.Settings;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace AchadinhosBot.Next.Infrastructure.MercadoLivre;

public sealed class MercadoLivreAffiliateScoutWorker : BackgroundService
{
    private readonly MercadoLivreAffiliateScoutClient _scoutClient;
    private readonly ISettingsStore _settingsStore;
    private readonly WhatsAppPublishContentService _publishService;
    private readonly WhatsAppAutomationQueueService _queueService;
    private readonly IWhatsAppGateway _whatsappGateway;
    private readonly ILogger<MercadoLivreAffiliateScoutWorker> _logger;

    // Simplified deduplication to avoid re-posting same products in the same run or window
    private readonly HashSet<string> _recentlySeenUrls = new(StringComparer.OrdinalIgnoreCase);
    private DateTimeOffset _lastDedupeCleanup = DateTimeOffset.UtcNow;

    public MercadoLivreAffiliateScoutWorker(
        MercadoLivreAffiliateScoutClient scoutClient,
        ISettingsStore settingsStore,
        WhatsAppPublishContentService publishService,
        WhatsAppAutomationQueueService queueService,
        IWhatsAppGateway whatsappGateway,
        ILogger<MercadoLivreAffiliateScoutWorker> logger)
    {
        _scoutClient = scoutClient;
        _settingsStore = settingsStore;
        _publishService = publishService;
        _queueService = queueService;
        _whatsappGateway = whatsappGateway;
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

        var result = await _scoutClient.TestAsync(ct);
        if (!result.Success || result.Offers.Count == 0)
        {
            _logger.LogInformation("MercadoLivreAffiliateScoutWorker: Nenhuma oferta encontrada ou falha no scraper. Msg: {Msg}", result.Message);
            return;
        }

        _logger.LogInformation("MercadoLivreAffiliateScoutWorker: Encontradas {Count} ofertas. Filtrando...", result.Offers.Count);

        CleanupDedupeCache();

        int sentCount = 0;
        foreach (var offer in result.Offers)
        {
            if (sentCount >= scout.MaxOffersPerRun) break;

            if (IsInvalidOrDuplicate(offer, scout)) continue;

            try
            {
                await ProcessAndSendOfferAsync(offer, scout, ct);
                _recentlySeenUrls.Add(offer.ProductUrl!);
                sentCount++;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Erro ao processar oferta ML: {Title}", offer.Title);
            }
        }

        _logger.LogInformation("MercadoLivreAffiliateScoutWorker: Ciclo finalizado. {Sent} ofertas enviadas para fila.", sentCount);
    }

    private bool IsInvalidOrDuplicate(MercadoLivreAffiliateScoutOffer offer, MercadoLivreAffiliateScoutSettings scout)
    {
        if (string.IsNullOrWhiteSpace(offer.ProductUrl)) return true;
        
        // 1. Check if already seen recently
        if (_recentlySeenUrls.Contains(offer.ProductUrl))
        {
            _logger.LogDebug("Oferta ja enviada recentemente: {Url}", offer.ProductUrl);
            return true;
        }

        // 2. Parse price and commission for tiered filtering
        decimal price = TryParsePrice(offer.PriceText);
        decimal comm = TryParseCommission(offer.CommissionText);

        // Tiered filter logic requested by user:
        // 1. comissão maior que 19%
        // 2. se preço maior que 245 e comissão maior que 11%
        // 3. se preço maior que 345 e comissão maior que 7%
        
        bool isAccepted = (comm >= 19m)
            || (price >= 245m && comm >= 11m)
            || (price >= 345m && comm >= 7m);

        if (!isAccepted)
        {
            _logger.LogInformation("Oferta ML ignorada (Filtro Tiered): {Title} | Preco: {Price} | Comm: {Comm}%", offer.Title, price, comm);
            return true;
        }

        _logger.LogInformation("Oferta ML ACEITA: {Title} | Preco: {Price} | Comm: {Comm}%", offer.Title, price, comm);
        return false;
    }

    private decimal TryParsePrice(string? text)
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

    private decimal TryParseCommission(string? text)
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

    private async Task ProcessAndSendOfferAsync(MercadoLivreAffiliateScoutOffer offer, MercadoLivreAffiliateScoutSettings scout, CancellationToken ct)
    {
        var targetGroupId = scout.AutoPublishToOfficialGroup 
            ? "120363405661434395@g.us" // Oficial: Rei das Ofertas
            : (scout.DestinationGroupId ?? "120363409272515351@g.us"); // Teste ou fallback

        var instanceName = scout.WhatsAppInstanceName ?? "ZapOfertas";

        if (string.IsNullOrWhiteSpace(targetGroupId))
        {
            _logger.LogWarning("MercadoLivreAffiliateScoutWorker: TargetGroupId nao configurado.");
            return;
        }

        _logger.LogInformation("MercadoLivreAffiliateScoutWorker: Roteando oferta para {Group}. AutoPublish={Auto}", 
            targetGroupId == "120363405661434395@g.us" ? "OFICIAL" : "TESTE", 
            scout.AutoPublishToOfficialGroup);

        // Build base text
        string rawText = $"🔥 *{offer.Title}*\n\n💰 *Promoção:* {offer.PriceText}\n\n🔗 Clique e compre: {offer.SharedUrl ?? offer.ProductUrl}";
        
        // Prepare content (Link shortening, formatting, image resolving)
        var prepared = await _publishService.PrepareForSendAsync(rawText, offer.ImageUrl, targetGroupId, ct);

        // Enqueue for delivery
        await _queueService.EnqueueAsync(
            "mercadolivre_scout",
            $"Oferta ML: {offer.Title}",
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
            ct);
        
        _logger.LogInformation("Oferta ML enfileirada para {Target}: {Title}", targetGroupId, offer.Title);
    }

    private void CleanupDedupeCache()
    {
        // Clear every 24 hours to prevent memory bloat
        if ((DateTimeOffset.UtcNow - _lastDedupeCleanup).TotalHours > 24)
        {
            _recentlySeenUrls.Clear();
            _lastDedupeCleanup = DateTimeOffset.UtcNow;
        }
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
