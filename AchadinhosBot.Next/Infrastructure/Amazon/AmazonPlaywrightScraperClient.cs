using System.Text.Json;
using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Domain.Settings;
using Microsoft.Extensions.Logging;

namespace AchadinhosBot.Next.Infrastructure.Amazon;

/// <summary>
/// Chama o microserviço Playwright (amazon-scraper) para obter dados de produto Amazon
/// sem ser bloqueado por CAPTCHA, pois o browser real executa JavaScript.
/// </summary>
public sealed class AmazonPlaywrightScraperClient
{
    private readonly ISettingsStore _settingsStore;
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly ILogger<AmazonPlaywrightScraperClient> _logger;

    public AmazonPlaywrightScraperClient(
        ISettingsStore settingsStore,
        IHttpClientFactory httpClientFactory,
        ILogger<AmazonPlaywrightScraperClient> logger)
    {
        _settingsStore = settingsStore;
        _httpClientFactory = httpClientFactory;
        _logger = logger;
    }

    public async Task<AmazonScrapedProduct?> ScrapeAsync(string asin, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(asin)) return null;

        var settings = await _settingsStore.GetAsync(ct);
        var config = settings.AmazonPlaywrightScraper ?? new AmazonPlaywrightScraperSettings();

        if (!config.Enabled || string.IsNullOrWhiteSpace(config.BaseUrl))
            return null;

        var timeoutSeconds = config.TimeoutSeconds > 0 ? config.TimeoutSeconds : 35;

        try
        {
            var client = _httpClientFactory.CreateClient("default");
            var url = $"{config.BaseUrl.TrimEnd('/')}/scrape?asin={Uri.EscapeDataString(asin.Trim().ToUpperInvariant())}";

            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(TimeSpan.FromSeconds(timeoutSeconds + 5)); // buffer extra

            using var response = await client.GetAsync(url, cts.Token);
            if (!response.IsSuccessStatusCode)
            {
                _logger.LogWarning("AmazonPlaywrightScraper: HTTP {Status} para ASIN={Asin}", (int)response.StatusCode, asin);
                return null;
            }

            var body = await response.Content.ReadAsStringAsync(cts.Token);
            using var doc = JsonDocument.Parse(body);
            var root = doc.RootElement;

            if (!root.TryGetProperty("success", out var successProp) || !successProp.GetBoolean())
            {
                var err = root.TryGetProperty("error", out var ep) ? ep.GetString() : "desconhecido";
                if (err == "captcha")
                    _logger.LogWarning("AmazonPlaywrightScraper: CAPTCHA detectado para ASIN={Asin}", asin);
                else
                    _logger.LogWarning("AmazonPlaywrightScraper: falha para ASIN={Asin} Erro={Error}", asin, err);
                return null;
            }

            var title = root.TryGetProperty("title", out var tp) ? tp.GetString() : null;
            var price = root.TryGetProperty("price", out var pp) ? pp.GetString() : null;
            var oldPrice = root.TryGetProperty("oldPrice", out var op) ? op.GetString() : null;
            var couponCode = root.TryGetProperty("couponCode", out var cc) ? cc.GetString() : null;
            var couponDesc = root.TryGetProperty("couponDescription", out var cd) ? cd.GetString() : null;
            var isLightning = root.TryGetProperty("isLightningDeal", out var ld) && ld.GetBoolean();

            var images = new List<string>();
            if (root.TryGetProperty("images", out var imgsProp) && imgsProp.ValueKind == JsonValueKind.Array)
            {
                foreach (var img in imgsProp.EnumerateArray())
                {
                    var imgUrl = img.GetString();
                    if (!string.IsNullOrWhiteSpace(imgUrl))
                        images.Add(imgUrl);
                }
            }

            if (string.IsNullOrWhiteSpace(title) && images.Count == 0)
            {
                _logger.LogDebug("AmazonPlaywrightScraper: sem título nem imagens para ASIN={Asin}", asin);
                return null;
            }

            _logger.LogInformation(
                "AmazonPlaywrightScraper OK. ASIN={Asin} Title={Title} Price={Price} Images={Count}",
                asin, title?.Substring(0, Math.Min(60, title?.Length ?? 0)), price, images.Count);

            return new AmazonScrapedProduct(
                Title: title,
                Price: price,
                OldPrice: oldPrice,
                DiscountPercent: null,
                Images: images,
                IsLightningDeal: isLightning,
                LightningDealExpiry: null,
                CouponCode: couponCode,
                CouponDescription: couponDesc);
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            _logger.LogWarning("AmazonPlaywrightScraper: timeout para ASIN={Asin}", asin);
            return null;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "AmazonPlaywrightScraper: exceção para ASIN={Asin}", asin);
            return null;
        }
    }
}
