using System.Net.Http.Json;
using System.Text.Json;
using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Domain.Settings;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;

namespace AchadinhosBot.Next.Infrastructure.MercadoLivre;

public sealed class MercadoLivreAffiliateScoutClient
{
    private readonly ISettingsStore _settingsStore;
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly IConfiguration _configuration;
    private readonly ILogger<MercadoLivreAffiliateScoutClient> _logger;

    public MercadoLivreAffiliateScoutClient(
        ISettingsStore settingsStore,
        IHttpClientFactory httpClientFactory,
        IConfiguration configuration,
        ILogger<MercadoLivreAffiliateScoutClient> logger)
    {
        _settingsStore = settingsStore;
        _httpClientFactory = httpClientFactory;
        _configuration = configuration;
        _logger = logger;
    }

    public async Task<MercadoLivreAffiliateScoutResult> TestAsync(CancellationToken ct)
    {
        var settings = await _settingsStore.GetAsync(ct);
        var scout = settings.MercadoLivreAffiliateScout ?? new MercadoLivreAffiliateScoutSettings();
        var serviceBaseUrl = (_configuration["MercadoLivreAffiliateScoutService:BaseUrl"]
            ?? _configuration["MERCADOLIVRE_AFFILIATE_SCRAPER__BASEURL"]
            ?? "http://mercadolivre-affiliate-scraper:3002").Trim();

        var request = new MercadoLivreAffiliateScoutRequest(
            scout.Enabled,
            scout.UsePersistentSession,
            scout.Headless,
            scout.BaseUrl,
            scout.LoginUrl,
            scout.HomeUrl,
            scout.LoginUser,
            scout.LoginPassword,
            scout.TwoFactorCode,
            scout.StorageStateJson,
            scout.StorageStatePath,
            scout.AuthMode,
            scout.OfferCardSelector,
            scout.OfferLinkSelector,
            scout.OfferTitleSelector,
            scout.OfferPriceSelector,
            scout.OfferImageSelector,
            scout.OfferCommissionSelector,
            scout.ShareButtonSelector,
            scout.ShareActionSelector,
            scout.SharedLinkSelector,
            scout.SharedLinkCopyButtonSelector,
            scout.RequireShareButtonFlow,
            scout.RequireImage,
            scout.SaveScreenshotsOnFailure,
            scout.MaxOffersPerRun);

        try
        {
            var client = _httpClientFactory.CreateClient("default");
            client.Timeout = TimeSpan.FromSeconds(120);

            using var response = await client.PostAsJsonAsync(
                $"{serviceBaseUrl.TrimEnd('/')}/test",
                request,
                cancellationToken: ct);

            if (!response.IsSuccessStatusCode)
            {
                var body = await response.Content.ReadAsStringAsync(ct);
                _logger.LogWarning("MercadoLivreAffiliateScout: HTTP {Status}. Body={Body}", (int)response.StatusCode, body);
                return new MercadoLivreAffiliateScoutResult(false, false, null, null, null, null, [], body, null);
            }

            var result = await response.Content.ReadFromJsonAsync<MercadoLivreAffiliateScoutResult>(
                new JsonSerializerOptions(JsonSerializerDefaults.Web),
                ct);

            return result ?? new MercadoLivreAffiliateScoutResult(false, false, null, null, null, null, [], "resposta vazia", null);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "MercadoLivreAffiliateScout: falha ao testar o scraper Playwright");
            return new MercadoLivreAffiliateScoutResult(false, false, null, null, null, null, [], ex.Message, null);
        }
    }
}

public sealed record MercadoLivreAffiliateScoutRequest(
    bool Enabled,
    bool UsePersistentSession,
    bool Headless,
    string? BaseUrl,
    string? LoginUrl,
    string? HomeUrl,
    string? LoginUser,
    string? LoginPassword,
    string? TwoFactorCode,
    string? StorageStateJson,
    string? StorageStatePath,
    string? AuthMode,
    string? OfferCardSelector,
    string? OfferLinkSelector,
    string? OfferTitleSelector,
    string? OfferPriceSelector,
    string? OfferImageSelector,
    string? OfferCommissionSelector,
    string? ShareButtonSelector,
    string? ShareActionSelector,
    string? SharedLinkSelector,
    string? SharedLinkCopyButtonSelector,
    bool RequireShareButtonFlow,
    bool RequireImage,
    bool SaveScreenshotsOnFailure,
    int MaxOffersPerRun);

public sealed record MercadoLivreAffiliateScoutOffer(
    string? Title,
    string? ProductUrl,
    string? SharedUrl,
    string? PriceText,
    string? CommissionText,
    string? ImageUrl);

public sealed record MercadoLivreAffiliateScoutResult(
    bool Success,
    bool LoggedIn,
    bool? AuthRequired,
    string? AuthModeDetected,
    string? CurrentUrl,
    string? ScreenshotPath,
    IReadOnlyList<MercadoLivreAffiliateScoutOffer> Offers,
    string? Message,
    string? PageTitle);
