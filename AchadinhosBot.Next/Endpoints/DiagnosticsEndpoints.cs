using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Configuration;
using AchadinhosBot.Next.Domain.Settings;
using Microsoft.Extensions.Options;

namespace AchadinhosBot.Next.Endpoints;

public static class DiagnosticsEndpoints
{
    public static void MapDiagnosticsEndpoints(this RouteGroupBuilder api)
    {
        api.MapGet("/diagnostics/apis", async (
            ISettingsStore store,
            IOptions<AffiliateOptions> affiliateOptions,
            IMercadoLivreOAuthService mercadoLivreOAuthService,
            CancellationToken ct) =>
        {
            var settings = await store.GetAsync(ct);
            var affiliate = affiliateOptions.Value;

            var gemini = settings.Gemini ?? new GeminiSettings();
            var geminiKeys = new List<string>();
            if (!string.IsNullOrWhiteSpace(gemini.ApiKey) && gemini.ApiKey != "********")
            {
                geminiKeys.Add(gemini.ApiKey.Trim());
            }
            if (gemini.ApiKeys is not null)
            {
                geminiKeys.AddRange(gemini.ApiKeys
                    .Where(x => !string.IsNullOrWhiteSpace(x))
                    .Select(x => x.Trim())
                    .Where(x => x != "********"));
            }

            var openAiConfigured = !string.IsNullOrWhiteSpace(settings.OpenAI?.ApiKey) && settings.OpenAI.ApiKey != "********";
            var openAiKeys = NormalizeSecretList(settings.OpenAI?.ApiKeys);
            if (openAiConfigured && !string.IsNullOrWhiteSpace(settings.OpenAI?.ApiKey))
            {
                openAiKeys.Add(settings.OpenAI.ApiKey.Trim());
            }
            openAiKeys = openAiKeys.Distinct(StringComparer.Ordinal).ToList();
            var deepSeekKeys = NormalizeSecretList(settings.DeepSeek?.ApiKeys);
            if (!string.IsNullOrWhiteSpace(settings.DeepSeek?.ApiKey) && settings.DeepSeek.ApiKey != "********")
            {
                deepSeekKeys.Add(settings.DeepSeek.ApiKey.Trim());
            }
            deepSeekKeys = deepSeekKeys.Distinct(StringComparer.Ordinal).ToList();
            var nemotronKeys = NormalizeSecretList(settings.Nemotron?.ApiKeys);
            if (!string.IsNullOrWhiteSpace(settings.Nemotron?.ApiKey) && settings.Nemotron.ApiKey != "********")
            {
                nemotronKeys.Add(settings.Nemotron.ApiKey.Trim());
            }
            nemotronKeys = nemotronKeys.Distinct(StringComparer.Ordinal).ToList();
            var qwenKeys = NormalizeSecretList(settings.Qwen?.ApiKeys);
            if (!string.IsNullOrWhiteSpace(settings.Qwen?.ApiKey) && settings.Qwen.ApiKey != "********")
            {
                qwenKeys.Add(settings.Qwen.ApiKey.Trim());
            }
            qwenKeys = qwenKeys.Distinct(StringComparer.Ordinal).ToList();
            var vilaKeys = NormalizeSecretList(settings.VilaNvidia?.ApiKeys);
            if (!string.IsNullOrWhiteSpace(settings.VilaNvidia?.ApiKey) && settings.VilaNvidia.ApiKey != "********")
            {
                vilaKeys.Add(settings.VilaNvidia.ApiKey.Trim());
            }
            vilaKeys = vilaKeys.Distinct(StringComparer.Ordinal).ToList();
            var amazonApi = affiliate.AmazonProductApi ?? new AmazonProductApiOptions();
            var amazonCreatorApi = affiliate.AmazonCreatorApi ?? new AmazonCreatorApiOptions();
            var amazonPaConfigured = !string.IsNullOrWhiteSpace(amazonApi.AccessKey)
                && !string.IsNullOrWhiteSpace(amazonApi.SecretKey)
                && !string.IsNullOrWhiteSpace(amazonApi.PartnerTag);
            var amazonCreatorConfigured = !string.IsNullOrWhiteSpace(amazonCreatorApi.ClientId)
                && !string.IsNullOrWhiteSpace(amazonCreatorApi.ClientSecret)
                && !string.IsNullOrWhiteSpace(amazonCreatorApi.TokenEndpoint)
                && !string.IsNullOrWhiteSpace(amazonCreatorApi.CatalogEndpoint)
                && !string.IsNullOrWhiteSpace(amazonCreatorApi.Version);
            var shopeeApi = affiliate.ShopeeProductApi ?? new ShopeeProductApiOptions();
            var shopeeConfigured = shopeeApi.PartnerId > 0
                && shopeeApi.ShopId > 0
                && !string.IsNullOrWhiteSpace(shopeeApi.PartnerKey);
            var mercadoLivreOAuthConfigured =
                !string.IsNullOrWhiteSpace(affiliate.MercadoLivreClientId) &&
                !string.IsNullOrWhiteSpace(affiliate.MercadoLivreClientSecret) &&
                !string.IsNullOrWhiteSpace(affiliate.MercadoLivreRefreshToken) &&
                !string.IsNullOrWhiteSpace(affiliate.MercadoLivreUserId);
            var mercadoLivreOAuthStatus = mercadoLivreOAuthConfigured
                ? await mercadoLivreOAuthService.GetStatusAsync(ct)
                : null;

            var publish = settings.InstagramPublish ?? new InstagramPublishSettings();
            return Results.Ok(new
            {
                app = new
                {
                    instagramPublishEnabled = publish.Enabled,
                    autoPilotEnabled = publish.AutoPilotEnabled,
                    storyAutoPilotEnabled = publish.StoryAutoPilotEnabled,
                    strictMode = new
                    {
                        requireOfficialProductData = publish.AutoPilotRequireOfficialProductData,
                        minimumImageMatchScore = publish.AutoPilotMinimumImageMatchScore,
                        requireAiCaption = publish.AutoPilotRequireAiCaption
                    }
                },
                ai = new
                {
                    openAiConfigured = openAiKeys.Count > 0,
                    openAiKeysConfigured = openAiKeys.Count,
                    geminiKeysConfigured = geminiKeys.Distinct(StringComparer.Ordinal).Count(),
                    deepSeekKeysConfigured = deepSeekKeys.Count,
                    nemotronKeysConfigured = nemotronKeys.Count,
                    qwenKeysConfigured = qwenKeys.Count,
                    vilaKeysConfigured = vilaKeys.Count
                },
                officialProductApis = new
                {
                    amazon = new
                    {
                        enabled = amazonApi.Enabled || amazonCreatorApi.Enabled,
                        configured = amazonPaConfigured || amazonCreatorConfigured,
                        provider = amazonCreatorApi.Enabled
                            ? "creator-api"
                            : (amazonApi.Enabled ? "pa-api" : "fallback"),
                        creatorApi = new
                        {
                            enabled = amazonCreatorApi.Enabled,
                            configured = amazonCreatorConfigured
                        },
                        paApi = new
                        {
                            enabled = amazonApi.Enabled,
                            configured = amazonPaConfigured
                        }
                    },
                    shopee = new
                    {
                        enabled = shopeeApi.Enabled,
                        configured = shopeeConfigured
                    },
                    mercadoLivre = new
                    {
                        oauthConfigured = mercadoLivreOAuthConfigured,
                        oauthValid = mercadoLivreOAuthStatus?.Success ?? false,
                        oauthMessage = mercadoLivreOAuthStatus?.Message
                    }
                },
                integrations = new
                {
                    whatsappConnected = settings.Integrations?.WhatsApp?.Connected ?? false,
                    telegramConnected = settings.Integrations?.Telegram?.Connected ?? false,
                    mercadoLivreConnected = settings.Integrations?.MercadoLivre?.Connected ?? false
                }
            });
        });
    }

    private static List<string> NormalizeSecretList(IEnumerable<string>? values)
        => (values ?? Array.Empty<string>())
            .Select(NormalizeSecret)
            .Where(x => !string.IsNullOrWhiteSpace(x))
            .Cast<string>()
            .Distinct(StringComparer.Ordinal)
            .ToList();

    private static string? NormalizeSecret(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        var trimmed = value.Trim();
        return trimmed == "********" ? null : trimmed;
    }
}
