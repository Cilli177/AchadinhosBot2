using AchadinhosBot.Next.Domain.Settings;

namespace AchadinhosBot.Next.Tests;

public sealed class MercadoLivreAffiliateScoutSettingsTests
{
    [Fact]
    public void NormalizeInPlace_ClampsScoutValues_AndNormalizesStrings()
    {
        var settings = new AutomationSettings
        {
            MercadoLivreAffiliateScout = new MercadoLivreAffiliateScoutSettings
            {
                IntervalMinutes = 1,
                IntervalJitterMinutes = 99,
                MinCommissionPercent = 125m,
                Tier1MinPrice = -10m,
                Tier1MinCommissionPercent = 140m,
                Tier2MinPrice = -1m,
                Tier2MinCommissionPercent = 101m,
                Tier3MinPrice = -5m,
                Tier3MinCommissionPercent = 150m,
                MaxOffersPerRun = 99,
                RepeatWindowHours = 999,
                AuthMode = "  code-or-qr  ",
                BaseUrl = " https://www.mercadolivre.com.br/afiliados ",
                Notes = "  fluxo principal  "
            }
        };

        AutomationSettingsSanitizer.NormalizeInPlace(settings);

        Assert.Equal(5, settings.MercadoLivreAffiliateScout.IntervalMinutes);
        Assert.Equal(30, settings.MercadoLivreAffiliateScout.IntervalJitterMinutes);
        Assert.Equal(100m, settings.MercadoLivreAffiliateScout.MinCommissionPercent);
        Assert.Equal(0m, settings.MercadoLivreAffiliateScout.Tier1MinPrice);
        Assert.Equal(100m, settings.MercadoLivreAffiliateScout.Tier1MinCommissionPercent);
        Assert.Equal(0m, settings.MercadoLivreAffiliateScout.Tier2MinPrice);
        Assert.Equal(100m, settings.MercadoLivreAffiliateScout.Tier2MinCommissionPercent);
        Assert.Equal(0m, settings.MercadoLivreAffiliateScout.Tier3MinPrice);
        Assert.Equal(100m, settings.MercadoLivreAffiliateScout.Tier3MinCommissionPercent);
        Assert.Equal(10, settings.MercadoLivreAffiliateScout.MaxOffersPerRun);
        Assert.Equal(168, settings.MercadoLivreAffiliateScout.RepeatWindowHours);
        Assert.Equal("code-or-qr", settings.MercadoLivreAffiliateScout.AuthMode);
        Assert.Equal("https://www.mercadolivre.com.br/afiliados", settings.MercadoLivreAffiliateScout.BaseUrl);
        Assert.Equal("fluxo principal", settings.MercadoLivreAffiliateScout.Notes);
    }
}
