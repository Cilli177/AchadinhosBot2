using AchadinhosBot.Next.Domain.Settings;
using AchadinhosBot.Next.Infrastructure.MercadoLivre;

namespace AchadinhosBot.Next.Tests;

public sealed class MercadoLivreAffiliateScoutSettingsTests
{
    [Fact]
    public void IsAcceptedByCommissionTiers_UsesConfiguredThresholds()
    {
        var scout = new MercadoLivreAffiliateScoutSettings
        {
            MinCommissionPercent = 19m,
            Tier1MinPrice = 99m,
            Tier1MinCommissionPercent = 12m,
            Tier2MinPrice = 189m,
            Tier2MinCommissionPercent = 11m,
            Tier3MinPrice = 325m,
            Tier3MinCommissionPercent = 7m
        };

        Assert.True(MercadoLivreAffiliateScoutWorker.IsAcceptedByCommissionTiers(50m, 19m, scout));
        Assert.True(MercadoLivreAffiliateScoutWorker.IsAcceptedByCommissionTiers(99m, 12m, scout));
        Assert.True(MercadoLivreAffiliateScoutWorker.IsAcceptedByCommissionTiers(189m, 11m, scout));
        Assert.True(MercadoLivreAffiliateScoutWorker.IsAcceptedByCommissionTiers(325m, 7m, scout));
        Assert.False(MercadoLivreAffiliateScoutWorker.IsAcceptedByCommissionTiers(98m, 12m, scout));
        Assert.False(MercadoLivreAffiliateScoutWorker.IsAcceptedByCommissionTiers(325m, 6.99m, scout));
    }

    [Fact]
    public void RankOffersByCommission_FiltersByTiers_AndPrioritizesHighestCommission()
    {
        var scout = new MercadoLivreAffiliateScoutSettings
        {
            MinCommissionPercent = 19m,
            Tier1MinPrice = 99m,
            Tier1MinCommissionPercent = 12m,
            Tier2MinPrice = 189m,
            Tier2MinCommissionPercent = 11m,
            Tier3MinPrice = 325m,
            Tier3MinCommissionPercent = 7m
        };

        var offers = new[]
        {
            new MercadoLivreAffiliateScoutOffer("Comissao baixa", "https://example.com/low", null, "R$ 500,00", "6%", null),
            new MercadoLivreAffiliateScoutOffer("Maior comissao", "https://example.com/high", null, "R$ 80,00", "25%", null),
            new MercadoLivreAffiliateScoutOffer("Tier alto valor", "https://example.com/tier", null, "R$ 400,00", "8%", null),
            new MercadoLivreAffiliateScoutOffer("Empate preco maior", "https://example.com/tie", null, "R$ 120,00", "25%", null)
        };

        var ranked = MercadoLivreAffiliateScoutWorker.RankOffersByCommission(offers, scout);

        Assert.Equal("Empate preco maior", ranked[0].Title);
        Assert.Equal("Maior comissao", ranked[1].Title);
        Assert.Equal("Tier alto valor", ranked[2].Title);
        Assert.DoesNotContain(ranked, offer => offer.Title == "Comissao baixa");
    }

    [Fact]
    public void GetEffectiveMinimumCommissionPercent_UsesLowestEnabledTierForCandidateCollection()
    {
        var scout = new MercadoLivreAffiliateScoutSettings
        {
            MinCommissionPercent = 25m,
            Tier1MinPrice = 99m,
            Tier1MinCommissionPercent = 12m,
            Tier2MinPrice = 189m,
            Tier2MinCommissionPercent = 11m,
            Tier3MinPrice = 325m,
            Tier3MinCommissionPercent = 7m
        };

        Assert.Equal(7m, MercadoLivreAffiliateScoutWorker.GetEffectiveMinimumCommissionPercent(scout));
    }

    [Fact]
    public void BuildScoutMessage_UsesFriendlyWhatsAppTemplate()
    {
        var offer = new MercadoLivreAffiliateScoutOffer(
            "Ventilador Arno",
            "https://produto.mercadolivre.com.br/MLB-1",
            "https://meli.la/abc",
            "R$ 289,00",
            "35%",
            null);

        var message = MercadoLivreAffiliateScoutWorker.BuildScoutMessage(offer);

        Assert.Contains("Achadinho Mercado Livre", message);
        Assert.Contains("Ventilador Arno", message);
        Assert.Contains("R$ 289,00", message);
        Assert.Contains("35%", message);
        Assert.Contains("Comiss", message);
        Assert.Contains("https://meli.la/abc", message);
        Assert.Contains("\U0001F525", message);
        Assert.Contains("Pre\u00e7o", message);
        AssertDoesNotContainMojibake(message);
    }

    [Fact]
    public void BuildScoutMessage_CanHideCommissionForOfficialGroup()
    {
        var offer = new MercadoLivreAffiliateScoutOffer(
            "Ventilador Arno",
            "https://produto.mercadolivre.com.br/MLB-1",
            "https://meli.la/abc",
            "R$ 289,00",
            "35%",
            null);

        var message = MercadoLivreAffiliateScoutWorker.BuildScoutMessage(offer, includeCommission: false);

        Assert.Contains("Ventilador Arno", message);
        Assert.DoesNotContain("35%", message);
        Assert.DoesNotContain("Comiss", message);
        Assert.Contains("https://meli.la/abc", message);
        AssertDoesNotContainMojibake(message);
    }

    [Fact]
    public void BuildCommissionNoteMessage_UsesSeparateOperationalMessage()
    {
        var offer = new MercadoLivreAffiliateScoutOffer(
            "Ventilador Arno",
            "https://produto.mercadolivre.com.br/MLB-1",
            "https://meli.la/abc",
            "R$ 289,00",
            "35%",
            null);

        var message = MercadoLivreAffiliateScoutWorker.BuildCommissionNoteMessage(offer);

        Assert.Contains("Comiss\u00e3o da oferta acima", message);
        Assert.Contains("35%", message);
        Assert.Contains("\U0001F4CA", message);
        AssertDoesNotContainMojibake(message);
    }

    [Fact]
    public void BuildCommissionNoteMessage_HandlesMissingCommission()
    {
        var offer = new MercadoLivreAffiliateScoutOffer(
            "Ventilador Arno",
            "https://produto.mercadolivre.com.br/MLB-1",
            "https://meli.la/abc",
            "R$ 289,00",
            null,
            null);

        var message = MercadoLivreAffiliateScoutWorker.BuildCommissionNoteMessage(offer);

        Assert.Contains("n\u00e3o informada pelo Mercado Livre", message);
        AssertDoesNotContainMojibake(message);
    }

    [Fact]
    public void BuildScoutStartMessage_DescribesCycleAndFilters()
    {
        var scout = new MercadoLivreAffiliateScoutSettings
        {
            MinCommissionPercent = 19m,
            Tier1MinPrice = 99m,
            Tier1MinCommissionPercent = 12m,
            Tier2MinPrice = 189m,
            Tier2MinCommissionPercent = 11m,
            Tier3MinPrice = 325m,
            Tier3MinCommissionPercent = 7m,
            RepeatWindowHours = 6,
            MaxOffersPerRun = 0,
            DestinationGroupId = "120363409272515351@g.us",
            AutoPublishToOfficialGroup = false
        };

        var message = MercadoLivreAffiliateScoutWorker.BuildScoutStartMessage(
            scout,
            new DateTimeOffset(2026, 4, 30, 12, 42, 0, TimeSpan.Zero));

        Assert.Contains("Scout Mercado Livre iniciado", message);
        Assert.Contains("30/04/2026 09:42 BRT", message);
        Assert.Contains("Comiss\u00e3o geral: *19%+*", message);
        Assert.Contains("Tier 1", message);
        Assert.Contains("R$ 99+", message);
        Assert.Contains("7%", message);
        Assert.Contains("6h", message);
        Assert.Contains("ilimitado por ciclo", message);
        Assert.Contains("Grupo Mercado Livre", message);
        Assert.Contains("comiss\u00e3o logo abaixo de cada oferta", message);
        AssertDoesNotContainMojibake(message);
    }

    [Fact]
    public void BuildScoutStartMessage_DescribesOfficialMirrorWhenEnabled()
    {
        var scout = new MercadoLivreAffiliateScoutSettings
        {
            AutoPublishToOfficialGroup = true,
            DestinationGroupId = "120363409272515351@g.us"
        };

        var message = MercadoLivreAffiliateScoutWorker.BuildScoutStartMessage(
            scout,
            new DateTimeOffset(2026, 4, 30, 12, 42, 0, TimeSpan.Zero));

        Assert.Contains("Grupo Mercado Livre + Rei das Ofertas oficial", message);
        AssertDoesNotContainMojibake(message);
    }

    [Fact]
    public void BuildScoutSummaryMessage_IncludesCycleCounters()
    {
        var message = MercadoLivreAffiliateScoutWorker.BuildScoutSummaryMessage(new MercadoLivreScoutCycleStats
        {
            FoundCount = 15,
            AcceptedCount = 7,
            DuplicateCount = 4,
            FilteredCount = 4,
            SentOfferCount = 5,
            SentOfficialOfferCount = 5,
            SentCommissionCount = 5,
            StoryDraftCount = 3,
            StoryApprovalSentCount = 3,
            FailedCount = 0,
            RefreshRetryUsed = true
        });

        Assert.Contains("Ofertas buscadas: *15*", message);
        Assert.Contains("Aprovadas pelos filtros: *7*", message);
        Assert.Contains("Repetidas ignoradas: *4*", message);
        Assert.Contains("Fora do filtro: *4*", message);
        Assert.Contains("Ofertas enviadas: *5*", message);
        Assert.Contains("Ofertas enviadas ao Rei das Ofertas: *5*", message);
        Assert.Contains("Comiss\u00f5es anexadas \u00e0s ofertas: *5*", message);
        Assert.Contains("Stories ML criados: *3*", message);
        Assert.Contains("Aprova\u00e7\u00f5es de story enviadas: *3*", message);
        Assert.Contains("Refresh extra: *sim*", message);
        AssertDoesNotContainMojibake(message);
    }

    [Fact]
    public void ResolveOfficialScheduledForUtc_ThrottlesOnlyAfterFirstOfficialOffer()
    {
        Assert.Null(MercadoLivreAffiliateScoutWorker.ResolveOfficialScheduledForUtc(0, throttleOfficialOffers: true));
        Assert.NotNull(MercadoLivreAffiliateScoutWorker.ResolveOfficialScheduledForUtc(1, throttleOfficialOffers: true));
        Assert.Null(MercadoLivreAffiliateScoutWorker.ResolveOfficialScheduledForUtc(2, throttleOfficialOffers: false));
    }

    [Fact]
    public void IsWithinRepeatWindow_BlocksOnlyInsideConfiguredWindow()
    {
        var scout = new MercadoLivreAffiliateScoutSettings { RepeatWindowHours = 6 };
        var now = new DateTimeOffset(2026, 4, 30, 12, 0, 0, TimeSpan.Zero);

        Assert.True(MercadoLivreAffiliateScoutWorker.IsWithinRepeatWindow(now.AddHours(-5).AddMinutes(-59), now, scout));
        Assert.False(MercadoLivreAffiliateScoutWorker.IsWithinRepeatWindow(now.AddHours(-6), now, scout));
        Assert.False(MercadoLivreAffiliateScoutWorker.IsWithinRepeatWindow(now.AddHours(-7), now, scout));
    }

    [Fact]
    public void ParseSentProductKeysFromJson_MigratesLegacyStringArray()
    {
        var now = new DateTimeOffset(2026, 4, 30, 12, 0, 0, TimeSpan.Zero);

        var parsed = MercadoLivreAffiliateScoutWorker.ParseSentProductKeysFromJson(
            """["MLB123","title:produto antigo"]""",
            now);

        Assert.Equal(now, parsed["MLB123"]);
        Assert.Equal(now, parsed["title:produto antigo"]);
    }

    [Fact]
    public void ParseSentProductKeysFromJson_ReadsTimestampRecords()
    {
        var now = new DateTimeOffset(2026, 4, 30, 12, 0, 0, TimeSpan.Zero);

        var parsed = MercadoLivreAffiliateScoutWorker.ParseSentProductKeysFromJson(
            """[{"key":"MLB123","lastSentAtUtc":"2026-04-30T09:00:00+00:00"}]""",
            now);

        Assert.Equal(new DateTimeOffset(2026, 4, 30, 9, 0, 0, TimeSpan.Zero), parsed["MLB123"]);
    }

    [Fact]
    public void MercadoLivreAffiliateScoutRequest_SerializesForceRefreshBeforeScan()
    {
        var request = new MercadoLivreAffiliateScoutRequest(
            true,
            true,
            true,
            "https://www.mercadolivre.com.br/afiliados",
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            "code-or-qr",
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            true,
            true,
            true,
            0,
            7m,
            99m,
            12m,
            189m,
            11m,
            325m,
            7m,
            120,
            true);

        var json = System.Text.Json.JsonSerializer.Serialize(
            request,
            new System.Text.Json.JsonSerializerOptions(System.Text.Json.JsonSerializerDefaults.Web));

        Assert.Contains(@"""forceRefreshBeforeScan"":true", json);
    }

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
                MaxOffersPerRun = 999,
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
        Assert.Equal(500, settings.MercadoLivreAffiliateScout.MaxOffersPerRun);
        Assert.Equal(168, settings.MercadoLivreAffiliateScout.RepeatWindowHours);
        Assert.Equal("code-or-qr", settings.MercadoLivreAffiliateScout.AuthMode);
        Assert.Equal("https://www.mercadolivre.com.br/afiliados", settings.MercadoLivreAffiliateScout.BaseUrl);
        Assert.Equal("fluxo principal", settings.MercadoLivreAffiliateScout.Notes);
    }

    [Fact]
    public void NormalizeInPlace_AllowsThirtyMinuteScoutCadenceWithoutJitter()
    {
        var settings = new AutomationSettings
        {
            MercadoLivreAffiliateScout = new MercadoLivreAffiliateScoutSettings
            {
                IntervalMinutes = 30,
                IntervalJitterMinutes = 0,
                MaxOffersPerRun = 0,
                RepeatWindowHours = 6
            }
        };

        AutomationSettingsSanitizer.NormalizeInPlace(settings);

        Assert.Equal(30, settings.MercadoLivreAffiliateScout.IntervalMinutes);
        Assert.Equal(0, settings.MercadoLivreAffiliateScout.IntervalJitterMinutes);
        Assert.Equal(0, settings.MercadoLivreAffiliateScout.MaxOffersPerRun);
        Assert.Equal(6, settings.MercadoLivreAffiliateScout.RepeatWindowHours);
    }

    [Fact]
    public void NormalizeInPlace_NormalizesMercadoLivreStorySettings()
    {
        var settings = new AutomationSettings
        {
            MercadoLivreAffiliateScout = new MercadoLivreAffiliateScoutSettings
            {
                StoryDraftsPerDay = 99,
                StoryScheduleTimes = new List<string> { "23:00", "bad", "09:00", "09:00" },
                StoryApprovalWhatsAppGroupId = " 120363426166665839@g.us ",
                StoryApprovalWhatsAppInstanceName = " ZapOfertas "
            }
        };

        AutomationSettingsSanitizer.NormalizeInPlace(settings);

        Assert.Equal(24, settings.MercadoLivreAffiliateScout.StoryDraftsPerDay);
        Assert.Equal(new[] { "09:00", "23:00" }, settings.MercadoLivreAffiliateScout.StoryScheduleTimes);
        Assert.Equal("120363426166665839@g.us", settings.MercadoLivreAffiliateScout.StoryApprovalWhatsAppGroupId);
        Assert.Equal("ZapOfertas", settings.MercadoLivreAffiliateScout.StoryApprovalWhatsAppInstanceName);
    }

    private static void AssertDoesNotContainMojibake(string message)
    {
        Assert.DoesNotContain("\u00c3", message);
        Assert.DoesNotContain("\u00f0\u0178", message);
        Assert.DoesNotContain("\u00e2\u0161", message);
    }
}
