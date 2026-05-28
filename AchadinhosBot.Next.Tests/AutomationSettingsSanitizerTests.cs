using AchadinhosBot.Next.Domain.Settings;

namespace AchadinhosBot.Next.Tests;

public sealed class AutomationSettingsSanitizerTests
{
    [Fact]
    public void Normalize_RepairsLegacyConversorScheduleText()
    {
        var text = "????Use nosso conversor para transformar qualquer link em link pronto para oferta:\n" +
            "??https://reidasofertas.ia.br/conversor\n\n" +
            "Abra quando precisar e compartilhe com quem quiser.";

        var normalized = AutomationSettingsSanitizer.Normalize(text);

        Assert.Equal(
            "\uD83D\uDD17 Use nosso conversor para transformar qualquer link em link pronto para oferta:\n" +
            "https://reidasofertas.ia.br/conversor\n\n" +
            "Abra quando precisar e compartilhe com quem quiser.",
            normalized);
    }

    [Fact]
    public void Normalize_RepairsLegacyBioAndSilenceScheduleFragments()
    {
        var bio = "?? Nossa bio est? atualizada com os principais atalhos e destaques:";
        var silence = "?? Para no perder as ofertas e evitar excesso de notificaes, deixe este grupo silenciado.\n\n" +
            "No WhatsApp: abra o grupo -> toque no nome -> Silenciar notificaes -> Sempre.";

        Assert.Equal(
            "\uD83D\uDD17 Nossa bio est\u00E1 atualizada com os principais atalhos e destaques:",
            AutomationSettingsSanitizer.Normalize(bio));
        Assert.Equal(
            "\uD83D\uDD15 Para n\u00E3o perder as ofertas e evitar excesso de notifica\u00E7\u00F5es, deixe este grupo silenciado.\n\n" +
            "No WhatsApp: abra o grupo -> toque no nome -> Silenciar notifica\u00E7\u00F5es -> Sempre.",
            AutomationSettingsSanitizer.Normalize(silence));
    }

    [Fact]
    public void MaskSecretsInPlace_MasksProviderPublishAndScoutSecrets()
    {
        var settings = new AutomationSettings
        {
            OpenAI = new OpenAISettings { ApiKey = "sk-real", ApiKeys = new List<string> { "sk-a", "sk-b" } },
            InstagramPublish = new InstagramPublishSettings
            {
                AccessToken = "EA-real",
                VerifyToken = "verify-real",
                ManyChatApiKey = "manychat-real"
            },
            MercadoLivreAffiliateScout = new MercadoLivreAffiliateScoutSettings
            {
                LoginUser = "user@example.com",
                LoginPassword = "password",
                TwoFactorCode = "123456",
                StorageStateJson = "{\"cookies\":[]}",
                ProductionRelayAdminKey = "relay-secret"
            }
        };

        AutomationSettingsSanitizer.MaskSecretsInPlace(settings);

        Assert.Equal("********", settings.OpenAI.ApiKey);
        Assert.Equal(new[] { "********", "********" }, settings.OpenAI.ApiKeys);
        Assert.Equal("********", settings.InstagramPublish.AccessToken);
        Assert.Equal("********", settings.InstagramPublish.VerifyToken);
        Assert.Equal("********", settings.InstagramPublish.ManyChatApiKey);
        Assert.Equal("********", settings.MercadoLivreAffiliateScout.LoginUser);
        Assert.Equal("********", settings.MercadoLivreAffiliateScout.LoginPassword);
        Assert.Equal("********", settings.MercadoLivreAffiliateScout.TwoFactorCode);
        Assert.Equal("********", settings.MercadoLivreAffiliateScout.StorageStateJson);
        Assert.Equal("********", settings.MercadoLivreAffiliateScout.ProductionRelayAdminKey);
    }
}
