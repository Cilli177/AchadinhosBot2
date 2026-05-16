using AchadinhosBot.Next.Application.Services;

namespace AchadinhosBot.Next.Tests;

public sealed class WhatsAppNicheGroupServiceTests
{
    [Fact]
    public void Classify_RoutesCheapOffer_ToAte50()
    {
        var decision = WhatsAppNicheClassifier.Classify(new WhatsAppNicheRouteOfferInput(
            "Kit organizador multiuso",
            "https://example.com/oferta",
            "Shopee",
            null,
            "R$ 39,90",
            null,
            null));

        Assert.False(decision.RequiresReview);
        Assert.Equal(WhatsAppNicheDefinitions.Ate50, decision.Slug);
    }

    [Fact]
    public void Classify_RoutesTechTerms_ToTech()
    {
        var decision = WhatsAppNicheClassifier.Classify(new WhatsAppNicheRouteOfferInput(
            "Fone bluetooth com cancelamento de ruido",
            "https://example.com/fone",
            "Amazon",
            null,
            "R$ 129,90",
            null,
            null));

        Assert.False(decision.RequiresReview);
        Assert.Equal(WhatsAppNicheDefinitions.Tech, decision.Slug);
    }

    [Theory]
    [InlineData("Camera DJI Osmo Pocket 3 Creator Kit")]
    [InlineData("GoPro Hero 13")]
    public void Classify_RoutesCameraTerms_ToTech(string title)
    {
        var decision = WhatsAppNicheClassifier.Classify(new WhatsAppNicheRouteOfferInput(
            title,
            "https://example.com/camera",
            "Mercado Livre",
            null,
            "R$ 1.999,90",
            null,
            null));

        Assert.False(decision.RequiresReview);
        Assert.Equal(WhatsAppNicheDefinitions.Tech, decision.Slug);
    }

    [Theory]
    [InlineData("Tinta Extra Piso Eucatex 18L")]
    [InlineData("Bolsa de ferramentas reforcada 16 bolsos")]
    public void Classify_RoutesHomeMaintenanceTerms_ToCasa(string title)
    {
        var decision = WhatsAppNicheClassifier.Classify(new WhatsAppNicheRouteOfferInput(
            title,
            "https://example.com/casa",
            "Loja",
            null,
            "R$ 129,90",
            null,
            null));

        Assert.False(decision.RequiresReview);
        Assert.Equal(WhatsAppNicheDefinitions.Casa, decision.Slug);
    }

    [Fact]
    public void Classify_AmbiguousOffer_RequiresReview()
    {
        var decision = WhatsAppNicheClassifier.Classify(new WhatsAppNicheRouteOfferInput(
            "Oferta especial do dia",
            "https://example.com/oferta",
            "Loja",
            null,
            null,
            null,
            null));

        Assert.True(decision.RequiresReview);
        Assert.Equal(WhatsAppNicheDefinitions.Geral, decision.Slug);
    }

    [Fact]
    public void InvitePolicy_AcceptsOnlyConfiguredOrOfficialLinks()
    {
        var approved = new[] { "https://chat.whatsapp.com/GrupoCasa123" };

        Assert.True(WhatsAppInviteLinkNormalizer.IsApprovedInviteUrl(
            WhatsAppInviteLinkNormalizer.OfficialInviteUrl,
            approved));
        Assert.True(WhatsAppInviteLinkNormalizer.IsApprovedInviteUrl(
            "https://chat.whatsapp.com/GrupoCasa123/",
            approved));
        Assert.False(WhatsAppInviteLinkNormalizer.IsApprovedInviteUrl(
            "https://chat.whatsapp.com/OutroGrupo999",
            approved));
    }
}
