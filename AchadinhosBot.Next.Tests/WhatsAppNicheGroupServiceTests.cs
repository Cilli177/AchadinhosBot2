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
            null,
            null));

        Assert.False(decision.RequiresReview);
        Assert.Equal(WhatsAppNicheDefinitions.Ate50, decision.Slug);
    }

    [Fact]
    public void Classify_ExplicitNicheStillWinsOverCheapPrice()
    {
        var decision = WhatsAppNicheClassifier.Classify(new WhatsAppNicheRouteOfferInput(
            "Kit organizador multiuso",
            "https://example.com/oferta",
            "Shopee",
            WhatsAppNicheDefinitions.Casa,
            "R$ 39,90",
            null,
            null,
            null));

        Assert.False(decision.RequiresReview);
        Assert.Equal(WhatsAppNicheDefinitions.Casa, decision.Slug);
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
            null,
            null));

        Assert.False(decision.RequiresReview);
        Assert.Equal(WhatsAppNicheDefinitions.Tech, decision.Slug);
    }

    [Theory]
    [InlineData("Smart TV 55 polegadas QLED 4K")]
    [InlineData("Projetor HY300 para sala e quarto")]
    public void ResolveHybridTargetSlugs_RoutesTvAndProjector_ToTechAndCasa(string title)
    {
        var slugs = WhatsAppNicheClassifier.ResolveHybridTargetSlugs(new WhatsAppNicheRouteOfferInput(
            title,
            "https://example.com/tv",
            "Amazon",
            null,
            "R$ 1.799,90",
            null,
            null,
            null));

        Assert.Equal(new[] { WhatsAppNicheDefinitions.Tech, WhatsAppNicheDefinitions.Casa }, slugs);
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
            null,
            null));

        Assert.False(decision.RequiresReview);
        Assert.Equal(WhatsAppNicheDefinitions.Casa, decision.Slug);
    }

    [Theory]
    [InlineData("Kit shampoo e condicionador com vitamina para cabelo")]
    [InlineData("Mascara capilar hidratante e leave-in")]
    public void Classify_RoutesHairCareTerms_ToBeleza(string title)
    {
        var decision = WhatsAppNicheClassifier.Classify(new WhatsAppNicheRouteOfferInput(
            title,
            "https://example.com/beleza",
            "Loja",
            null,
            "R$ 79,90",
            null,
            null,
            null));

        Assert.False(decision.RequiresReview);
        Assert.Equal(WhatsAppNicheDefinitions.Beleza, decision.Slug);
    }

    [Fact]
    public void Classify_HairCareTermsOverrideMistakenFitnessCategory_ToBeleza()
    {
        var decision = WhatsAppNicheClassifier.Classify(new WhatsAppNicheRouteOfferInput(
            "Shampoo e condicionador com vitamina",
            "https://example.com/beleza",
            "Loja",
            WhatsAppNicheDefinitions.FitnessHealth,
            "R$ 79,90",
            null,
            null,
            null));

        Assert.False(decision.RequiresReview);
        Assert.Equal(WhatsAppNicheDefinitions.Beleza, decision.Slug);
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
