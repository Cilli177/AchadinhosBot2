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
}
