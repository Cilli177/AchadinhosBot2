using AchadinhosBot.Next.Application.Services;

namespace AchadinhosBot.Next.Tests;

public sealed class OfficialWhatsAppGroupGuardTests
{
    [Fact]
    public void Validate_BlocksOfficialGroupWhenTrackedLinkIsMissing()
    {
        var result = OfficialWhatsAppGroupGuard.Validate(
            isOfficialDestination: true,
            text: "Oferta top https://www.amazon.com.br/dp/B0TESTE",
            hasImageCandidate: true,
            hasActualImage: true);

        Assert.False(result.Allowed);
        Assert.Equal("no_tracked_offer_link", result.Reason);
    }

    [Theory]
    [InlineData("https://www.mercadolivre.com.br/p/MLB12345678")]
    [InlineData("https://reidasofertas.ia.br/r/ML-014623")]
    [InlineData("https://meli.la/2wA3gUk")]
    public void Validate_BlocksOfficialGroupWhenMercadoLivreIsPaused(string url)
    {
        var result = OfficialWhatsAppGroupGuard.Validate(
            isOfficialDestination: true,
            text: $"Oferta ML {url}",
            hasImageCandidate: true,
            hasActualImage: true);

        Assert.False(result.Allowed);
        Assert.Equal("mercado_livre_paused", result.Reason);
    }

    [Theory]
    [InlineData("https://tinyurl.com/abc123")]
    [InlineData("https://shope.ee/abc123")]
    public void Validate_BlocksOfficialGroupWhenOnlyAffiliateShortenerExists(string url)
    {
        var result = OfficialWhatsAppGroupGuard.Validate(
            isOfficialDestination: true,
            text: $"Oferta top {url}",
            hasImageCandidate: true,
            hasActualImage: true);

        Assert.False(result.Allowed);
        Assert.Equal("no_tracked_offer_link", result.Reason);
    }

    [Fact]
    public void Validate_BlocksOfficialGroupWhenImageIsMissing()
    {
        var result = OfficialWhatsAppGroupGuard.Validate(
            isOfficialDestination: true,
            text: "Oferta top https://reidasofertas.ia.br/r/AM-000001",
            hasImageCandidate: false,
            hasActualImage: false);

        Assert.False(result.Allowed);
        Assert.Equal("image_required", result.Reason);
    }

    [Fact]
    public void Validate_BlocksOfficialGroupWhenGenericLkTrackingIsPresent()
    {
        var result = OfficialWhatsAppGroupGuard.Validate(
            isOfficialDestination: true,
            text: "Oferta top https://reidasofertas.ia.br/r/LK-001894",
            hasImageCandidate: true,
            hasActualImage: true);

        Assert.False(result.Allowed);
        Assert.Equal("generic_tracking_link", result.Reason);
    }

    [Fact]
    public void Validate_AllowsTrackedOfferWithOfficialInviteAndBio()
    {
        var result = OfficialWhatsAppGroupGuard.Validate(
            isOfficialDestination: true,
            text: """
                  Oferta top https://reidasofertas.ia.br/r/AM-000001

                  💚CONVIDEM MEMBROS
                  LINK DOS GRUPOS: https://chat.whatsapp.com/GosnHVUa2lE0nYGhO6an4x

                  https://reidasofertas.ia.br/bio
                  """,
            hasImageCandidate: true,
            hasActualImage: true);

        Assert.True(result.Allowed);
        Assert.Equal("ok", result.Reason);
    }

    [Fact]
    public void Validate_BlocksOfficialGroupWhenOnlyImageCandidateExists()
    {
        var result = OfficialWhatsAppGroupGuard.Validate(
            isOfficialDestination: true,
            text: "Oferta top https://reidasofertas.ia.br/r/AM-000001",
            hasImageCandidate: true,
            hasActualImage: false);

        Assert.False(result.Allowed);
        Assert.Equal("image_required", result.Reason);
    }
}
