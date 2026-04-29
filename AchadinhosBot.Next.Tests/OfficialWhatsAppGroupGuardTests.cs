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
    public void Validate_AllowsTrackedOfferWithOfficialInviteAndBio()
    {
        var result = OfficialWhatsAppGroupGuard.Validate(
            isOfficialDestination: true,
            text: """
                  Oferta top https://reidasofertas.ia.br/r/AM-000001

                  💚CONVIDEM MEMBROS
                  LINK DOS GRUPOS: https://chat.whatsapp.com/FhkbgV9fnUjKnOM4KGDCPX

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
