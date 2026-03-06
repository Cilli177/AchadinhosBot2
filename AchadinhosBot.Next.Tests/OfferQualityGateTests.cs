using AchadinhosBot.Next.Application.Services;

namespace AchadinhosBot.Next.Tests;

public sealed class OfferQualityGateTests
{
    [Fact]
    public void ValidateForAutoForward_BlocksEmptyText()
    {
        var result = OfferQualityGate.ValidateForAutoForward("", hasImageCandidate: false);

        Assert.False(result.Allowed);
        Assert.Equal("empty_text", result.Reason);
    }

    [Fact]
    public void ValidateForAutoForward_BlocksWhenNoUrls()
    {
        var result = OfferQualityGate.ValidateForAutoForward("Produto top com desconto hoje", hasImageCandidate: true);

        Assert.False(result.Allowed);
        Assert.Equal("no_urls", result.Reason);
    }

    [Fact]
    public void ValidateForAutoForward_BlocksInvalidUrlFormat()
    {
        var result = OfferQualityGate.ValidateForAutoForward("Oferta valida https:///produto", hasImageCandidate: true);

        Assert.False(result.Allowed);
        Assert.Equal("invalid_url_format", result.Reason);
    }

    [Fact]
    public void ValidateForAutoForward_BlocksInsufficientContext()
    {
        var result = OfferQualityGate.ValidateForAutoForward("abc https://example.com/produto", hasImageCandidate: true);

        Assert.False(result.Allowed);
        Assert.Equal("insufficient_context", result.Reason);
    }

    [Fact]
    public void ValidateForAutoForward_BlocksMercadoLivreWithoutImage()
    {
        var result = OfferQualityGate.ValidateForAutoForward(
            "Oferta imperdivel meli.la/xyz https://meli.la/abc123",
            hasImageCandidate: false);

        Assert.False(result.Allowed);
        Assert.Equal("mercadolivre_without_image", result.Reason);
    }

    [Fact]
    public void ValidateForAutoForward_AllowsMercadoLivreWithImage()
    {
        var result = OfferQualityGate.ValidateForAutoForward(
            "Oferta imperdivel Mercado Livre https://meli.la/abc123",
            hasImageCandidate: true);

        Assert.True(result.Allowed);
        Assert.Equal("ok", result.Reason);
    }

    [Fact]
    public void ValidateForAutoForward_AllowsNonMercadoLivreWithoutImage()
    {
        var result = OfferQualityGate.ValidateForAutoForward(
            "Oferta Amazon headset gamer com preco baixo https://amzn.to/abc123",
            hasImageCandidate: false);

        Assert.True(result.Allowed);
        Assert.Equal("ok", result.Reason);
    }
}
