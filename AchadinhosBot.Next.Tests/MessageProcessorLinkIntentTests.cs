using System.Reflection;
using AchadinhosBot.Next.Application.Services;

namespace AchadinhosBot.Next.Tests;

public sealed class MessageProcessorLinkIntentTests
{
    [Theory]
    [InlineData("https://reidasofertas.ia.br/bio")]
    [InlineData("https://bio.reidasofertas.ia.br")]
    [InlineData("https://reidasofertas.ia.br/catalogo")]
    [InlineData("https://reidasofertas.ia.br/dashboard")]
    [InlineData("https://reidasofertas.ia.br/api/admin/ops/status")]
    [InlineData("https://reidasofertas.ia.br/r/AM-000001")]
    public void ShouldAttemptAffiliateConversion_ReturnsFalse_ForOwnedOperationalLinks(string url)
    {
        var result = InvokeShouldAttemptAffiliateConversion(url);

        Assert.False(result);
    }

    [Theory]
    [InlineData("https://amzn.to/4squJ9F")]
    [InlineData("https://www.amazon.com.br/dp/B08YKC39Y7")]
    [InlineData("https://meli.la/2J9DirG")]
    [InlineData("https://www.mercadolivre.com.br/p/MLB19761624")]
    [InlineData("https://s.shopee.com.br/AUpvSsCTgY")]
    [InlineData("https://tinyurl.com/34cak37t")]
    [InlineData("https://compre.link/w52/l8DsaK")]
    public void ShouldAttemptAffiliateConversion_ReturnsTrue_ForAffiliateCandidatesAndShorteners(string url)
    {
        var result = InvokeShouldAttemptAffiliateConversion(url);

        Assert.True(result);
    }

    [Theory]
    [InlineData("http://localhost/oferta")]
    [InlineData("http://127.0.0.1/oferta")]
    [InlineData("http://192.168.0.20/oferta")]
    [InlineData("ftp://s.shopee.com.br/AUpvSsCTgY")]
    public void IsBlockedUrl_ReturnsTrue_ForUnsafeSchemesAndPrivateHosts(string url)
    {
        var method = typeof(MessageProcessor).GetMethod(
            "IsBlockedUrl",
            BindingFlags.Static | BindingFlags.NonPublic);

        Assert.NotNull(method);
        var raw = method!.Invoke(null, new object[] { url });
        Assert.NotNull(raw);
        Assert.True((bool)raw!);
    }

    [Fact]
    public void OfferUrlExtractor_ExtractsCandidateWithPunctuationAndPreservesIndexes()
    {
        var extractor = new OfferUrlExtractor();
        var input = "Oferta (https://s.shopee.com.br/AUpvSsCTgY). Aproveita!";

        var candidate = Assert.Single(extractor.Extract(input));

        Assert.Equal("https://s.shopee.com.br/AUpvSsCTgY", candidate.CleanedUrl);
        Assert.Equal(string.Empty, candidate.Prefix);
        Assert.Equal(").", candidate.Suffix);
        Assert.True(candidate.ShouldConvert);
        Assert.False(candidate.IsBlocked);
        Assert.Equal(input.IndexOf("https://", StringComparison.Ordinal), candidate.Index);
    }

    [Theory]
    [InlineData("http://localhost/oferta")]
    [InlineData("http://10.0.0.3/oferta")]
    [InlineData("https://magalu.com/oferta")]
    public void OfferUrlExtractor_BlocksUnsafeOrUnsupportedHosts(string url)
    {
        var extractor = new OfferUrlExtractor();

        var candidate = Assert.Single(extractor.Extract($"Oferta {url}"));

        Assert.True(candidate.IsBlocked);
        Assert.False(candidate.ShouldConvert);
    }

    private static bool InvokeShouldAttemptAffiliateConversion(string url)
    {
        var method = typeof(MessageProcessor).GetMethod(
            "ShouldAttemptAffiliateConversion",
            BindingFlags.Static | BindingFlags.NonPublic);

        Assert.NotNull(method);
        var raw = method!.Invoke(null, new object[] { url });
        Assert.NotNull(raw);
        return (bool)raw!;
    }
}
