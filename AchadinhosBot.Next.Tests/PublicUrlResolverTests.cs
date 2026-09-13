using AchadinhosBot.Next.Application.Services;

namespace AchadinhosBot.Next.Tests;

public sealed class PublicUrlResolverTests
{
    [Theory]
    [InlineData("https://reidasofertas.ia.br/path", "https://reidasofertas.ia.br")]
    [InlineData("https://www.reidasofertas.ia.br/anything", "https://reidasofertas.ia.br")]
    [InlineData("https://example.test/a", "https://example.test")]
    public void TryNormalize_NormalizesPublicAuthority(string input, string expected)
    {
        Assert.True(PublicUrlResolver.TryNormalize(input, out var normalized));
        Assert.Equal(expected, normalized);
    }

    [Theory]
    [InlineData("localhost")]
    [InlineData("host.docker.internal")]
    [InlineData("admin.internal")]
    [InlineData("preview.local")]
    public void IsInternalLikeHost_BlocksNonPublicHosts(string host)
        => Assert.True(PublicUrlResolver.IsInternalLikeHost(host));

    [Fact]
    public void BuildMediaUrl_PreservesNgrokCompatibilityFlag()
        => Assert.Equal("https://demo.ngrok-free.app/media/item.jpg?ngrok-skip-browser-warning=1", PublicUrlResolver.BuildMediaUrl("https://demo.ngrok-free.app/", "item"));
}
