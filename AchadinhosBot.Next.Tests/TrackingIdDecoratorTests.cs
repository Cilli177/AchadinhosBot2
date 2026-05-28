using AchadinhosBot.Next.Application.Services;

namespace AchadinhosBot.Next.Tests;

public sealed class TrackingIdDecoratorTests
{
    [Theory]
    [InlineData("whatsapp_grupo_oficial", null, "AM-W000001")]
    [InlineData(null, "niche_live_moda", "AM-M000001")]
    [InlineData(null, "niche_live_casa", "AM-C000001")]
    [InlineData(null, "niche_live_beleza", "AM-B000001")]
    [InlineData(null, "niche_live_fitness_health", "AM-F000001")]
    [InlineData(null, "niche_live_tech", "AM-T000001")]
    [InlineData(null, "niche_live_ate_50", "AM-A000001")]
    public void Decorate_EmbedsSourceMarkerInTrackingId(string? source, string? campaign, string expected)
    {
        var decorated = TrackingIdDecorator.Decorate("AM-000001", campaign, source);

        Assert.Equal(expected, decorated);
    }

    [Fact]
    public void Resolve_ReturnsCanonicalLookupIdFromDecoratedId()
    {
        var resolved = TrackingIdDecorator.Resolve("AM-M000001");

        Assert.True(resolved.Decorated);
        Assert.Equal("AM-000001", resolved.LookupId);
        Assert.Equal("niche_live_moda", resolved.Campaign);
    }
}
