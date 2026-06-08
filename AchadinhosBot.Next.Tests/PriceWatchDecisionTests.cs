using AchadinhosBot.Next.Application.Services;

namespace AchadinhosBot.Next.Tests;

public sealed class PriceWatchDecisionTests
{
    [Fact]
    public void FirstRunWithoutTargetSeedsBaselineOnly()
    {
        var result = PriceWatchDecision.Decide(299m, null, null, 5m, null, DateTimeOffset.UtcNow);

        Assert.False(result.ShouldSend);
        Assert.Equal("baseline_registrado", result.Reason);
    }

    [Fact]
    public void LowerThanLastSentSends()
    {
        var result = PriceWatchDecision.Decide(249m, 299m, null, 5m, DateTimeOffset.UtcNow.AddHours(-3), DateTimeOffset.UtcNow);

        Assert.True(result.ShouldSend);
        Assert.Equal("queda_real", result.Reason);
    }

    [Fact]
    public void DesiredPriceReachedSends()
    {
        var result = PriceWatchDecision.Decide(300m, null, 300m, 5m, null, DateTimeOffset.UtcNow);

        Assert.True(result.ShouldSend);
        Assert.Equal("preco_alvo", result.Reason);
    }

    [Fact]
    public void NearDesiredPriceSendsWithinConfiguredPercent()
    {
        var result = PriceWatchDecision.Decide(315m, null, 300m, 5m, null, DateTimeOffset.UtcNow);

        Assert.True(result.ShouldSend);
        Assert.Equal("perto_do_alvo", result.Reason);
    }

    [Fact]
    public void RecentSendDoesNotRepeat()
    {
        var now = DateTimeOffset.UtcNow;
        var result = PriceWatchDecision.Decide(250m, 300m, null, 5m, now.AddMinutes(-20), now);

        Assert.False(result.ShouldSend);
        Assert.Equal("envio_recente", result.Reason);
    }
}
