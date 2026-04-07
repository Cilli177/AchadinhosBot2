using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Application.Services;
using AchadinhosBot.Next.Domain.Governance;

namespace AchadinhosBot.Next.Tests;

public sealed class TrafficCanaryResolverTests
{
    [Fact]
    public async Task ResolveAsync_ReturnsStable_WhenNoRuleMatches()
    {
        var resolver = new TrafficCanaryResolver(new StubRuleStore(Array.Empty<CanaryRule>()));
        var result = await resolver.ResolveAsync(new CanaryRoutingContext("whatsapp_outbound", "g1", "i1", "whatsapp"), CancellationToken.None);

        Assert.Equal("stable", result.Variant);
        Assert.Null(result.RuleId);
    }

    [Fact]
    public async Task ResolveAsync_RespectsCanaryPercent()
    {
        var rules = new[]
        {
            new CanaryRule("rule-1", true, "instagram_publish", null, null, "instagram", 100)
        };
        var resolver = new TrafficCanaryResolver(new StubRuleStore(rules));
        var result = await resolver.ResolveAsync(new CanaryRoutingContext("instagram_publish", null, null, "instagram"), CancellationToken.None);

        Assert.Equal("canary", result.Variant);
        Assert.Equal("rule-1", result.RuleId);
    }

    private sealed class StubRuleStore : ICanaryRuleStore
    {
        private readonly IReadOnlyList<CanaryRule> _rules;

        public StubRuleStore(IReadOnlyList<CanaryRule> rules)
        {
            _rules = rules;
        }

        public Task<IReadOnlyList<CanaryRule>> ListAsync(CancellationToken cancellationToken)
            => Task.FromResult(_rules);

        public Task SaveAsync(IReadOnlyList<CanaryRule> rules, CancellationToken cancellationToken)
            => Task.CompletedTask;
    }
}
