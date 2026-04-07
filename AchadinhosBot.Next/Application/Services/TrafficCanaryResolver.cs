using System.Security.Cryptography;
using System.Text;
using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Domain.Governance;

namespace AchadinhosBot.Next.Application.Services;

public sealed class TrafficCanaryResolver : ITrafficCanaryResolver
{
    private readonly ICanaryRuleStore _ruleStore;

    public TrafficCanaryResolver(ICanaryRuleStore ruleStore)
    {
        _ruleStore = ruleStore;
    }

    public async Task<CanaryResolution> ResolveAsync(CanaryRoutingContext context, CancellationToken cancellationToken)
    {
        var rules = await _ruleStore.ListAsync(cancellationToken);
        var match = rules.FirstOrDefault(rule => Matches(rule, context));
        if (match is null || !match.Enabled || match.CanaryPercent <= 0)
        {
            return new CanaryResolution("stable", match?.RuleId, match?.CanaryPercent);
        }

        var key = BuildKey(context);
        var bucket = GetBucket(key);
        return bucket < Math.Clamp(match.CanaryPercent, 0, 100)
            ? new CanaryResolution("canary", match.RuleId, match.CanaryPercent)
            : new CanaryResolution("stable", match.RuleId, match.CanaryPercent);
    }

    private static bool Matches(CanaryRule rule, CanaryRoutingContext context)
    {
        if (!string.Equals(rule.ActionType, context.ActionType, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        if (!string.IsNullOrWhiteSpace(rule.GroupId) &&
            !string.Equals(rule.GroupId, context.GroupId, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        if (!string.IsNullOrWhiteSpace(rule.InstanceName) &&
            !string.Equals(rule.InstanceName, context.InstanceName, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        if (!string.IsNullOrWhiteSpace(rule.Channel) &&
            !string.Equals(rule.Channel, context.Channel, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        return true;
    }

    private static string BuildKey(CanaryRoutingContext context)
        => $"{context.ActionType}|{context.GroupId}|{context.InstanceName}|{context.Channel}";

    private static int GetBucket(string key)
    {
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(key));
        var value = BitConverter.ToUInt32(hash, 0);
        return (int)(value % 100);
    }
}
