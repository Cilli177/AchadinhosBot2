using System.Collections.Concurrent;
using AchadinhosBot.Next.Application.Abstractions;

namespace AchadinhosBot.Next.Application.Services;

public sealed class DefaultOutboundRateLimitPolicy : IOutboundRateLimitPolicy
{
    private readonly ConcurrentDictionary<string, DateTimeOffset> _blockedUntil = new(StringComparer.OrdinalIgnoreCase);

    public bool TryGetDelay(string channel, string destination, out TimeSpan delay)
    {
        var key = BuildKey(channel, destination);
        if (_blockedUntil.TryGetValue(key, out var until))
        {
            var now = DateTimeOffset.UtcNow;
            if (until > now)
            {
                delay = until - now;
                return true;
            }

            _blockedUntil.TryRemove(key, out _);
        }

        delay = TimeSpan.Zero;
        return false;
    }

    public void RecordSuccess(string channel, string destination)
        => _blockedUntil.TryRemove(BuildKey(channel, destination), out _);

    public void RecordFailure(string channel, string destination, bool isRateLimit)
    {
        if (!isRateLimit)
        {
            return;
        }

        _blockedUntil[BuildKey(channel, destination)] = DateTimeOffset.UtcNow.AddSeconds(45);
    }

    private static string BuildKey(string channel, string destination)
        => $"{channel.Trim().ToLowerInvariant()}:{destination.Trim().ToLowerInvariant()}";
}
