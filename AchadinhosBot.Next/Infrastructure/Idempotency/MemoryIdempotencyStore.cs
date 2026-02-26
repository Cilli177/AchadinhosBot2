using AchadinhosBot.Next.Application.Abstractions;

namespace AchadinhosBot.Next.Infrastructure.Idempotency;

public sealed class MemoryIdempotencyStore : IIdempotencyStore
{
    private readonly Dictionary<string, DateTimeOffset> _keys = new();
    private readonly object _sync = new();

    public bool TryBegin(string key, TimeSpan ttl)
    {
        var now = DateTimeOffset.UtcNow;

        lock (_sync)
        {
            var expired = _keys.Where(k => k.Value <= now).Select(k => k.Key).ToList();
            foreach (var item in expired) _keys.Remove(item);

            if (_keys.ContainsKey(key)) return false;

            _keys[key] = now.Add(ttl);
            return true;
        }
    }

    public void RemoveByPrefix(string prefix)
    {
        if (string.IsNullOrWhiteSpace(prefix)) return;

        lock (_sync)
        {
            var matches = _keys.Keys
                .Where(k => k.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                .ToList();
            foreach (var key in matches)
            {
                _keys.Remove(key);
            }
        }
    }
}
