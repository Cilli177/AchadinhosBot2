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
}
