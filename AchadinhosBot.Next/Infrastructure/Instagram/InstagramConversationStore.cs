namespace AchadinhosBot.Next.Infrastructure.Instagram;

public sealed class InstagramConversationStore
{
    private readonly Dictionary<string, InstagramConversation> _pending = new(StringComparer.OrdinalIgnoreCase);
    private readonly TimeSpan _ttl = TimeSpan.FromMinutes(10);
    private readonly object _lock = new();

    public void SetPending(string key, string? context)
    {
        if (string.IsNullOrWhiteSpace(key)) return;
        lock (_lock)
        {
            _pending[key] = new InstagramConversation
            {
                Key = key,
                Context = context,
                CreatedAt = DateTimeOffset.UtcNow
            };
        }
    }

    public bool TryConsume(string key, out InstagramConversation conversation)
    {
        conversation = default!;
        if (string.IsNullOrWhiteSpace(key)) return false;
        lock (_lock)
        {
            CleanupLocked();
            if (_pending.TryGetValue(key, out var found))
            {
                _pending.Remove(key);
                conversation = found;
                return true;
            }
        }
        return false;
    }

    private void CleanupLocked()
    {
        var now = DateTimeOffset.UtcNow;
        var expired = _pending
            .Where(kv => now - kv.Value.CreatedAt > _ttl)
            .Select(kv => kv.Key)
            .ToList();
        foreach (var key in expired)
        {
            _pending.Remove(key);
        }
    }
}

public sealed class InstagramConversation
{
    public string Key { get; set; } = string.Empty;
    public string? Context { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
}
