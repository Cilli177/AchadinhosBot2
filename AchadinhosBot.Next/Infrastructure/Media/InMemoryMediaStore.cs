using System.Collections.Concurrent;

namespace AchadinhosBot.Next.Infrastructure.Media;

public interface IMediaStore
{
    string Add(byte[] bytes, string mimeType, TimeSpan? ttl = null);
    bool TryGet(string id, out MediaItem item);
}

public sealed record MediaItem(byte[] Bytes, string MimeType, DateTimeOffset ExpiresAt);

public sealed class InMemoryMediaStore : IMediaStore
{
    private readonly ConcurrentDictionary<string, MediaItem> _items = new();

    public string Add(byte[] bytes, string mimeType, TimeSpan? ttl = null)
    {
        var id = Guid.NewGuid().ToString("N");
        var expires = DateTimeOffset.UtcNow.Add(ttl ?? TimeSpan.FromMinutes(10));
        _items[id] = new MediaItem(bytes, mimeType, expires);
        Cleanup();
        return id;
    }

    public bool TryGet(string id, out MediaItem item)
    {
        if (_items.TryGetValue(id, out var existingItem))
        {
            if (existingItem.ExpiresAt > DateTimeOffset.UtcNow)
            {
                item = existingItem;
                return true;
            }

            _items.TryRemove(id, out _);
        }

        item = new MediaItem(Array.Empty<byte>(), "application/octet-stream", DateTimeOffset.MinValue);
        return false;
    }

    private void Cleanup()
    {
        var now = DateTimeOffset.UtcNow;
        foreach (var kvp in _items)
        {
            if (kvp.Value.ExpiresAt <= now)
            {
                _items.TryRemove(kvp.Key, out _);
            }
        }
    }
}
