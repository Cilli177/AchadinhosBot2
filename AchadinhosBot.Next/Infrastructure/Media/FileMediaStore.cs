using System.Collections.Concurrent;
using System.Text.Json;

namespace AchadinhosBot.Next.Infrastructure.Media;

public sealed class FileMediaStore : IMediaStore
{
    private const int CleanupInterval = 50;
    private readonly string _directory;
    private readonly ConcurrentDictionary<string, MediaItem> _cache = new();
    private readonly object _sync = new();
    private int _writeCount;

    public FileMediaStore(string? rootDirectory = null)
    {
        _directory = string.IsNullOrWhiteSpace(rootDirectory)
            ? Path.Combine(AppContext.BaseDirectory, "data", "media-store")
            : rootDirectory;
        Directory.CreateDirectory(_directory);
    }

    public string Add(byte[] bytes, string mimeType, TimeSpan? ttl = null)
    {
        ArgumentNullException.ThrowIfNull(bytes);

        var id = Guid.NewGuid().ToString("N");
        var expires = DateTimeOffset.UtcNow.Add(ttl ?? TimeSpan.FromHours(2));
        var item = new MediaItem(bytes, string.IsNullOrWhiteSpace(mimeType) ? "application/octet-stream" : mimeType, expires);
        var dataPath = Path.Combine(_directory, $"{id}.bin");
        var metaPath = Path.Combine(_directory, $"{id}.meta.json");

        lock (_sync)
        {
            File.WriteAllBytes(dataPath, bytes);
            File.WriteAllText(metaPath, JsonSerializer.Serialize(new MediaItemMeta(item.MimeType, item.ExpiresAt)));
            _cache[id] = item;
            _writeCount++;

            if (_writeCount % CleanupInterval == 0)
            {
                CleanupExpiredFiles();
            }
        }

        return id;
    }

    public bool TryGet(string id, out MediaItem item)
    {
        if (string.IsNullOrWhiteSpace(id))
        {
            item = new MediaItem(Array.Empty<byte>(), "application/octet-stream", DateTimeOffset.MinValue);
            return false;
        }

        if (_cache.TryGetValue(id, out var cached))
        {
            if (cached.ExpiresAt > DateTimeOffset.UtcNow)
            {
                item = cached;
                return true;
            }

            RemoveMedia(id);
        }

        var dataPath = Path.Combine(_directory, $"{id}.bin");
        var metaPath = Path.Combine(_directory, $"{id}.meta.json");
        if (!File.Exists(dataPath) || !File.Exists(metaPath))
        {
            item = new MediaItem(Array.Empty<byte>(), "application/octet-stream", DateTimeOffset.MinValue);
            return false;
        }

        try
        {
            var metaJson = File.ReadAllText(metaPath);
            var meta = JsonSerializer.Deserialize<MediaItemMeta>(metaJson);
            if (meta is null || meta.ExpiresAt <= DateTimeOffset.UtcNow)
            {
                RemoveMedia(id);
                item = new MediaItem(Array.Empty<byte>(), "application/octet-stream", DateTimeOffset.MinValue);
                return false;
            }

            var bytes = File.ReadAllBytes(dataPath);
            item = new MediaItem(bytes, meta.MimeType, meta.ExpiresAt);
            _cache[id] = item;
            return true;
        }
        catch
        {
            item = new MediaItem(Array.Empty<byte>(), "application/octet-stream", DateTimeOffset.MinValue);
            return false;
        }
    }

    private void CleanupExpiredFiles()
    {
        var now = DateTimeOffset.UtcNow;
        foreach (var metaPath in Directory.EnumerateFiles(_directory, "*.meta.json"))
        {
            try
            {
                var id = Path.GetFileName(metaPath).Replace(".meta.json", string.Empty, StringComparison.OrdinalIgnoreCase);
                var metaJson = File.ReadAllText(metaPath);
                var meta = JsonSerializer.Deserialize<MediaItemMeta>(metaJson);
                if (meta is null || meta.ExpiresAt <= now)
                {
                    RemoveMedia(id);
                }
            }
            catch
            {
                // Ignore malformed entries during cleanup.
            }
        }
    }

    private void RemoveMedia(string id)
    {
        _cache.TryRemove(id, out _);
        var dataPath = Path.Combine(_directory, $"{id}.bin");
        var metaPath = Path.Combine(_directory, $"{id}.meta.json");
        if (File.Exists(dataPath))
        {
            File.Delete(dataPath);
        }

        if (File.Exists(metaPath))
        {
            File.Delete(metaPath);
        }
    }

    private sealed record MediaItemMeta(string MimeType, DateTimeOffset ExpiresAt);
}
