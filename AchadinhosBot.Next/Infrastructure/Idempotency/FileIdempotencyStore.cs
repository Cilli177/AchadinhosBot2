using System.Text.Json;
using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Configuration;
using Microsoft.Extensions.Options;

namespace AchadinhosBot.Next.Infrastructure.Idempotency;

public sealed class FileIdempotencyStore : IIdempotencyStore
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);
    private readonly Dictionary<string, DateTimeOffset> _keys;
    private readonly object _sync = new();
    private readonly string _path;
    private readonly ILogger<FileIdempotencyStore> _logger;

    public FileIdempotencyStore(IOptions<MessagingOptions> options, ILogger<FileIdempotencyStore> logger)
    {
        _logger = logger;
        var dataDirectory = options.Value.ResolveDataDirectory();
        Directory.CreateDirectory(dataDirectory);
        _path = Path.Combine(dataDirectory, "idempotency-store.json");
        _keys = LoadSnapshot();
    }

    public bool TryBegin(string key, TimeSpan ttl)
    {
        var now = DateTimeOffset.UtcNow;

        lock (_sync)
        {
            PruneExpired(now);
            if (_keys.ContainsKey(key))
            {
                return false;
            }

            _keys[key] = now.Add(ttl);
            PersistSnapshot();
            return true;
        }
    }

    public void RemoveByPrefix(string prefix)
    {
        if (string.IsNullOrWhiteSpace(prefix))
        {
            return;
        }

        lock (_sync)
        {
            var matches = _keys.Keys
                .Where(key => key.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                .ToList();

            if (matches.Count == 0)
            {
                return;
            }

            foreach (var key in matches)
            {
                _keys.Remove(key);
            }

            PersistSnapshot();
        }
    }

    private Dictionary<string, DateTimeOffset> LoadSnapshot()
    {
        try
        {
            if (!File.Exists(_path))
            {
                return new Dictionary<string, DateTimeOffset>(StringComparer.OrdinalIgnoreCase);
            }

            var json = File.ReadAllText(_path);
            var entries = JsonSerializer.Deserialize<List<IdempotencyEntry>>(json, JsonOptions) ?? new List<IdempotencyEntry>();
            return entries
                .Where(entry => !string.IsNullOrWhiteSpace(entry.Key))
                .Where(entry => entry.ExpiresAt > DateTimeOffset.UtcNow)
                .GroupBy(entry => entry.Key, StringComparer.OrdinalIgnoreCase)
                .ToDictionary(group => group.Key, group => group.Max(item => item.ExpiresAt), StringComparer.OrdinalIgnoreCase);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Falha ao carregar store persistente de idempotencia. Uma store vazia sera usada.");
            return new Dictionary<string, DateTimeOffset>(StringComparer.OrdinalIgnoreCase);
        }
    }

    private void PruneExpired(DateTimeOffset now)
    {
        var expired = _keys
            .Where(item => item.Value <= now)
            .Select(item => item.Key)
            .ToList();

        foreach (var key in expired)
        {
            _keys.Remove(key);
        }
    }

    private void PersistSnapshot()
    {
        try
        {
            var snapshot = _keys
                .Select(item => new IdempotencyEntry(item.Key, item.Value))
                .OrderBy(item => item.ExpiresAt)
                .ToList();

            var json = JsonSerializer.Serialize(snapshot, JsonOptions);
            var tempPath = $"{_path}.{Guid.NewGuid():N}.tmp";
            File.WriteAllText(tempPath, json);
            File.Move(tempPath, _path, true);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Falha ao persistir store de idempotencia em {Path}", _path);
        }
    }

    private sealed record IdempotencyEntry(string Key, DateTimeOffset ExpiresAt);
}
