using System.Text.Json;
using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Domain.Logs;

namespace AchadinhosBot.Next.Infrastructure.Storage;

public sealed class LinkTrackingStore : ILinkTrackingStore
{
    private static readonly HashSet<string> PreferredPrefixes = new(StringComparer.OrdinalIgnoreCase)
    {
        "AM",
        "SP",
        "ML",
        "SHE",
        "MGL",
        "AME",
        "ALI",
        "LK"
    };

    private readonly string _path;
    private readonly string _versionsDir;
    private readonly ILogger<LinkTrackingStore> _logger;
    private readonly SemaphoreSlim _mutex = new(1, 1);
    private System.Collections.Concurrent.ConcurrentDictionary<string, LinkTrackingEntry>? _cache;
    private DateTimeOffset _lastWriteTime = DateTimeOffset.MinValue;

    [ActivatorUtilitiesConstructor]
    public LinkTrackingStore(
        ILogger<LinkTrackingStore> logger,
        IConfiguration configuration,
        IWebHostEnvironment environment)
        : this(logger, ResolvePath(configuration, environment))
    {
    }

    public LinkTrackingStore(ILogger<LinkTrackingStore> logger, string? path = null)
    {
        _logger = logger;
        _path = string.IsNullOrWhiteSpace(path)
            ? Path.Combine(AppContext.BaseDirectory, "data", "link-tracking.json")
            : path;
        _versionsDir = Path.Combine(Path.GetDirectoryName(_path) ?? AppContext.BaseDirectory, "versions");
    }

    private static string ResolvePath(IConfiguration configuration, IWebHostEnvironment environment)
    {
        var configuredPath = configuration["LinkTracking:Path"];
        if (string.IsNullOrWhiteSpace(configuredPath))
        {
            configuredPath = configuration["LINK_TRACKING_PATH"];
        }

        if (!string.IsNullOrWhiteSpace(configuredPath))
        {
            return Path.IsPathRooted(configuredPath)
                ? configuredPath
                : Path.Combine(FindPersistentDataRoot(environment.ContentRootPath), configuredPath);
        }

        return Path.Combine(FindPersistentDataRoot(environment.ContentRootPath), "link-tracking.json");
    }

    private static string FindPersistentDataRoot(string contentRootPath)
    {
        foreach (var candidate in new[]
        {
            @"D:\Achadinhos\data",
            @"C:\Achadinhos\data"
        })
        {
            if (Directory.Exists(candidate))
            {
                return candidate;
            }
        }

        foreach (var startPath in new[] { contentRootPath, AppContext.BaseDirectory })
        {
            var directory = new DirectoryInfo(startPath);
            while (directory is not null)
            {
                if (File.Exists(Path.Combine(directory.FullName, "AchadinhosBot2.sln")) ||
                    Directory.Exists(Path.Combine(directory.FullName, ".git")) ||
                    Directory.Exists(Path.Combine(directory.FullName, ".runtime")))
                {
                    return Path.Combine(directory.FullName, "data");
                }

                directory = directory.Parent;
            }
        }

        return Path.Combine(contentRootPath, "data");
    }

    public Task<LinkTrackingEntry> CreateAsync(string targetUrl, CancellationToken cancellationToken)
        => CreateAsync(new LinkTrackingCreateRequest { TargetUrl = targetUrl }, cancellationToken);

    public async Task<LinkTrackingEntry> CreateAsync(LinkTrackingCreateRequest request, CancellationToken cancellationToken)
    {
        await _mutex.WaitAsync(cancellationToken);
        try
        {
            var data = await EnsureLoadedCoreAsync(cancellationToken);
            var entry = BuildEntry(request, data);
            data[entry.Id] = entry;
            await WriteAsync(data, cancellationToken);
            return entry;
        }
        finally
        {
            _mutex.Release();
        }
    }

    public Task<LinkTrackingEntry> GetOrCreateAsync(string targetUrl, CancellationToken cancellationToken)
        => GetOrCreateAsync(new LinkTrackingCreateRequest { TargetUrl = targetUrl }, cancellationToken);

    public async Task<LinkTrackingEntry> GetOrCreateAsync(LinkTrackingCreateRequest request, CancellationToken cancellationToken)
    {
        var data = await EnsureLoadedAsync(cancellationToken);
        if (TryFindByTargetUrl(data, request.TargetUrl, out var existing))
        {
            if (ShouldReuseExistingTrackingId(existing.Id))
            {
                return existing;
            }
        }

        await _mutex.WaitAsync(cancellationToken);
        try
        {
            if (TryFindByTargetUrl(data, request.TargetUrl, out existing))
            {
                if (ShouldReuseExistingTrackingId(existing.Id))
                {
                    return existing;
                }
            }

            data = await EnsureLoadedCoreAsync(cancellationToken);
            var entry = BuildEntry(request, data);
            data[entry.Id] = entry;
            await WriteAsync(data, cancellationToken);
            return entry;
        }
        finally
        {
            _mutex.Release();
        }
    }

    public async Task<LinkTrackingEntry?> RegisterClickAsync(string trackingId, CancellationToken cancellationToken)
    {
        var cache = await EnsureLoadedAsync(cancellationToken);
        if (!TryGetActiveByTrackingId(cache, trackingId, out var entry))
        {
            _logger.LogWarning("RegisterClickAsync: link tracking ID {Id} not found.", trackingId);
            return null;
        }

        _logger.LogInformation("RegisterClickAsync: registering click for ID {Id} -> {TargetUrl}", entry.Id, entry.TargetUrl);

        await _mutex.WaitAsync(cancellationToken);
        try
        {
            entry.Clicks += 1;
            entry.LastClickAt = DateTimeOffset.UtcNow;
            cache[entry.Id] = entry;
            await WriteAsync(cache, cancellationToken);
            return entry;
        }
        finally
        {
            _mutex.Release();
        }
    }

    public async Task<LinkTrackingEntry?> GetLinkAsync(string id, CancellationToken cancellationToken)
    {
        var data = await EnsureLoadedAsync(cancellationToken);
        return TryGetActiveByTrackingId(data, id, out var entry) ? entry : null;
    }

    public async Task<IReadOnlyList<LinkTrackingEntry>> ListAsync(CancellationToken cancellationToken)
    {
        var data = await EnsureLoadedAsync(cancellationToken);
        return data.Values
            .OrderByDescending(x => x.CreatedAt)
            .ToList();
    }

    private async Task<System.Collections.Concurrent.ConcurrentDictionary<string, LinkTrackingEntry>> EnsureLoadedAsync(CancellationToken cancellationToken)
    {
        await _mutex.WaitAsync(cancellationToken);
        try
        {
            return await EnsureLoadedCoreAsync(cancellationToken);
        }
        finally
        {
            _mutex.Release();
        }
    }

    private async Task<System.Collections.Concurrent.ConcurrentDictionary<string, LinkTrackingEntry>> EnsureLoadedCoreAsync(CancellationToken cancellationToken)
    {
        if (_cache != null)
        {
            if (!File.Exists(_path))
            {
                return _cache;
            }

            var currentWriteTime = new DateTimeOffset(File.GetLastWriteTimeUtc(_path));
            if (currentWriteTime == _lastWriteTime)
            {
                return _cache;
            }

            _logger.LogInformation("Link tracking cache reload detected. Path={Path}", _path);
        }

        if (!File.Exists(_path))
        {
            var recovered = await TryRecoverFromLatestBackupAsync(cancellationToken);
            if (recovered is not null)
            {
                return recovered;
            }

            _cache = new System.Collections.Concurrent.ConcurrentDictionary<string, LinkTrackingEntry>(StringComparer.OrdinalIgnoreCase);
            _lastWriteTime = DateTimeOffset.MinValue;
            return _cache;
        }

        try
        {
            await using var stream = File.OpenRead(_path);
            var data = await JsonSerializer.DeserializeAsync<Dictionary<string, LinkTrackingEntry>>(stream, cancellationToken: cancellationToken);

            var dict = data ?? new Dictionary<string, LinkTrackingEntry>(StringComparer.OrdinalIgnoreCase);
            NormalizeLoadedEntries(dict);

            if (dict.Count == 0)
            {
                var recovered = await TryRecoverFromLatestBackupAsync(cancellationToken);
                if (recovered is not null)
                {
                    return recovered;
                }
            }

            _cache = new System.Collections.Concurrent.ConcurrentDictionary<string, LinkTrackingEntry>(dict, StringComparer.OrdinalIgnoreCase);
            _lastWriteTime = new DateTimeOffset(File.GetLastWriteTimeUtc(_path));

            return _cache;
        }
        catch
        {
            var recovered = await TryRecoverFromLatestBackupAsync(cancellationToken);
            if (recovered is not null)
            {
                return recovered;
            }

            _cache ??= new System.Collections.Concurrent.ConcurrentDictionary<string, LinkTrackingEntry>(StringComparer.OrdinalIgnoreCase);
            return _cache;
        }
    }

    private async Task<System.Collections.Concurrent.ConcurrentDictionary<string, LinkTrackingEntry>?> TryRecoverFromLatestBackupAsync(CancellationToken cancellationToken)
    {
        if (!Directory.Exists(_versionsDir))
        {
            return null;
        }

        var backupPath = new DirectoryInfo(_versionsDir)
            .EnumerateFiles("link-tracking.*.json.bak", SearchOption.TopDirectoryOnly)
            .OrderByDescending(x => x.LastWriteTimeUtc)
            .FirstOrDefault()?.FullName;

        if (string.IsNullOrWhiteSpace(backupPath) || !File.Exists(backupPath))
        {
            return null;
        }

        try
        {
            _logger.LogWarning("Recovering link tracking store from backup. BackupPath={BackupPath}", backupPath);

            await using var stream = File.OpenRead(backupPath);
            var data = await JsonSerializer.DeserializeAsync<Dictionary<string, LinkTrackingEntry>>(stream, cancellationToken: cancellationToken);

            var dict = data ?? new Dictionary<string, LinkTrackingEntry>(StringComparer.OrdinalIgnoreCase);
            NormalizeLoadedEntries(dict);
            _cache = new System.Collections.Concurrent.ConcurrentDictionary<string, LinkTrackingEntry>(dict, StringComparer.OrdinalIgnoreCase);
            await PersistRecoveredSnapshotAsync(_cache, cancellationToken);
            return _cache;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to recover link tracking store from backup. BackupPath={BackupPath}", backupPath);
            return null;
        }
    }

    private async Task PersistRecoveredSnapshotAsync(System.Collections.Concurrent.ConcurrentDictionary<string, LinkTrackingEntry> data, CancellationToken cancellationToken)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(_path)!);

        var tempPath = _path + ".recovered";
        await using (var stream = File.Create(tempPath))
        {
            await JsonSerializer.SerializeAsync(stream, data, new JsonSerializerOptions { WriteIndented = false }, cancellationToken);
        }

        File.Move(tempPath, _path, true);
        _lastWriteTime = new DateTimeOffset(File.GetLastWriteTimeUtc(_path));
    }

    private async Task WriteAsync(System.Collections.Concurrent.ConcurrentDictionary<string, LinkTrackingEntry> data, CancellationToken cancellationToken)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(_path)!);
        await BackupCurrentFileAsync(cancellationToken);

        var tempPath = _path + ".tmp";
        await using (var stream = File.Create(tempPath))
        {
            await JsonSerializer.SerializeAsync(stream, data, new JsonSerializerOptions { WriteIndented = false }, cancellationToken);
        }

        File.Move(tempPath, _path, true);
        _lastWriteTime = new DateTimeOffset(File.GetLastWriteTimeUtc(_path));
    }

    private async Task BackupCurrentFileAsync(CancellationToken cancellationToken)
    {
        if (!File.Exists(_path))
        {
            return;
        }

        var fileInfo = new FileInfo(_path);
        if (fileInfo.Length == 0)
        {
            return;
        }

        Directory.CreateDirectory(_versionsDir);
        var backupName = $"link-tracking.{DateTimeOffset.UtcNow:yyyyMMdd-HHmmss-fff}-{Guid.NewGuid():N}.json.bak";
        var backupPath = Path.Combine(_versionsDir, backupName);

        await using var source = File.Open(_path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
        await using var destination = File.Create(backupPath);
        await source.CopyToAsync(destination, cancellationToken);
    }

    private static LinkTrackingEntry BuildEntry(LinkTrackingCreateRequest request, System.Collections.Concurrent.ConcurrentDictionary<string, LinkTrackingEntry> data)
    {
        var normalized = request.TargetUrl?.Trim() ?? string.Empty;
        var prefix = ResolveStorePrefix(normalized);
        var next = GetNextSequence(data, prefix);
        var id = $"{prefix}-{next:000000}";
        var createdAt = DateTimeOffset.UtcNow;

        return new LinkTrackingEntry
        {
            Id = id,
            Slug = id,
            TargetUrl = normalized,
            Store = string.IsNullOrWhiteSpace(request.Store) ? string.Empty : request.Store.Trim(),
            OriginChannel = string.IsNullOrWhiteSpace(request.OriginChannel) ? "unknown" : request.OriginChannel.Trim(),
            OriginSurface = string.IsNullOrWhiteSpace(request.OriginSurface) ? "unknown" : request.OriginSurface.Trim(),
            Campaign = string.IsNullOrWhiteSpace(request.Campaign) ? null : request.Campaign.Trim(),
            OfferId = string.IsNullOrWhiteSpace(request.OfferId) ? null : request.OfferId.Trim(),
            DraftId = string.IsNullOrWhiteSpace(request.DraftId) ? null : request.DraftId.Trim(),
            MessageId = string.IsNullOrWhiteSpace(request.MessageId) ? null : request.MessageId.Trim(),
            Clicks = 0,
            CreatedAt = createdAt,
            ExpiresAtUtc = request.ExpiresAtUtc
        };
    }

    private static int GetNextSequence(System.Collections.Concurrent.ConcurrentDictionary<string, LinkTrackingEntry> data, string prefix)
    {
        var start = $"{prefix}-";
        var max = 0;

        foreach (var key in data.Keys)
        {
            if (!key.StartsWith(start, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            var suffix = key[start.Length..];
            if (int.TryParse(suffix, out var parsed) && parsed > max)
            {
                max = parsed;
            }
        }

        return max + 1;
    }

    private static string ResolveStorePrefix(string url)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
        {
            return "LK";
        }

        var host = uri.Host.ToLowerInvariant();

        if (host.Contains("amazon"))
        {
            return "AM";
        }

        if (host.Contains("shopee"))
        {
            return "SP";
        }

        if (host.Contains("mercadolivre") || host.Contains("meli.") || host.Equals("meli.la", StringComparison.OrdinalIgnoreCase))
        {
            return "ML";
        }

        if (host.Contains("shein"))
        {
            return "SHE";
        }

        if (host.Contains("magalu") || host.Contains("magazineluiza"))
        {
            return "MGL";
        }

        if (host.Contains("americanas"))
        {
            return "AME";
        }

        if (host.Contains("aliexpress") || host.Contains("ali"))
        {
            return "ALI";
        }

        return "LK";
    }

    private static bool TryFindByTargetUrl(
        System.Collections.Concurrent.ConcurrentDictionary<string, LinkTrackingEntry> data,
        string targetUrl,
        out LinkTrackingEntry existing)
    {
        var normalized = targetUrl?.Trim() ?? string.Empty;
        LinkTrackingEntry? fallback = null;

        foreach (var value in data.Values)
        {
            if (!string.Equals(value.TargetUrl, normalized, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            if (IsExpired(value))
            {
                continue;
            }

            if (IsPreferredTrackingId(value.Id))
            {
                existing = value;
                return true;
            }

            fallback ??= value;
        }

        if (fallback is not null)
        {
            existing = fallback;
            return true;
        }

        existing = new LinkTrackingEntry();
        return false;
    }

    private static bool TryGetActiveByTrackingId(
        System.Collections.Concurrent.ConcurrentDictionary<string, LinkTrackingEntry> data,
        string trackingId,
        out LinkTrackingEntry entry)
    {
        if (data.TryGetValue(trackingId, out var byKey) && !IsExpired(byKey))
        {
            entry = byKey;
            return true;
        }

        var bySlug = data.Values.FirstOrDefault(x =>
            !IsExpired(x) &&
            (string.Equals(x.Id, trackingId, StringComparison.OrdinalIgnoreCase) ||
             string.Equals(x.Slug, trackingId, StringComparison.OrdinalIgnoreCase)));

        if (bySlug is not null)
        {
            entry = bySlug;
            return true;
        }

        entry = new LinkTrackingEntry();
        return false;
    }

    private static void NormalizeLoadedEntries(Dictionary<string, LinkTrackingEntry> entries)
    {
        foreach (var kvp in entries.ToList())
        {
            var entry = kvp.Value;
            if (string.IsNullOrWhiteSpace(entry.Id))
            {
                entry.Id = kvp.Key;
            }

            if (string.IsNullOrWhiteSpace(entry.Slug))
            {
                entry.Slug = entry.Id;
            }

            if (entry.CreatedAt == default)
            {
                entry.CreatedAt = DateTimeOffset.UtcNow;
            }

            entries[kvp.Key] = entry;
        }
    }

    private static bool IsExpired(LinkTrackingEntry entry)
        => entry.ExpiresAtUtc.HasValue && entry.ExpiresAtUtc.Value <= DateTimeOffset.UtcNow;

    private static bool IsPreferredTrackingId(string? id)
    {
        if (!TryParseTrackingId(id, out var prefix))
        {
            return false;
        }

        return PreferredPrefixes.Contains(prefix);
    }

    private static bool ShouldReuseExistingTrackingId(string? id)
    {
        if (!IsPreferredTrackingId(id))
        {
            return false;
        }

        return !TryParseTrackingSequence(id, out var sequence) || sequence >= 200;
    }

    private static bool TryParseTrackingId(string? id, out string prefix)
    {
        prefix = string.Empty;
        if (string.IsNullOrWhiteSpace(id))
        {
            return false;
        }

        var trimmed = id.Trim();
        var dash = trimmed.IndexOf('-');
        if (dash <= 0 || dash >= trimmed.Length - 1)
        {
            return false;
        }

        var candidatePrefix = trimmed[..dash];
        var number = trimmed[(dash + 1)..];
        if (!candidatePrefix.All(char.IsLetter) ||
            candidatePrefix.Length is < 2 or > 4 ||
            !number.All(char.IsDigit))
        {
            return false;
        }

        prefix = candidatePrefix;
        return true;
    }

    private static bool TryParseTrackingSequence(string? id, out int sequence)
    {
        sequence = 0;
        if (!TryParseTrackingId(id, out _))
        {
            return false;
        }

        var trimmed = id!.Trim();
        var dash = trimmed.IndexOf('-');
        if (dash <= 0 || dash >= trimmed.Length - 1)
        {
            return false;
        }

        return int.TryParse(trimmed[(dash + 1)..], out sequence);
    }
}
