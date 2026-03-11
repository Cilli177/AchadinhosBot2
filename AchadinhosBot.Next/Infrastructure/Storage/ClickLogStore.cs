using System.Text.Json;
using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Domain.Logs;

namespace AchadinhosBot.Next.Infrastructure.Storage;

public sealed class ClickLogStore : IClickLogStore
{
    private readonly string _basePath;
    private readonly System.Collections.Concurrent.ConcurrentDictionary<string, SemaphoreSlim> _mutexes = new();

    public ClickLogStore()
    {
        _basePath = Path.Combine(AppContext.BaseDirectory, "data");
    }

    private string GetPath(string? category)
    {
        var suffix = string.IsNullOrWhiteSpace(category) ? "" : "-" + category.Trim().ToLowerInvariant();
        return Path.Combine(_basePath, $"click-logs{suffix}.jsonl");
    }

    private SemaphoreSlim GetMutex(string path) => _mutexes.GetOrAdd(path, _ => new SemaphoreSlim(1, 1));

    public async Task AppendAsync(ClickLogEntry entry, string? category, CancellationToken cancellationToken)
    {
        var path = GetPath(category);
        var mutex = GetMutex(path);

        await mutex.WaitAsync(cancellationToken);
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            await using var stream = new FileStream(path, FileMode.Append, FileAccess.Write, FileShare.Read);
            await using var writer = new StreamWriter(stream);
            var json = JsonSerializer.Serialize(entry);
            await writer.WriteLineAsync(json);
            await writer.FlushAsync();
            await JsonlLogRetention.TrimIfNeededAsync(path, 15000, 8 * 1024 * 1024, cancellationToken);
        }
        finally
        {
            mutex.Release();
        }
    }

    public async Task<IReadOnlyList<ClickLogEntry>> QueryAsync(string? category, string? search, int limit, CancellationToken cancellationToken)
    {
        var entries = new List<ClickLogEntry>();
        var path = GetPath(category);

        if (!File.Exists(path))
        {
            return entries;
        }

        var mutex = GetMutex(path);
        await mutex.WaitAsync(cancellationToken);
        try
        {
            await using var stream = File.OpenRead(path);
            using var reader = new StreamReader(stream);
            while (!reader.EndOfStream)
            {
                var line = await reader.ReadLineAsync();
                if (string.IsNullOrWhiteSpace(line)) continue;
                try
                {
                    var entry = JsonSerializer.Deserialize<ClickLogEntry>(line);
                    if (entry is null) continue;

                    if (!string.IsNullOrWhiteSpace(search))
                    {
                        var q = search.Trim();
                        if (!(entry.TargetUrl.Contains(q, StringComparison.OrdinalIgnoreCase) ||
                              entry.TrackingId.Contains(q, StringComparison.OrdinalIgnoreCase) ||
                              entry.Source.Contains(q, StringComparison.OrdinalIgnoreCase) ||
                              (entry.Campaign?.Contains(q, StringComparison.OrdinalIgnoreCase) ?? false) ||
                              (entry.Referrer?.Contains(q, StringComparison.OrdinalIgnoreCase) ?? false)))
                        {
                            continue;
                        }
                    }

                    entries.Add(entry);
                }
                catch
                {
                    // ignore bad lines
                }
            }
        }
        finally
        {
            mutex.Release();
        }

        return entries
            .OrderByDescending(e => e.Timestamp)
            .Take(Math.Clamp(limit, 1, 2000))
            .ToArray();
    }

    public async Task ClearAsync(string? category, CancellationToken cancellationToken)
    {
        var path = GetPath(category);
        var mutex = GetMutex(path);

        await mutex.WaitAsync(cancellationToken);
        try
        {
            if (File.Exists(path))
            {
                File.WriteAllText(path, string.Empty);
            }
        }
        finally
        {
            mutex.Release();
        }
    }
}
