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

    private IEnumerable<string> GetPaths(string? category)
    {
        Directory.CreateDirectory(_basePath);
        if (!string.IsNullOrWhiteSpace(category))
        {
            var path = GetPath(category);
            if (File.Exists(path))
            {
                yield return path;
            }
            yield break;
        }

        var files = Directory
            .EnumerateFiles(_basePath, "click-logs*.jsonl", SearchOption.TopDirectoryOnly)
            .OrderBy(x => x, StringComparer.OrdinalIgnoreCase)
            .ToArray();

        if (files.Length == 0)
        {
            var rootPath = GetPath(null);
            if (File.Exists(rootPath))
            {
                yield return rootPath;
            }
            yield break;
        }

        foreach (var file in files)
        {
            yield return file;
        }
    }

    private static string? InferCategory(string path)
    {
        var name = Path.GetFileNameWithoutExtension(path);
        if (string.Equals(name, "click-logs", StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        const string prefix = "click-logs-";
        return name.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)
            ? name[prefix.Length..].Trim().ToLowerInvariant()
            : null;
    }

    private static string? InferCategoryFromEntry(ClickLogEntry entry, string? fallbackCategory)
    {
        if (!string.IsNullOrWhiteSpace(entry.Category))
        {
            return entry.Category.Trim().ToLowerInvariant();
        }

        if (!string.IsNullOrWhiteSpace(fallbackCategory))
        {
            return fallbackCategory.Trim().ToLowerInvariant();
        }

        var source = entry.Source?.Trim().ToLowerInvariant() ?? string.Empty;
        var targetUrl = entry.TargetUrl?.Trim().ToLowerInvariant() ?? string.Empty;

        if (source.Contains("bio") || targetUrl.Contains("utm_source=bio") || targetUrl.Contains("bio.reidasofertas.ia.br"))
        {
            return "bio";
        }

        if (source.Contains("catalog") || targetUrl.Contains("/catalogo") || targetUrl.Contains("/item/"))
        {
            return "catalog";
        }

        if (source.Contains("convert") || source.Contains("converter") || source.Contains("admin_") || targetUrl.Contains("/conversor"))
        {
            return "converter";
        }

        return null;
    }

    private SemaphoreSlim GetMutex(string path) => _mutexes.GetOrAdd(path, _ => new SemaphoreSlim(1, 1));

    public async Task AppendAsync(ClickLogEntry entry, string? category, CancellationToken cancellationToken)
    {
        var normalizedCategory = string.IsNullOrWhiteSpace(category) ? null : category.Trim().ToLowerInvariant();
        entry.Category = string.IsNullOrWhiteSpace(entry.Category) ? normalizedCategory : entry.Category.Trim().ToLowerInvariant();
        var path = GetPath(normalizedCategory);
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
        var normalizedCategory = string.IsNullOrWhiteSpace(category) ? null : category.Trim().ToLowerInvariant();
        var paths = GetPaths(null).ToArray();
        if (paths.Length == 0)
        {
            return entries;
        }

        foreach (var path in paths)
        {
            var inferredCategory = InferCategory(path);
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
                        entry.Category = InferCategoryFromEntry(entry, inferredCategory);

                        if (!string.IsNullOrWhiteSpace(normalizedCategory) && !string.Equals(entry.Category, normalizedCategory, StringComparison.OrdinalIgnoreCase))
                        {
                            continue;
                        }

                        if (!string.IsNullOrWhiteSpace(search))
                        {
                            var q = search.Trim();
                            if (!(entry.TargetUrl.Contains(q, StringComparison.OrdinalIgnoreCase) ||
                                  entry.TrackingId.Contains(q, StringComparison.OrdinalIgnoreCase) ||
                                  entry.Source.Contains(q, StringComparison.OrdinalIgnoreCase) ||
                                  (entry.Category?.Contains(q, StringComparison.OrdinalIgnoreCase) ?? false) ||
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
        }

        return entries
            .OrderByDescending(e => e.Timestamp)
            .Take(Math.Clamp(limit, 1, 5000))
            .ToArray();
    }

    public async Task ClearAsync(string? category, CancellationToken cancellationToken)
    {
        var paths = GetPaths(category).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        if (paths.Length == 0 && !string.IsNullOrWhiteSpace(category))
        {
            paths = new[] { GetPath(category) };
        }

        foreach (var path in paths)
        {
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
}
