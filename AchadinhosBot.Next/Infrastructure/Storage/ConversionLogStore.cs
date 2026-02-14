using System.Text.Json;
using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Domain.Logs;

namespace AchadinhosBot.Next.Infrastructure.Storage;

public sealed class ConversionLogStore : IConversionLogStore
{
    private readonly string _path;
    private readonly SemaphoreSlim _mutex = new(1, 1);

    public ConversionLogStore()
    {
        _path = Path.Combine(AppContext.BaseDirectory, "data", "conversion-logs.jsonl");
    }

    public async Task AppendAsync(ConversionLogEntry entry, CancellationToken cancellationToken)
    {
        await _mutex.WaitAsync(cancellationToken);
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(_path)!);
            await using var stream = new FileStream(_path, FileMode.Append, FileAccess.Write, FileShare.Read);
            await using var writer = new StreamWriter(stream);
            var json = JsonSerializer.Serialize(entry);
            await writer.WriteLineAsync(json);
            await writer.FlushAsync();
        }
        finally
        {
            _mutex.Release();
        }
    }

    public async Task<IReadOnlyList<ConversionLogEntry>> QueryAsync(ConversionLogQuery query, CancellationToken cancellationToken)
    {
        var entries = new List<ConversionLogEntry>();
        if (!File.Exists(_path))
        {
            return entries;
        }

        await _mutex.WaitAsync(cancellationToken);
        try
        {
            await using var stream = File.OpenRead(_path);
            using var reader = new StreamReader(stream);
            while (!reader.EndOfStream)
            {
                var line = await reader.ReadLineAsync();
                if (string.IsNullOrWhiteSpace(line)) continue;
                try
                {
                    var entry = JsonSerializer.Deserialize<ConversionLogEntry>(line);
                    if (entry is null) continue;

                    if (!string.IsNullOrWhiteSpace(query.Store) &&
                        !string.Equals(entry.Store, query.Store, StringComparison.OrdinalIgnoreCase))
                    {
                        continue;
                    }

                    if (!string.IsNullOrWhiteSpace(query.Search))
                    {
                        var q = query.Search.Trim();
                        if (!(entry.OriginalUrl.Contains(q, StringComparison.OrdinalIgnoreCase) ||
                              entry.ConvertedUrl.Contains(q, StringComparison.OrdinalIgnoreCase) ||
                              (entry.OriginChatRef?.Contains(q, StringComparison.OrdinalIgnoreCase) ?? false) ||
                              (entry.DestinationChatRef?.Contains(q, StringComparison.OrdinalIgnoreCase) ?? false) ||
                              (entry.OriginChatId?.ToString().Contains(q, StringComparison.OrdinalIgnoreCase) ?? false) ||
                              (entry.DestinationChatId?.ToString().Contains(q, StringComparison.OrdinalIgnoreCase) ?? false)))
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
            _mutex.Release();
        }

        return entries
            .OrderByDescending(e => e.Timestamp)
            .Take(Math.Clamp(query.Limit, 1, 500))
            .ToArray();
    }

    public async Task ClearAsync(CancellationToken cancellationToken)
    {
        await _mutex.WaitAsync(cancellationToken);
        try
        {
            if (File.Exists(_path))
            {
                File.WriteAllText(_path, string.Empty);
            }
        }
        finally
        {
            _mutex.Release();
        }
    }
}
