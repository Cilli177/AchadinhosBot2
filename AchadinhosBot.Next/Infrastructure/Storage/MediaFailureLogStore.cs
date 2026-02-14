using System.Text.Json;
using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Domain.Logs;

namespace AchadinhosBot.Next.Infrastructure.Storage;

public sealed class MediaFailureLogStore : IMediaFailureLogStore
{
    private readonly string _path;
    private readonly SemaphoreSlim _mutex = new(1, 1);

    public MediaFailureLogStore()
    {
        _path = Path.Combine(AppContext.BaseDirectory, "data", "media-failures.jsonl");
    }

    public async Task AppendAsync(MediaFailureEntry entry, CancellationToken cancellationToken)
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

    public async Task<IReadOnlyList<MediaFailureEntry>> ListAsync(int limit, CancellationToken cancellationToken)
    {
        var entries = new List<MediaFailureEntry>();
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
                    var entry = JsonSerializer.Deserialize<MediaFailureEntry>(line);
                    if (entry is not null)
                    {
                        entries.Add(entry);
                    }
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
            .Take(Math.Clamp(limit, 1, 200))
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
