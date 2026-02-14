using System.Text.Json;
using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Domain.Logs;

namespace AchadinhosBot.Next.Infrastructure.Storage;

public sealed class LinkTrackingStore : ILinkTrackingStore
{
    private readonly string _path;
    private readonly SemaphoreSlim _mutex = new(1, 1);

    public LinkTrackingStore()
    {
        _path = Path.Combine(AppContext.BaseDirectory, "data", "link-tracking.json");
    }

    public async Task<LinkTrackingEntry> CreateAsync(string targetUrl, CancellationToken cancellationToken)
    {
        await _mutex.WaitAsync(cancellationToken);
        try
        {
            var data = await ReadAsync(cancellationToken);
            var id = Guid.NewGuid().ToString("N");
            var entry = new LinkTrackingEntry
            {
                Id = id,
                TargetUrl = targetUrl,
                Clicks = 0,
                CreatedAt = DateTimeOffset.UtcNow
            };
            data[id] = entry;
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
        await _mutex.WaitAsync(cancellationToken);
        try
        {
            var data = await ReadAsync(cancellationToken);
            if (!data.TryGetValue(trackingId, out var entry))
            {
                return null;
            }

            entry.Clicks += 1;
            entry.LastClickAt = DateTimeOffset.UtcNow;
            data[trackingId] = entry;
            await WriteAsync(data, cancellationToken);
            return entry;
        }
        finally
        {
            _mutex.Release();
        }
    }

    private async Task<Dictionary<string, LinkTrackingEntry>> ReadAsync(CancellationToken cancellationToken)
    {
        if (!File.Exists(_path))
        {
            return new Dictionary<string, LinkTrackingEntry>(StringComparer.OrdinalIgnoreCase);
        }

        await using var stream = File.OpenRead(_path);
        var data = await JsonSerializer.DeserializeAsync<Dictionary<string, LinkTrackingEntry>>(stream, cancellationToken: cancellationToken);
        return data ?? new Dictionary<string, LinkTrackingEntry>(StringComparer.OrdinalIgnoreCase);
    }

    private async Task WriteAsync(Dictionary<string, LinkTrackingEntry> data, CancellationToken cancellationToken)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(_path)!);
        await using var stream = File.Create(_path);
        await JsonSerializer.SerializeAsync(stream, data, new JsonSerializerOptions { WriteIndented = true }, cancellationToken);
    }
}
