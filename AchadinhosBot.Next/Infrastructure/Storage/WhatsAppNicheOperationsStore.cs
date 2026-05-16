using System.Text.Json;
using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Domain.Logs;

namespace AchadinhosBot.Next.Infrastructure.Storage;

public sealed class WhatsAppNicheOperationsStore : IWhatsAppNicheOperationsStore
{
    private readonly string _eventsPath = Path.Combine(AppContext.BaseDirectory, "data", "whatsapp-niche-route-events.jsonl");
    private readonly string _reviewsPath = Path.Combine(AppContext.BaseDirectory, "data", "whatsapp-niche-reviews.json");
    private readonly SemaphoreSlim _mutex = new(1, 1);

    public async Task AppendRouteEventAsync(WhatsAppNicheRouteEvent entry, CancellationToken cancellationToken)
    {
        await _mutex.WaitAsync(cancellationToken);
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(_eventsPath)!);
            await File.AppendAllTextAsync(_eventsPath, JsonSerializer.Serialize(entry) + Environment.NewLine, cancellationToken);
            await JsonlLogRetention.TrimIfNeededAsync(_eventsPath, 10000, 8 * 1024 * 1024, cancellationToken);
        }
        finally { _mutex.Release(); }
    }

    public async Task<IReadOnlyList<WhatsAppNicheRouteEvent>> ListRouteEventsAsync(int limit, CancellationToken cancellationToken)
    {
        await _mutex.WaitAsync(cancellationToken);
        try
        {
            if (!File.Exists(_eventsPath)) return Array.Empty<WhatsAppNicheRouteEvent>();
            var lines = await File.ReadAllLinesAsync(_eventsPath, cancellationToken);
            return lines.Select(TryRead<WhatsAppNicheRouteEvent>).Where(x => x is not null).Cast<WhatsAppNicheRouteEvent>()
                .OrderByDescending(x => x.Timestamp).Take(Math.Clamp(limit, 1, 5000)).ToArray();
        }
        finally { _mutex.Release(); }
    }

    public async Task SaveReviewAsync(WhatsAppNicheReviewItem item, CancellationToken cancellationToken)
    {
        var items = (await ReadReviewsAsync(cancellationToken)).ToList();
        items.Add(item);
        await WriteReviewsAsync(items, cancellationToken);
    }

    public async Task<IReadOnlyList<WhatsAppNicheReviewItem>> ListReviewsAsync(string? status, int limit, CancellationToken cancellationToken)
        => (await ReadReviewsAsync(cancellationToken))
            .Where(x => string.IsNullOrWhiteSpace(status) || string.Equals(x.Status, status, StringComparison.OrdinalIgnoreCase))
            .OrderByDescending(x => x.CreatedAtUtc).Take(Math.Clamp(limit, 1, 1000)).ToArray();

    public async Task<WhatsAppNicheReviewItem?> GetReviewAsync(string id, CancellationToken cancellationToken)
        => (await ReadReviewsAsync(cancellationToken)).FirstOrDefault(x => string.Equals(x.Id, id, StringComparison.OrdinalIgnoreCase));

    public async Task UpdateReviewAsync(WhatsAppNicheReviewItem item, CancellationToken cancellationToken)
    {
        var items = (await ReadReviewsAsync(cancellationToken)).ToList();
        var index = items.FindIndex(x => string.Equals(x.Id, item.Id, StringComparison.OrdinalIgnoreCase));
        if (index >= 0) items[index] = item;
        await WriteReviewsAsync(items, cancellationToken);
    }

    private async Task<IReadOnlyList<WhatsAppNicheReviewItem>> ReadReviewsAsync(CancellationToken ct)
    {
        await _mutex.WaitAsync(ct);
        try
        {
            if (!File.Exists(_reviewsPath)) return Array.Empty<WhatsAppNicheReviewItem>();
            var json = await File.ReadAllTextAsync(_reviewsPath, ct);
            return JsonSerializer.Deserialize<List<WhatsAppNicheReviewItem>>(json) ?? [];
        }
        finally { _mutex.Release(); }
    }

    private async Task WriteReviewsAsync(IReadOnlyList<WhatsAppNicheReviewItem> items, CancellationToken ct)
    {
        await _mutex.WaitAsync(ct);
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(_reviewsPath)!);
            await File.WriteAllTextAsync(_reviewsPath, JsonSerializer.Serialize(items), ct);
        }
        finally { _mutex.Release(); }
    }

    private static T? TryRead<T>(string line)
    {
        try { return string.IsNullOrWhiteSpace(line) ? default : JsonSerializer.Deserialize<T>(line); }
        catch { return default; }
    }
}
