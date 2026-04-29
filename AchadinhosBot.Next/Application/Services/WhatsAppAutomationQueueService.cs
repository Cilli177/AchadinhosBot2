using System.Collections.Concurrent;
using System.Threading.Channels;

namespace AchadinhosBot.Next.Application.Services;

public sealed class WhatsAppAutomationQueueService
{
    private readonly Channel<QueuedWhatsAppAutomationJob> _channel = Channel.CreateUnbounded<QueuedWhatsAppAutomationJob>(
        new UnboundedChannelOptions
        {
            SingleReader = true,
            SingleWriter = false
        });

    private readonly ConcurrentDictionary<string, WhatsAppAutomationQueueItem> _items = new(StringComparer.OrdinalIgnoreCase);
    private string? _currentJobId;

    public async Task<WhatsAppAutomationQueueItem> EnqueueAsync(
        string kind,
        string label,
        Func<CancellationToken, Task<(bool Success, string Message)>> handler,
        CancellationToken ct)
    {
        var item = new WhatsAppAutomationQueueItem
        {
            Id = Guid.NewGuid().ToString("N"),
            Kind = kind,
            Label = label,
            Status = "queued",
            EnqueuedAt = DateTimeOffset.UtcNow
        };

        _items[item.Id] = item;
        await _channel.Writer.WriteAsync(new QueuedWhatsAppAutomationJob(item.Id, handler), ct);
        return item;
    }

    public bool TryDequeue(out QueuedWhatsAppAutomationJob? job)
        => _channel.Reader.TryRead(out job);

    public async Task<bool> WaitForWorkAsync(CancellationToken ct)
        => await _channel.Reader.WaitToReadAsync(ct);

    public async Task ProcessNextAsync(CancellationToken ct)
    {
        if (!TryDequeue(out var job) || job is null)
        {
            return;
        }

        var item = _items.TryGetValue(job.ItemId, out var existing) ? existing : null;
        if (item is null)
        {
            return;
        }

        item.Status = "running";
        item.StartedAt = DateTimeOffset.UtcNow;
        item.Detail = null;
        _currentJobId = item.Id;

        try
        {
            var result = await job.Handler(ct);
            item.Success = result.Success;
            item.Detail = result.Message;
            item.Status = result.Success ? "done" : "failed";
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            item.Status = "cancelled";
            item.Detail = "Cancelado.";
        }
        catch (Exception ex)
        {
            item.Status = "failed";
            item.Detail = ex.Message;
        }
        finally
        {
            item.CompletedAt = DateTimeOffset.UtcNow;
            _currentJobId = null;
        }
    }

    public IReadOnlyList<WhatsAppAutomationQueueItem> GetSnapshot(int maxItems = 20)
    {
        return _items.Values
            .OrderByDescending(x => x.EnqueuedAt)
            .Take(maxItems)
            .Select(x => x.Clone())
            .ToList();
    }

    public WhatsAppAutomationQueueState GetState()
    {
        var items = GetSnapshot();
        return new WhatsAppAutomationQueueState(
            _currentJobId,
            items.Count(x => string.Equals(x.Status, "queued", StringComparison.OrdinalIgnoreCase)),
            items);
    }
}

public sealed record WhatsAppAutomationQueueState(
    string? CurrentJobId,
    int PendingCount,
    IReadOnlyList<WhatsAppAutomationQueueItem> Items);

public sealed class WhatsAppAutomationQueueItem
{
    public string Id { get; set; } = string.Empty;
    public string Kind { get; set; } = string.Empty;
    public string Label { get; set; } = string.Empty;
    public string Status { get; set; } = "queued";
    public bool Success { get; set; }
    public DateTimeOffset EnqueuedAt { get; set; }
    public DateTimeOffset? StartedAt { get; set; }
    public DateTimeOffset? CompletedAt { get; set; }
    public string? Detail { get; set; }

    public WhatsAppAutomationQueueItem Clone() => new()
    {
        Id = Id,
        Kind = Kind,
        Label = Label,
        Status = Status,
        Success = Success,
        EnqueuedAt = EnqueuedAt,
        StartedAt = StartedAt,
        CompletedAt = CompletedAt,
        Detail = Detail
    };
}

public sealed record QueuedWhatsAppAutomationJob(
    string ItemId,
    Func<CancellationToken, Task<(bool Success, string Message)>> Handler);
