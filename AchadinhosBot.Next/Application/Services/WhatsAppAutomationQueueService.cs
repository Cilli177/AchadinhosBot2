using System.Collections.Concurrent;
using System.Threading.Channels;

namespace AchadinhosBot.Next.Application.Services;

public sealed class WhatsAppAutomationQueueService
{
    private readonly Channel<string> _channel = Channel.CreateUnbounded<string>(
        new UnboundedChannelOptions
        {
            SingleReader = true,
            SingleWriter = false
        });

    private readonly ConcurrentDictionary<string, WhatsAppAutomationQueueItem> _items = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, QueuedWhatsAppAutomationJob> _jobs = new(StringComparer.OrdinalIgnoreCase);
    private string? _currentJobId;

    public async Task<WhatsAppAutomationQueueItem> EnqueueAsync(
        string kind,
        string label,
        Func<CancellationToken, Task<(bool Success, string Message)>> handler,
        CancellationToken ct,
        DateTimeOffset? scheduledForUtc = null)
    {
        var item = new WhatsAppAutomationQueueItem
        {
            Id = Guid.NewGuid().ToString("N"),
            Kind = kind,
            Label = label,
            Status = "queued",
            EnqueuedAt = DateTimeOffset.UtcNow,
            ScheduledForUtc = scheduledForUtc?.ToUniversalTime()
        };

        _items[item.Id] = item;
        _jobs[item.Id] = new QueuedWhatsAppAutomationJob(item.Id, handler);
        await _channel.Writer.WriteAsync(item.Id, ct);
        return item;
    }

    public bool TryDequeue(out QueuedWhatsAppAutomationJob? job)
    {
        while (_channel.Reader.TryRead(out _))
        {
            // The channel is only a wake-up signal; jobs live in _jobs so future
            // scheduled messages do not block immediate messages behind them.
        }

        var now = DateTimeOffset.UtcNow;
        var due = _jobs.Values
            .Select(x => new
            {
                Job = x,
                Item = _items.TryGetValue(x.ItemId, out var item) ? item : null
            })
            .Where(x => x.Item is not null)
            .Where(x => string.Equals(x.Item!.Status, "queued", StringComparison.OrdinalIgnoreCase))
            .Where(x => !x.Item!.ScheduledForUtc.HasValue || x.Item.ScheduledForUtc.Value <= now)
            .OrderBy(x => x.Item!.ScheduledForUtc ?? x.Item.EnqueuedAt)
            .ThenBy(x => x.Item!.EnqueuedAt)
            .FirstOrDefault();

        if (due is null || !_jobs.TryRemove(due.Job.ItemId, out job))
        {
            job = null;
            return false;
        }

        return true;
    }

    public async Task<bool> WaitForWorkAsync(CancellationToken ct)
        => await _channel.Reader.WaitToReadAsync(ct);

    public bool HasDueQueuedWork()
    {
        var now = DateTimeOffset.UtcNow;
        return _items.Values.Any(x =>
            string.Equals(x.Status, "queued", StringComparison.OrdinalIgnoreCase) &&
            (!x.ScheduledForUtc.HasValue || x.ScheduledForUtc.Value <= now));
    }

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
            _jobs.TryRemove(item.Id, out _);
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
    public DateTimeOffset? ScheduledForUtc { get; set; }
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
        ScheduledForUtc = ScheduledForUtc,
        StartedAt = StartedAt,
        CompletedAt = CompletedAt,
        Detail = Detail
    };
}

public sealed record QueuedWhatsAppAutomationJob(
    string ItemId,
    Func<CancellationToken, Task<(bool Success, string Message)>> Handler);
