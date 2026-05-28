using System.Collections.Concurrent;
using System.Threading.Channels;
using AchadinhosBot.Next.Application.Abstractions;

namespace AchadinhosBot.Next.Application.Services;

public sealed class WhatsAppAutomationQueueService
{
    private const int DefaultCapacity = 1000;
    private const int MaxAttempts = 3;

    private readonly Channel<string> _channel = Channel.CreateUnbounded<string>(
        new UnboundedChannelOptions
        {
            SingleReader = true,
            SingleWriter = false
        });

    private readonly IOutboundRateLimitPolicy? _rateLimitPolicy;
    private readonly ConcurrentDictionary<string, WhatsAppAutomationQueueItem> _items = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, QueuedWhatsAppAutomationJob> _jobs = new(StringComparer.OrdinalIgnoreCase);
    private string? _currentJobId;

    public WhatsAppAutomationQueueService()
    {
    }

    public WhatsAppAutomationQueueService(IOutboundRateLimitPolicy rateLimitPolicy)
    {
        _rateLimitPolicy = rateLimitPolicy;
    }

    public async Task<WhatsAppAutomationQueueItem> EnqueueAsync(
        string kind,
        string label,
        Func<CancellationToken, Task<(bool Success, string Message)>> handler,
        CancellationToken ct,
        DateTimeOffset? scheduledForUtc = null)
    {
        if (_items.Values.Count(x => string.Equals(x.Status, "queued", StringComparison.OrdinalIgnoreCase)) >= DefaultCapacity)
        {
            throw new InvalidOperationException($"Fila de automacao WhatsApp cheia (capacidade {DefaultCapacity}).");
        }

        var item = new WhatsAppAutomationQueueItem
        {
            Id = Guid.NewGuid().ToString("N"),
            Kind = kind,
            Label = label,
            Status = "queued",
            EnqueuedAt = DateTimeOffset.UtcNow,
            ScheduledForUtc = scheduledForUtc?.ToUniversalTime(),
            Attempts = 0,
            MaxAttempts = MaxAttempts
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
        item.Attempts++;
        item.StartedAt = DateTimeOffset.UtcNow;
        item.Detail = null;
        _currentJobId = item.Id;

        try
        {
            var result = await job.Handler(ct);
            item.Success = result.Success;
            item.Detail = result.Message;
            if (result.Success)
            {
                item.Status = "done";
                _rateLimitPolicy?.RecordSuccess(item.Kind, item.Label);
            }
            else if (ShouldRetry(item, result.Message, out var retryDelay))
            {
                item.Status = "queued";
                item.ScheduledForUtc = DateTimeOffset.UtcNow.Add(retryDelay);
                item.LastError = result.Message;
                _jobs[item.Id] = job;
                await _channel.Writer.WriteAsync(item.Id, ct);
            }
            else
            {
                item.Status = "failed";
                item.LastError = result.Message;
            }
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            item.Status = "cancelled";
            item.Detail = "Cancelado.";
        }
        catch (Exception ex)
        {
            item.Detail = ex.Message;
            if (ShouldRetry(item, ex.Message, out var retryDelay))
            {
                item.Status = "queued";
                item.ScheduledForUtc = DateTimeOffset.UtcNow.Add(retryDelay);
                item.LastError = ex.Message;
                _jobs[item.Id] = job;
                await _channel.Writer.WriteAsync(item.Id, ct);
            }
            else
            {
                item.Status = "failed";
                item.LastError = ex.Message;
            }
        }
        finally
        {
            item.CompletedAt = DateTimeOffset.UtcNow;
            _currentJobId = null;
            if (!string.Equals(item.Status, "queued", StringComparison.OrdinalIgnoreCase))
            {
                _jobs.TryRemove(item.Id, out _);
            }
        }
    }

    private bool ShouldRetry(WhatsAppAutomationQueueItem item, string? message, out TimeSpan delay)
    {
        var isRateLimit = LooksLikeRateLimit(message);
        _rateLimitPolicy?.RecordFailure(item.Kind, item.Label, isRateLimit);
        if (item.Attempts >= item.MaxAttempts || !IsTransientFailure(message))
        {
            delay = TimeSpan.Zero;
            return false;
        }

        if (_rateLimitPolicy?.TryGetDelay(item.Kind, item.Label, out delay) == true && delay > TimeSpan.Zero)
        {
            return true;
        }

        delay = TimeSpan.FromSeconds(Math.Min(120, Math.Pow(2, item.Attempts) * 5));
        return true;
    }

    private static bool IsTransientFailure(string? message)
        => LooksLikeRateLimit(message)
           || Contains(message, "tempor")
           || Contains(message, "timeout")
           || Contains(message, "unavailable")
           || Contains(message, "indispon")
           || Contains(message, "closed")
           || Contains(message, "close")
           || Contains(message, "503")
           || Contains(message, "502");

    private static bool LooksLikeRateLimit(string? message)
        => Contains(message, "rate")
           || Contains(message, "limit")
           || Contains(message, "429")
           || Contains(message, "overlimit")
           || Contains(message, "too many");

    private static bool Contains(string? value, string needle)
        => value?.Contains(needle, StringComparison.OrdinalIgnoreCase) == true;

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
    public int Attempts { get; set; }
    public int MaxAttempts { get; set; } = 3;
    public string? Detail { get; set; }
    public string? LastError { get; set; }

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
        Attempts = Attempts,
        MaxAttempts = MaxAttempts,
        Detail = Detail,
        LastError = LastError
    };
}

public sealed record QueuedWhatsAppAutomationJob(
    string ItemId,
    Func<CancellationToken, Task<(bool Success, string Message)>> Handler);
