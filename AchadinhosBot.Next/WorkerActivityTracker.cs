using System.Collections.Concurrent;

namespace AchadinhosBot.Next.Infrastructure.Monitoring;

public sealed class WorkerActivityTracker
{
    private readonly ConcurrentDictionary<string, WorkerActivitySnapshot> _activities = new(StringComparer.OrdinalIgnoreCase);

    public void MarkStarted(string workerName)
    {
        if (string.IsNullOrWhiteSpace(workerName))
        {
            return;
        }

        _activities.AddOrUpdate(
            workerName,
            _ => new WorkerActivitySnapshot(workerName, DateTimeOffset.UtcNow, null, null, null),
            (_, existing) => existing);
    }

    public void MarkSuccess(string workerName)
    {
        if (string.IsNullOrWhiteSpace(workerName))
        {
            return;
        }

        _activities.AddOrUpdate(
            workerName,
            _ => new WorkerActivitySnapshot(workerName, DateTimeOffset.UtcNow, DateTimeOffset.UtcNow, null, null),
            (_, existing) => existing with
            {
                LastSuccessUtc = DateTimeOffset.UtcNow,
                LastFailureUtc = null,
                LastError = null
            });
    }

    public void MarkFailure(string workerName, Exception ex)
    {
        if (string.IsNullOrWhiteSpace(workerName))
        {
            return;
        }

        _activities.AddOrUpdate(
            workerName,
            _ => new WorkerActivitySnapshot(workerName, DateTimeOffset.UtcNow, null, DateTimeOffset.UtcNow, ex.Message),
            (_, existing) => existing with
            {
                LastFailureUtc = DateTimeOffset.UtcNow,
                LastError = ex.Message
            });
    }

    public WorkerActivitySnapshot? GetSnapshot(string workerName)
    {
        if (string.IsNullOrWhiteSpace(workerName))
        {
            return null;
        }

        return _activities.TryGetValue(workerName, out var snapshot) ? snapshot : null;
    }

    public IReadOnlyList<WorkerActivitySnapshot> ListSnapshots()
        => _activities.Values.OrderBy(x => x.WorkerName, StringComparer.OrdinalIgnoreCase).ToArray();
}

public sealed record WorkerActivitySnapshot(
    string WorkerName,
    DateTimeOffset FirstSeenUtc,
    DateTimeOffset? LastSuccessUtc,
    DateTimeOffset? LastFailureUtc,
    string? LastError);
