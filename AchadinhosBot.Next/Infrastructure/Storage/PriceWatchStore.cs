using System.Text.Json;
using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Domain.PriceWatch;

namespace AchadinhosBot.Next.Infrastructure.Storage;

public sealed class PriceWatchStore : IPriceWatchStore
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true
    };

    private readonly string _path;
    private readonly SemaphoreSlim _lock = new(1, 1);

    public PriceWatchStore(IWebHostEnvironment environment)
    {
        var root = string.IsNullOrWhiteSpace(environment.ContentRootPath)
            ? AppContext.BaseDirectory
            : environment.ContentRootPath;
        _path = Path.Combine(root, "data", "price-watches.json");
    }

    public async Task<IReadOnlyList<PriceWatchItem>> ListAsync(CancellationToken cancellationToken, string? status = null, string? contactJid = null)
    {
        await _lock.WaitAsync(cancellationToken);
        try
        {
            var data = await LoadCoreAsync(cancellationToken);
            return data.Watches
                .Where(x => string.IsNullOrWhiteSpace(status) || string.Equals(x.Status, status, StringComparison.OrdinalIgnoreCase))
                .Where(x => string.IsNullOrWhiteSpace(contactJid) || string.Equals(x.ContactJid, contactJid, StringComparison.OrdinalIgnoreCase))
                .OrderByDescending(x => x.UpdatedAt)
                .ToList();
        }
        finally
        {
            _lock.Release();
        }
    }

    public async Task<IReadOnlyList<PriceWatchItem>> ListDueAsync(DateTimeOffset now, int limit, CancellationToken cancellationToken)
    {
        await _lock.WaitAsync(cancellationToken);
        try
        {
            var data = await LoadCoreAsync(cancellationToken);
            return data.Watches
                .Where(x => string.Equals(x.Status, PriceWatchStatuses.Active, StringComparison.OrdinalIgnoreCase))
                .Where(x => x.NextCheckAt <= now)
                .OrderBy(x => x.NextCheckAt)
                .Take(Math.Clamp(limit, 1, 100))
                .ToList();
        }
        finally
        {
            _lock.Release();
        }
    }

    public async Task<PriceWatchItem?> GetAsync(string id, CancellationToken cancellationToken)
    {
        await _lock.WaitAsync(cancellationToken);
        try
        {
            var data = await LoadCoreAsync(cancellationToken);
            return data.Watches.FirstOrDefault(x => string.Equals(x.Id, id, StringComparison.OrdinalIgnoreCase));
        }
        finally
        {
            _lock.Release();
        }
    }

    public Task SaveAsync(PriceWatchItem item, CancellationToken cancellationToken)
        => UpsertAsync(item, cancellationToken);

    public Task UpdateAsync(PriceWatchItem item, CancellationToken cancellationToken)
        => UpsertAsync(item, cancellationToken);

    public async Task<int> PauseByContactAsync(string contactJid, CancellationToken cancellationToken)
    {
        await _lock.WaitAsync(cancellationToken);
        try
        {
            var data = await LoadCoreAsync(cancellationToken);
            var count = 0;
            foreach (var item in data.Watches.Where(x =>
                         string.Equals(x.ContactJid, contactJid, StringComparison.OrdinalIgnoreCase) &&
                         string.Equals(x.Status, PriceWatchStatuses.Active, StringComparison.OrdinalIgnoreCase)))
            {
                item.Status = PriceWatchStatuses.Paused;
                item.UpdatedAt = DateTimeOffset.UtcNow;
                count++;
            }

            if (count > 0)
            {
                await SaveCoreAsync(data, cancellationToken);
            }

            return count;
        }
        finally
        {
            _lock.Release();
        }
    }

    public async Task<IReadOnlyList<PriceWatchReviewItem>> ListReviewsAsync(CancellationToken cancellationToken, string? status = "pending")
    {
        await _lock.WaitAsync(cancellationToken);
        try
        {
            var data = await LoadCoreAsync(cancellationToken);
            return data.Reviews
                .Where(x => string.IsNullOrWhiteSpace(status) || string.Equals(x.Status, status, StringComparison.OrdinalIgnoreCase))
                .OrderByDescending(x => x.CreatedAt)
                .ToList();
        }
        finally
        {
            _lock.Release();
        }
    }

    public async Task<PriceWatchReviewItem?> GetReviewAsync(string id, CancellationToken cancellationToken)
    {
        await _lock.WaitAsync(cancellationToken);
        try
        {
            var data = await LoadCoreAsync(cancellationToken);
            return data.Reviews.FirstOrDefault(x => string.Equals(x.Id, id, StringComparison.OrdinalIgnoreCase));
        }
        finally
        {
            _lock.Release();
        }
    }

    public Task SaveReviewAsync(PriceWatchReviewItem item, CancellationToken cancellationToken)
        => UpsertReviewAsync(item, cancellationToken);

    public Task UpdateReviewAsync(PriceWatchReviewItem item, CancellationToken cancellationToken)
        => UpsertReviewAsync(item, cancellationToken);

    private async Task UpsertAsync(PriceWatchItem item, CancellationToken cancellationToken)
    {
        await _lock.WaitAsync(cancellationToken);
        try
        {
            var data = await LoadCoreAsync(cancellationToken);
            Normalize(item);
            var index = data.Watches.FindIndex(x => string.Equals(x.Id, item.Id, StringComparison.OrdinalIgnoreCase));
            if (index >= 0)
            {
                data.Watches[index] = item;
            }
            else
            {
                data.Watches.Add(item);
            }

            await SaveCoreAsync(data, cancellationToken);
        }
        finally
        {
            _lock.Release();
        }
    }

    private async Task UpsertReviewAsync(PriceWatchReviewItem item, CancellationToken cancellationToken)
    {
        await _lock.WaitAsync(cancellationToken);
        try
        {
            var data = await LoadCoreAsync(cancellationToken);
            var index = data.Reviews.FindIndex(x => string.Equals(x.Id, item.Id, StringComparison.OrdinalIgnoreCase));
            if (index >= 0)
            {
                data.Reviews[index] = item;
            }
            else
            {
                data.Reviews.Add(item);
            }

            await SaveCoreAsync(data, cancellationToken);
        }
        finally
        {
            _lock.Release();
        }
    }

    private async Task<PriceWatchData> LoadCoreAsync(CancellationToken cancellationToken)
    {
        if (!File.Exists(_path))
        {
            return new PriceWatchData();
        }

        await using var stream = File.OpenRead(_path);
        var data = await JsonSerializer.DeserializeAsync<PriceWatchData>(stream, JsonOptions, cancellationToken)
                   ?? new PriceWatchData();
        foreach (var item in data.Watches)
        {
            Normalize(item);
        }

        return data;
    }

    private async Task SaveCoreAsync(PriceWatchData data, CancellationToken cancellationToken)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(_path)!);
        var temp = _path + ".tmp";
        await using (var stream = File.Create(temp))
        {
            await JsonSerializer.SerializeAsync(stream, data, JsonOptions, cancellationToken);
        }

        File.Move(temp, _path, overwrite: true);
    }

    private static void Normalize(PriceWatchItem item)
    {
        item.Id = string.IsNullOrWhiteSpace(item.Id) ? Guid.NewGuid().ToString("N") : item.Id.Trim();
        item.ContactJid = (item.ContactJid ?? string.Empty).Trim();
        item.Status = string.IsNullOrWhiteSpace(item.Status) ? PriceWatchStatuses.Active : item.Status.Trim();
        item.SourceType = string.IsNullOrWhiteSpace(item.SourceType) ? PriceWatchSourceTypes.Link : item.SourceType.Trim();
        item.IntervalHours = Math.Clamp(item.IntervalHours <= 0 ? 12 : item.IntervalHours, 1, 168);
        item.NearTargetPercent = item.NearTargetPercent <= 0 ? 5m : Math.Clamp(item.NearTargetPercent, 1m, 25m);
        if (item.NextCheckAt == default)
        {
            item.NextCheckAt = DateTimeOffset.UtcNow;
        }
    }

    private sealed class PriceWatchData
    {
        public List<PriceWatchItem> Watches { get; set; } = new();
        public List<PriceWatchReviewItem> Reviews { get; set; } = new();
    }
}
