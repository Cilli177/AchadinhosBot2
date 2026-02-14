using System.Text.Json;
using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Domain.Instagram;

namespace AchadinhosBot.Next.Infrastructure.Storage;

public sealed class InstagramCommentStore : IInstagramCommentStore
{
    private readonly string _path;
    private readonly SemaphoreSlim _mutex = new(1, 1);

    public InstagramCommentStore()
    {
        _path = Path.Combine(AppContext.BaseDirectory, "data", "instagram-comments.json");
    }

    public async Task<IReadOnlyList<InstagramCommentPending>> ListPendingAsync(CancellationToken ct)
    {
        await _mutex.WaitAsync(ct);
        try
        {
            var items = await ReadAllAsync(ct);
            return items.Where(x => x.Status == "pending").OrderByDescending(x => x.Timestamp).ToList();
        }
        finally
        {
            _mutex.Release();
        }
    }

    public async Task AddAsync(InstagramCommentPending comment, CancellationToken ct)
    {
        await _mutex.WaitAsync(ct);
        try
        {
            var items = await ReadAllAsync(ct);
            items.Add(comment);
            await WriteAllAsync(items, ct);
        }
        finally
        {
            _mutex.Release();
        }
    }

    public async Task<InstagramCommentPending?> GetAsync(string id, CancellationToken ct)
    {
        await _mutex.WaitAsync(ct);
        try
        {
            var items = await ReadAllAsync(ct);
            return items.FirstOrDefault(x => x.Id == id);
        }
        finally
        {
            _mutex.Release();
        }
    }

    public async Task UpdateAsync(InstagramCommentPending comment, CancellationToken ct)
    {
        await _mutex.WaitAsync(ct);
        try
        {
            var items = await ReadAllAsync(ct);
            var idx = items.FindIndex(x => x.Id == comment.Id);
            if (idx >= 0)
            {
                items[idx] = comment;
            }
            else
            {
                items.Add(comment);
            }
            await WriteAllAsync(items, ct);
        }
        finally
        {
            _mutex.Release();
        }
    }

    private async Task<List<InstagramCommentPending>> ReadAllAsync(CancellationToken ct)
    {
        if (!File.Exists(_path)) return new List<InstagramCommentPending>();
        var json = await File.ReadAllTextAsync(_path, ct);
        if (string.IsNullOrWhiteSpace(json)) return new List<InstagramCommentPending>();
        return JsonSerializer.Deserialize<List<InstagramCommentPending>>(json) ?? new List<InstagramCommentPending>();
    }

    private async Task WriteAllAsync(List<InstagramCommentPending> items, CancellationToken ct)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(_path)!);
        var json = JsonSerializer.Serialize(items);
        await File.WriteAllTextAsync(_path, json, ct);
    }
}
