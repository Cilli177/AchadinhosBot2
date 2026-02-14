using System.Text.Json;
using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Domain.Instagram;

namespace AchadinhosBot.Next.Infrastructure.Storage;

public sealed class InstagramPublishStore : IInstagramPublishStore
{
    private readonly string _path;
    private readonly SemaphoreSlim _mutex = new(1, 1);

    public InstagramPublishStore()
    {
        _path = Path.Combine(AppContext.BaseDirectory, "data", "instagram-drafts.json");
    }

    public async Task<IReadOnlyList<InstagramPublishDraft>> ListAsync(CancellationToken ct)
    {
        await _mutex.WaitAsync(ct);
        try
        {
            return await ReadAllAsync(ct);
        }
        finally
        {
            _mutex.Release();
        }
    }

    public async Task<InstagramPublishDraft?> GetAsync(string id, CancellationToken ct)
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

    public async Task SaveAsync(InstagramPublishDraft draft, CancellationToken ct)
    {
        await _mutex.WaitAsync(ct);
        try
        {
            var items = await ReadAllAsync(ct);
            items.Add(draft);
            await WriteAllAsync(items, ct);
        }
        finally
        {
            _mutex.Release();
        }
    }

    public async Task UpdateAsync(InstagramPublishDraft draft, CancellationToken ct)
    {
        await _mutex.WaitAsync(ct);
        try
        {
            var items = await ReadAllAsync(ct);
            var idx = items.FindIndex(x => x.Id == draft.Id);
            if (idx >= 0)
            {
                items[idx] = draft;
            }
            else
            {
                items.Add(draft);
            }
            await WriteAllAsync(items, ct);
        }
        finally
        {
            _mutex.Release();
        }
    }

    private async Task<List<InstagramPublishDraft>> ReadAllAsync(CancellationToken ct)
    {
        if (!File.Exists(_path)) return new List<InstagramPublishDraft>();
        var json = await File.ReadAllTextAsync(_path, ct);
        if (string.IsNullOrWhiteSpace(json)) return new List<InstagramPublishDraft>();
        return JsonSerializer.Deserialize<List<InstagramPublishDraft>>(json) ?? new List<InstagramPublishDraft>();
    }

    private async Task WriteAllAsync(List<InstagramPublishDraft> items, CancellationToken ct)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(_path)!);
        var json = JsonSerializer.Serialize(items);
        await File.WriteAllTextAsync(_path, json, ct);
    }
}
