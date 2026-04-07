using System.Text.Json;
using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Domain.Logs;

namespace AchadinhosBot.Next.Infrastructure.Storage;

public sealed class InstagramAiLogStore : IInstagramAiLogStore
{
    private readonly string _path;
    private readonly SemaphoreSlim _mutex = new(1, 1);

    public InstagramAiLogStore()
    {
        var dir = Path.Combine(AppContext.BaseDirectory, "data");
        Directory.CreateDirectory(dir);
        _path = Path.Combine(dir, "instagram-ai-log.jsonl");
    }

    public async Task AppendAsync(InstagramAiLogEntry entry, CancellationToken ct)
    {
        await _mutex.WaitAsync(ct);
        try
        {
            var line = JsonSerializer.Serialize(entry) + Environment.NewLine;
            await File.AppendAllTextAsync(_path, line, ct);
        }
        finally
        {
            _mutex.Release();
        }
    }

    public async Task<IReadOnlyList<InstagramAiLogEntry>> ListAsync(int take, CancellationToken ct)
    {
        await _mutex.WaitAsync(ct);
        try
        {
            if (!File.Exists(_path))
            {
                return Array.Empty<InstagramAiLogEntry>();
            }

            var lines = await File.ReadAllLinesAsync(_path, ct);
            return lines
                .Where(x => !string.IsNullOrWhiteSpace(x))
                .Select(x => TryDeserialize<InstagramAiLogEntry>(x))
                .Where(x => x is not null)
                .Select(x => x!)
                .TakeLast(Math.Clamp(take, 1, 5000))
                .Reverse()
                .ToArray();
        }
        finally
        {
            _mutex.Release();
        }
    }

    public async Task ClearAsync(CancellationToken ct)
    {
        await _mutex.WaitAsync(ct);
        try
        {
            await File.WriteAllTextAsync(_path, string.Empty, ct);
        }
        finally
        {
            _mutex.Release();
        }
    }

    private static T? TryDeserialize<T>(string line)
    {
        try
        {
            return JsonSerializer.Deserialize<T>(line);
        }
        catch
        {
            return default;
        }
    }
}
