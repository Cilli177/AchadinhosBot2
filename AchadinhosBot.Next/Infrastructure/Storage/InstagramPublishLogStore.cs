using System.Text.Json;
using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Domain.Instagram;
using AchadinhosBot.Next.Domain.Logs;

namespace AchadinhosBot.Next.Infrastructure.Storage;

public sealed class InstagramPublishLogStore : IInstagramPublishLogStore
{
    private readonly string _path = Path.Combine(AppContext.BaseDirectory, "data", "instagram-publish-log.jsonl");
    private readonly SemaphoreSlim _mutex = new(1, 1);

    public async Task AppendAsync(InstagramPublishLogEntry entry, CancellationToken ct)
    {
        await _mutex.WaitAsync(ct);
        try
        {
            if (string.IsNullOrWhiteSpace(entry.ProcessName))
            {
                entry.ProcessName = InstagramProcessNames.ReelAssistido;
            }
            else
            {
                entry.ProcessName = entry.ProcessName.Trim();
            }
            Directory.CreateDirectory(Path.GetDirectoryName(_path)!);
            var line = JsonSerializer.Serialize(entry) + Environment.NewLine;
            await File.AppendAllTextAsync(_path, line, ct);
        }
        finally
        {
            _mutex.Release();
        }
    }

    public async Task<IReadOnlyList<InstagramPublishLogEntry>> ListAsync(int take, CancellationToken ct)
    {
        await _mutex.WaitAsync(ct);
        try
        {
            if (!File.Exists(_path))
            {
                return Array.Empty<InstagramPublishLogEntry>();
            }

            var lines = await File.ReadAllLinesAsync(_path, ct);
            return lines
                .Where(static x => !string.IsNullOrWhiteSpace(x))
                .Select(TryDeserialize)
                .Where(static x => x is not null)
                .Cast<InstagramPublishLogEntry>()
                .OrderByDescending(static x => x.Timestamp)
                .Take(Math.Clamp(take, 1, 5000))
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
            if (File.Exists(_path))
            {
                await File.WriteAllTextAsync(_path, string.Empty, ct);
            }
        }
        finally
        {
            _mutex.Release();
        }
    }

    private static InstagramPublishLogEntry? TryDeserialize(string line)
    {
        try
        {
            return JsonSerializer.Deserialize<InstagramPublishLogEntry>(line);
        }
        catch
        {
            return null;
        }
    }
}
