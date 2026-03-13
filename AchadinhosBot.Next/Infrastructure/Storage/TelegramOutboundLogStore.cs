using System.Text.Json;
using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Domain.Logs;

namespace AchadinhosBot.Next.Infrastructure.Storage;

public sealed class TelegramOutboundLogStore : ITelegramOutboundLogStore
{
    private readonly string _path;
    private readonly SemaphoreSlim _mutex = new(1, 1);

    public TelegramOutboundLogStore()
    {
        _path = Path.Combine(AppContext.BaseDirectory, "data", "telegram-outbound-log.jsonl");
    }

    public async Task AppendAsync(TelegramOutboundLogEntry entry, CancellationToken cancellationToken)
    {
        await _mutex.WaitAsync(cancellationToken);
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(_path)!);
            var line = JsonSerializer.Serialize(entry) + Environment.NewLine;
            await File.AppendAllTextAsync(_path, line, cancellationToken);
        }
        finally
        {
            _mutex.Release();
        }
    }

    public async Task<IReadOnlyList<TelegramOutboundLogEntry>> ListRecentAsync(int limit, CancellationToken cancellationToken)
    {
        await _mutex.WaitAsync(cancellationToken);
        try
        {
            if (!File.Exists(_path))
            {
                return Array.Empty<TelegramOutboundLogEntry>();
            }

            var lines = await File.ReadAllLinesAsync(_path, cancellationToken);
            return lines
                .Where(x => !string.IsNullOrWhiteSpace(x))
                .Select(TryDeserialize)
                .Where(x => x is not null)
                .Cast<TelegramOutboundLogEntry>()
                .OrderByDescending(x => x.CreatedAtUtc)
                .Take(Math.Clamp(limit, 1, 1000))
                .ToArray();
        }
        finally
        {
            _mutex.Release();
        }
    }

    public async Task<TelegramOutboundLogEntry?> GetAsync(string messageId, CancellationToken cancellationToken)
    {
        var items = await ListRecentAsync(1000, cancellationToken);
        return items.FirstOrDefault(x => string.Equals(x.MessageId, messageId, StringComparison.OrdinalIgnoreCase));
    }

    private static TelegramOutboundLogEntry? TryDeserialize(string line)
    {
        try
        {
            return JsonSerializer.Deserialize<TelegramOutboundLogEntry>(line);
        }
        catch
        {
            return null;
        }
    }
}
