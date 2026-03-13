using System.Text.Json;
using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Domain.Logs;

namespace AchadinhosBot.Next.Infrastructure.Storage;

public sealed class WhatsAppOutboundLogStore : IWhatsAppOutboundLogStore
{
    private readonly string _path;
    private readonly SemaphoreSlim _mutex = new(1, 1);

    public WhatsAppOutboundLogStore()
    {
        _path = Path.Combine(AppContext.BaseDirectory, "data", "whatsapp-outbound-log.jsonl");
    }

    public async Task AppendAsync(WhatsAppOutboundLogEntry entry, CancellationToken cancellationToken)
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

    public async Task<IReadOnlyList<WhatsAppOutboundLogEntry>> ListRecentAsync(int limit, CancellationToken cancellationToken)
    {
        await _mutex.WaitAsync(cancellationToken);
        try
        {
            if (!File.Exists(_path))
            {
                return Array.Empty<WhatsAppOutboundLogEntry>();
            }

            var lines = await File.ReadAllLinesAsync(_path, cancellationToken);
            return lines
                .Where(x => !string.IsNullOrWhiteSpace(x))
                .Select(TryDeserialize)
                .Where(x => x is not null)
                .Cast<WhatsAppOutboundLogEntry>()
                .OrderByDescending(x => x.CreatedAtUtc)
                .Take(Math.Clamp(limit, 1, 1000))
                .ToArray();
        }
        finally
        {
            _mutex.Release();
        }
    }

    public async Task<WhatsAppOutboundLogEntry?> GetAsync(string messageId, CancellationToken cancellationToken)
    {
        var items = await ListRecentAsync(1000, cancellationToken);
        return items.FirstOrDefault(x => string.Equals(x.MessageId, messageId, StringComparison.OrdinalIgnoreCase));
    }

    private static WhatsAppOutboundLogEntry? TryDeserialize(string line)
    {
        try
        {
            return JsonSerializer.Deserialize<WhatsAppOutboundLogEntry>(line);
        }
        catch
        {
            return null;
        }
    }
}
