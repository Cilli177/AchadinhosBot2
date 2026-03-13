using System.Text.Json;
using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Domain.Agents;

namespace AchadinhosBot.Next.Infrastructure.Storage;

public sealed class WhatsAppAgentMemoryStore : IWhatsAppAgentMemoryStore
{
    private readonly string _path;
    private readonly SemaphoreSlim _mutex = new(1, 1);

    public WhatsAppAgentMemoryStore()
    {
        _path = Path.Combine(AppContext.BaseDirectory, "data", "whatsapp-agent-memory.jsonl");
    }

    public async Task AppendAsync(WhatsAppAgentMemoryEntry entry, CancellationToken cancellationToken)
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

    public async Task<IReadOnlyDictionary<string, WhatsAppAgentMemoryEntry>> GetLatestByMessageIdsAsync(IEnumerable<string> messageIds, CancellationToken cancellationToken)
    {
        var ids = messageIds
            .Where(x => !string.IsNullOrWhiteSpace(x))
            .Select(x => x.Trim())
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        if (ids.Count == 0)
        {
            return new Dictionary<string, WhatsAppAgentMemoryEntry>(StringComparer.OrdinalIgnoreCase);
        }

        await _mutex.WaitAsync(cancellationToken);
        try
        {
            if (!File.Exists(_path))
            {
                return new Dictionary<string, WhatsAppAgentMemoryEntry>(StringComparer.OrdinalIgnoreCase);
            }

            var lines = await File.ReadAllLinesAsync(_path, cancellationToken);
            return lines
                .Where(x => !string.IsNullOrWhiteSpace(x))
                .Select(TryDeserialize)
                .Where(x => x is not null)
                .Cast<WhatsAppAgentMemoryEntry>()
                .Where(x => ids.Contains(x.MessageId))
                .OrderByDescending(x => x.CreatedAtUtc)
                .GroupBy(x => x.MessageId, StringComparer.OrdinalIgnoreCase)
                .ToDictionary(g => g.Key, g => g.First(), StringComparer.OrdinalIgnoreCase);
        }
        finally
        {
            _mutex.Release();
        }
    }

    private static WhatsAppAgentMemoryEntry? TryDeserialize(string line)
    {
        try
        {
            return JsonSerializer.Deserialize<WhatsAppAgentMemoryEntry>(line);
        }
        catch
        {
            return null;
        }
    }
}
