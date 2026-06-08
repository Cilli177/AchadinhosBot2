using System.Text.Json;
using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Domain.Logs;

namespace AchadinhosBot.Next.Infrastructure.Storage;

public sealed class WhatsAppParticipantBlastProgressStore : IWhatsAppParticipantBlastProgressStore
{
    private readonly string _path;
    private readonly SemaphoreSlim _mutex = new(1, 1);

    public WhatsAppParticipantBlastProgressStore()
    {
        _path = Path.Combine(AppContext.BaseDirectory, "data", "whatsapp-participant-blast-progress.jsonl");
    }

    public async Task AppendAsync(WhatsAppParticipantBlastProgressEntry entry, CancellationToken cancellationToken)
    {
        await _mutex.WaitAsync(cancellationToken);
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(_path)!);
            await using var stream = new FileStream(_path, FileMode.Append, FileAccess.Write, FileShare.Read);
            await using var writer = new StreamWriter(stream);
            await writer.WriteLineAsync(JsonSerializer.Serialize(entry));
            await writer.FlushAsync();
            await JsonlLogRetention.TrimIfNeededAsync(_path, 15000, 8 * 1024 * 1024, cancellationToken);
        }
        finally
        {
            _mutex.Release();
        }
    }

    public async Task<IReadOnlyList<WhatsAppParticipantBlastProgressEntry>> ListAsync(string? operationId, int limit, CancellationToken cancellationToken)
    {
        var entries = new List<WhatsAppParticipantBlastProgressEntry>();
        if (!File.Exists(_path))
        {
            return entries;
        }

        await _mutex.WaitAsync(cancellationToken);
        try
        {
            await using var stream = File.OpenRead(_path);
            using var reader = new StreamReader(stream);
            while (!reader.EndOfStream)
            {
                var line = await reader.ReadLineAsync();
                if (string.IsNullOrWhiteSpace(line))
                {
                    continue;
                }

                try
                {
                    var entry = JsonSerializer.Deserialize<WhatsAppParticipantBlastProgressEntry>(line);
                    if (entry is not null)
                    {
                        entries.Add(entry);
                    }
                }
                catch
                {
                    // ignora linhas ruins
                }
            }
        }
        finally
        {
            _mutex.Release();
        }

        var filtered = string.IsNullOrWhiteSpace(operationId)
            ? entries
            : entries.Where(x => string.Equals(x.OperationId, operationId.Trim(), StringComparison.OrdinalIgnoreCase)).ToList();

        return filtered
            .OrderByDescending(x => x.Timestamp)
            .Take(Math.Clamp(limit, 1, 2000))
            .ToArray();
    }

    public async Task ClearAsync(CancellationToken cancellationToken)
    {
        await _mutex.WaitAsync(cancellationToken);
        try
        {
            if (File.Exists(_path))
            {
                File.WriteAllText(_path, string.Empty);
            }
        }
        finally
        {
            _mutex.Release();
        }
    }
}
