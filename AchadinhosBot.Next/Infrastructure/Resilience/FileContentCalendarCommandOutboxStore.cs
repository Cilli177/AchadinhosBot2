using System.Text.Json;
using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Application.Consumers;
using AchadinhosBot.Next.Configuration;
using Microsoft.Extensions.Options;
using AchadinhosBot.Next.Infrastructure.Storage;
using Microsoft.Extensions.Logging.Abstractions;

namespace AchadinhosBot.Next.Infrastructure.Resilience;

public sealed class FileContentCalendarCommandOutboxStore : IContentCalendarCommandOutboxStore
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);
    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly string _directory;
    private readonly InterprocessFileLock _interprocessLock;
    private readonly ILogger<FileContentCalendarCommandOutboxStore> _logger;

    public FileContentCalendarCommandOutboxStore(IOptions<MessagingOptions> options, ILogger<FileContentCalendarCommandOutboxStore>? logger = null)
        : this(Path.Combine(options.Value.ResolveDataDirectory(), "content-calendar-command-outbox"), logger)
    {
    }

    internal FileContentCalendarCommandOutboxStore(string directory, ILogger<FileContentCalendarCommandOutboxStore>? logger = null)
    {
        _directory = Path.GetFullPath(directory);
        Directory.CreateDirectory(_directory);
        _interprocessLock = new InterprocessFileLock(Path.Combine(_directory, "outbox"));
        _logger = logger ?? NullLogger<FileContentCalendarCommandOutboxStore>.Instance;
    }

    public async Task SaveAsync(ContentCalendarCommandEnvelope envelope, CancellationToken ct)
    {
        var messageId = NormalizeMessageId(envelope.MessageId);
        await _gate.WaitAsync(ct);
        try
        {
            await using var fileLock = await _interprocessLock.AcquireAsync(ct);
            var path = Path.Combine(_directory, $"{messageId}.json");
            var temporary = $"{path}.{Guid.NewGuid():N}.tmp";
            await File.WriteAllTextAsync(temporary, JsonSerializer.Serialize(envelope, JsonOptions), ct);
            File.Move(temporary, path, true);
        }
        finally { _gate.Release(); }
    }

    public async Task<IReadOnlyList<ContentCalendarCommandEnvelope>> ListPendingAsync(CancellationToken ct)
    {
        await _gate.WaitAsync(ct);
        try
        {
            await using var fileLock = await _interprocessLock.AcquireAsync(ct);
            var result = new List<ContentCalendarCommandEnvelope>();
            foreach (var path in Directory.EnumerateFiles(_directory, "*.json").OrderBy(x => x, StringComparer.OrdinalIgnoreCase))
            {
                try
                {
                    var item = JsonSerializer.Deserialize<ContentCalendarCommandEnvelope>(await File.ReadAllTextAsync(path, ct), JsonOptions);
                    if (item is null || !Guid.TryParse(item.MessageId, out _))
                        throw new InvalidDataException("Outbox envelope is invalid.");
                    result.Add(item);
                }
                catch (Exception exception) when (exception is JsonException or InvalidDataException)
                {
                    var quarantinedPath = path + ".invalid";
                    File.Move(path, quarantinedPath, overwrite: true);
                    _logger.LogError(exception, "Invalid content-calendar outbox envelope was quarantined as {QuarantinedPath}.", quarantinedPath);
                }
            }
            return result;
        }
        finally { _gate.Release(); }
    }

    public async Task DeleteAsync(string messageId, CancellationToken ct)
    {
        var normalizedMessageId = NormalizeMessageId(messageId);
        await _gate.WaitAsync(ct);
        try
        {
            await using var fileLock = await _interprocessLock.AcquireAsync(ct);
            var path = Path.Combine(_directory, $"{normalizedMessageId}.json");
            if (File.Exists(path)) File.Delete(path);
        }
        finally { _gate.Release(); }
    }

    private static string NormalizeMessageId(string messageId)
    {
        if (!Guid.TryParse(messageId, out var parsed))
            throw new ArgumentException("Outbox message id must be a GUID.", nameof(messageId));
        return parsed.ToString("D");
    }
}
