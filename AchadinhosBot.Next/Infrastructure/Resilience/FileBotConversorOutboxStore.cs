using System.Text.Json;
using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Application.Consumers;
using AchadinhosBot.Next.Configuration;
using Microsoft.Extensions.Options;

namespace AchadinhosBot.Next.Infrastructure.Resilience;

public sealed class FileBotConversorOutboxStore : IBotConversorOutboxStore
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);
    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly string _directory;
    private readonly ILogger<FileBotConversorOutboxStore> _logger;

    public FileBotConversorOutboxStore(IOptions<MessagingOptions> options, ILogger<FileBotConversorOutboxStore> logger)
    {
        _logger = logger;
        _directory = Path.Combine(options.Value.ResolveDataDirectory(), "bot-conversor-outbox");
        Directory.CreateDirectory(_directory);
    }

    public async Task SaveAsync(ProcessBotConversorWebhookCommand command, CancellationToken cancellationToken)
    {
        var path = ResolvePath(command.MessageId);
        var tempPath = $"{path}.{Guid.NewGuid():N}.tmp";
        var json = JsonSerializer.Serialize(command, JsonOptions);

        await _gate.WaitAsync(cancellationToken);
        try
        {
            await File.WriteAllTextAsync(tempPath, json, cancellationToken);
            File.Move(tempPath, path, true);
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<IReadOnlyList<ProcessBotConversorWebhookCommand>> ListPendingAsync(CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken);
        try
        {
            var items = new List<ProcessBotConversorWebhookCommand>();
            foreach (var file in Directory.EnumerateFiles(_directory, "*.json").OrderBy(path => path, StringComparer.OrdinalIgnoreCase))
            {
                try
                {
                    var json = await File.ReadAllTextAsync(file, cancellationToken);
                    var item = JsonSerializer.Deserialize<ProcessBotConversorWebhookCommand>(json, JsonOptions);
                    if (item is not null && !string.IsNullOrWhiteSpace(item.MessageId))
                    {
                        items.Add(item);
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Falha ao ler item de outbox {File}", file);
                }
            }

            return items;
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task DeleteAsync(string messageId, CancellationToken cancellationToken)
    {
        var path = ResolvePath(messageId);

        await _gate.WaitAsync(cancellationToken);
        try
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
        finally
        {
            _gate.Release();
        }
    }

    private string ResolvePath(string messageId)
    {
        var safeMessageId = string.IsNullOrWhiteSpace(messageId) ? Guid.NewGuid().ToString("N") : messageId.Trim();
        return Path.Combine(_directory, $"{safeMessageId}.json");
    }
}
