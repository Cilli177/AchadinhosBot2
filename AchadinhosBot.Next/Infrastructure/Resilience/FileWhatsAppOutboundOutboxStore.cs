using System.Text.Json;
using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Application.Consumers;
using AchadinhosBot.Next.Configuration;
using Microsoft.Extensions.Options;

namespace AchadinhosBot.Next.Infrastructure.Resilience;

public sealed class FileWhatsAppOutboundOutboxStore : IWhatsAppOutboundOutboxStore
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);
    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly string _directory;

    public FileWhatsAppOutboundOutboxStore(IOptions<MessagingOptions> options)
    {
        _directory = Path.Combine(options.Value.ResolveDataDirectory(), "whatsapp-outbox");
        Directory.CreateDirectory(_directory);
    }

    public async Task SaveAsync(SendWhatsAppMessageCommand command, CancellationToken cancellationToken)
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

    public async Task<IReadOnlyList<SendWhatsAppMessageCommand>> ListPendingAsync(CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken);
        try
        {
            var items = new List<SendWhatsAppMessageCommand>();
            foreach (var file in Directory.EnumerateFiles(_directory, "*.json").OrderBy(path => path, StringComparer.OrdinalIgnoreCase))
            {
                var json = await File.ReadAllTextAsync(file, cancellationToken);
                var item = JsonSerializer.Deserialize<SendWhatsAppMessageCommand>(json, JsonOptions);
                if (item is not null)
                {
                    items.Add(item);
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
        return Path.Combine(_directory, $"{messageId.Trim()}.json");
    }
}
