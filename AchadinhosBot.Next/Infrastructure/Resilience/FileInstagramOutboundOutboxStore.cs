using System.Text.Json;
using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Application.Consumers;
using AchadinhosBot.Next.Configuration;
using Microsoft.Extensions.Options;

namespace AchadinhosBot.Next.Infrastructure.Resilience;

public sealed class FileInstagramOutboundOutboxStore : IInstagramOutboundOutboxStore
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);
    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly string _directory;

    public FileInstagramOutboundOutboxStore(IOptions<MessagingOptions> options)
    {
        _directory = Path.Combine(options.Value.ResolveDataDirectory(), "instagram-outbox");
        Directory.CreateDirectory(_directory);
    }

    public async Task SaveAsync(InstagramOutboundEnvelope envelope, CancellationToken cancellationToken)
    {
        var path = ResolvePath(envelope.MessageId);
        var tempPath = $"{path}.{Guid.NewGuid():N}.tmp";
        var json = JsonSerializer.Serialize(envelope, JsonOptions);

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

    public async Task<IReadOnlyList<InstagramOutboundEnvelope>> ListPendingAsync(CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken);
        try
        {
            var items = new List<InstagramOutboundEnvelope>();
            foreach (var file in Directory.EnumerateFiles(_directory, "*.json").OrderBy(path => path, StringComparer.OrdinalIgnoreCase))
            {
                var json = await File.ReadAllTextAsync(file, cancellationToken);
                var item = JsonSerializer.Deserialize<InstagramOutboundEnvelope>(json, JsonOptions);
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
