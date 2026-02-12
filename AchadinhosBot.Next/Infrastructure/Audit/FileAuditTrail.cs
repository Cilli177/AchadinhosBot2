using System.Text.Json;
using AchadinhosBot.Next.Application.Abstractions;

namespace AchadinhosBot.Next.Infrastructure.Audit;

public sealed class FileAuditTrail : IAuditTrail
{
    private readonly string _path;
    private readonly SemaphoreSlim _mutex = new(1, 1);

    public FileAuditTrail()
    {
        _path = Path.Combine(AppContext.BaseDirectory, "data", "audit.log");
    }

    public async Task WriteAsync(string action, string actor, object details, CancellationToken cancellationToken)
    {
        await _mutex.WaitAsync(cancellationToken);
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(_path)!);
            var record = new
            {
                ts = DateTimeOffset.UtcNow,
                action,
                actor,
                details
            };

            var line = JsonSerializer.Serialize(record) + Environment.NewLine;
            await File.AppendAllTextAsync(_path, line, cancellationToken);
        }
        finally
        {
            _mutex.Release();
        }
    }
}
