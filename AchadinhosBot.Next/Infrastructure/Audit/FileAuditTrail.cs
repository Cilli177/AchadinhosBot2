using System.Text.Json;
using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Infrastructure.Monitoring;

namespace AchadinhosBot.Next.Infrastructure.Audit;

public sealed class FileAuditTrail : IAuditTrail
{
    private readonly string _path;
    private readonly SemaphoreSlim _mutex = new(1, 1);
    private readonly IHttpContextAccessor? _httpContextAccessor;

    public FileAuditTrail(IHttpContextAccessor? httpContextAccessor = null)
    {
        _httpContextAccessor = httpContextAccessor;
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
                requestId = _httpContextAccessor?.HttpContext?.TraceIdentifier,
                correlationId = _httpContextAccessor?.HttpContext?.Response.Headers[RequestCorrelationMiddleware.CorrelationHeaderName].ToString(),
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
