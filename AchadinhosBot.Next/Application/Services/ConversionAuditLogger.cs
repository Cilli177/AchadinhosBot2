using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Domain.Logs;

namespace AchadinhosBot.Next.Application.Services;

public sealed class ConversionAuditLogger : IConversionAuditLogger
{
    private readonly IConversionLogStore _store;
    private readonly ILogger<ConversionAuditLogger> _logger;

    public ConversionAuditLogger(IConversionLogStore store, ILogger<ConversionAuditLogger> logger)
    {
        _store = store;
        _logger = logger;
    }

    public async Task AppendAsync(ConversionLogEntry entry, CancellationToken cancellationToken)
    {
        try
        {
            await _store.AppendAsync(entry, cancellationToken);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogError(
                ex,
                "Falha ao gravar auditoria de conversao. Source={Source} Store={Store} OriginalHost={OriginalHost} ConvertedHost={ConvertedHost} Success={Success}",
                entry.Source,
                entry.Store,
                OfferUrlExtractor.TryGetSafeHost(entry.OriginalUrl),
                OfferUrlExtractor.TryGetSafeHost(entry.ConvertedUrl),
                entry.Success);
        }
    }
}
