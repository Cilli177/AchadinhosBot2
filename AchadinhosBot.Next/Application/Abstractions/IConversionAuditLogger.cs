using AchadinhosBot.Next.Domain.Logs;

namespace AchadinhosBot.Next.Application.Abstractions;

public interface IConversionAuditLogger
{
    Task AppendAsync(ConversionLogEntry entry, CancellationToken cancellationToken);
}
