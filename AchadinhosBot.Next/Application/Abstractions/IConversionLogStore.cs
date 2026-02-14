using AchadinhosBot.Next.Domain.Logs;

namespace AchadinhosBot.Next.Application.Abstractions;

public interface IConversionLogStore
{
    Task AppendAsync(ConversionLogEntry entry, CancellationToken cancellationToken);
    Task<IReadOnlyList<ConversionLogEntry>> QueryAsync(ConversionLogQuery query, CancellationToken cancellationToken);
    Task ClearAsync(CancellationToken cancellationToken);
}

public sealed class ConversionLogQuery
{
    public string? Store { get; set; }
    public string? Search { get; set; }
    public int Limit { get; set; } = 200;
}
