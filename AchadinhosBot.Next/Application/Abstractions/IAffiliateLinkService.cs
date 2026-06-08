namespace AchadinhosBot.Next.Application.Abstractions;

public interface IAffiliateLinkService
{
    Task<AffiliateLinkResult> ConvertAsync(string rawUrl, CancellationToken cancellationToken, string? source = null, bool forceResolution = false);
}

public sealed record AffiliateLinkResult(
    bool Success,
    string? ConvertedUrl,
    string Store,
    bool IsAffiliated,
    string? ValidationError,
    string? Error,
    bool CorrectionApplied,
    string? CorrectionNote)
{
    public string? EnrichmentUrl { get; init; }
}
