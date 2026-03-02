namespace AchadinhosBot.Next.Application.Abstractions;

public interface IAffiliateCouponSyncService
{
    Task<AffiliateCouponSyncResult> SyncAsync(AffiliateCouponSyncRequest request, CancellationToken cancellationToken);
}

public sealed record AffiliateCouponSyncRequest(string? StoreFilter);

public sealed record AffiliateCouponSyncResult(
    bool Success,
    string Message,
    int ProvidersAttempted,
    int ProvidersSucceeded,
    int TotalFetched,
    int TotalInserted,
    int TotalUpdated,
    int TotalIgnored,
    IReadOnlyList<AffiliateCouponProviderSyncOutcome> Providers);

public sealed record AffiliateCouponProviderSyncOutcome(
    string Store,
    bool Configured,
    bool Success,
    string? Error,
    int Fetched,
    int Inserted,
    int Updated,
    int Ignored);
