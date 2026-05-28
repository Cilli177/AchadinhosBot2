namespace AchadinhosBot.Next.Application.Abstractions;

public interface IAffiliateStoreConverter
{
    string Store { get; }
    bool CanConvert(Uri uri);
    Task<AffiliateLinkResult> ConvertAsync(Uri uri, CancellationToken cancellationToken, string? source = null, bool forceResolution = false);
}
