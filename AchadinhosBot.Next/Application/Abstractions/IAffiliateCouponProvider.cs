namespace AchadinhosBot.Next.Application.Abstractions;

public interface IAffiliateCouponProvider
{
    string Store { get; }
    bool IsConfigured { get; }
    Task<IReadOnlyList<AffiliateCouponCandidate>> FetchAsync(CancellationToken cancellationToken);
}

public sealed record AffiliateCouponCandidate(
    string Code,
    string? Description,
    string? AffiliateLink,
    DateTimeOffset? StartsAt,
    DateTimeOffset? EndsAt,
    int? Priority,
    string? Source);
