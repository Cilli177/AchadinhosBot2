using AchadinhosBot.Next.Domain.Settings;

namespace AchadinhosBot.Next.Application.Abstractions;

public interface ICouponSelector
{
    Task<IReadOnlyList<AffiliateCoupon>> GetActiveCouponsAsync(string store, int maxCount, CancellationToken cancellationToken);
    string NormalizeStore(string store);
}
