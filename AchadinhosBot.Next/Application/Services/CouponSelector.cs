using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Domain.Settings;

namespace AchadinhosBot.Next.Application.Services;

public sealed class CouponSelector : ICouponSelector
{
    private readonly ISettingsStore _settingsStore;

    public CouponSelector(ISettingsStore settingsStore)
    {
        _settingsStore = settingsStore;
    }

    public async Task<IReadOnlyList<AffiliateCoupon>> GetActiveCouponsAsync(string store, int maxCount, CancellationToken cancellationToken)
    {
        var normalizedStore = NormalizeStore(store);
        if (string.IsNullOrWhiteSpace(normalizedStore))
        {
            return Array.Empty<AffiliateCoupon>();
        }

        var settings = await _settingsStore.GetAsync(cancellationToken);
        var hub = settings.CouponHub ?? new CouponHubSettings();
        if (!hub.Enabled || hub.Coupons.Count == 0)
        {
            return Array.Empty<AffiliateCoupon>();
        }

        var now = DateTimeOffset.UtcNow;
        var limit = Math.Clamp(maxCount, 1, 5);

        return hub.Coupons
            .Where(c => c.Enabled)
            .Where(c => NormalizeStore(c.Store) == normalizedStore)
            .Where(c => string.IsNullOrWhiteSpace(c.Code) == false)
            .Where(c => c.StartsAt is null || c.StartsAt <= now)
            .Where(c => c.EndsAt is null || c.EndsAt >= now)
            .OrderByDescending(c => c.Priority)
            .ThenBy(c => c.EndsAt ?? DateTimeOffset.MaxValue)
            .ThenByDescending(c => c.CreatedAt)
            .Take(limit)
            .ToArray();
    }

    public string NormalizeStore(string store)
    {
        var normalized = (store ?? string.Empty).Trim().ToLowerInvariant();
        return normalized switch
        {
            "amazon" => "amazon",
            "mercado livre" => "mercadolivre",
            "mercadolivre" => "mercadolivre",
            "meli" => "mercadolivre",
            "shein" => "shein",
            "shopee" => "shopee",
            _ => string.Empty
        };
    }
}
