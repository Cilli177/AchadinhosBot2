using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Domain.Settings;

namespace AchadinhosBot.Next.Application.Services;

public sealed class AffiliateCouponSyncService : IAffiliateCouponSyncService
{
    private readonly IReadOnlyList<IAffiliateCouponProvider> _providers;
    private readonly ISettingsStore _settingsStore;
    private readonly ICouponSelector _couponSelector;
    private readonly ILogger<AffiliateCouponSyncService> _logger;

    public AffiliateCouponSyncService(
        IEnumerable<IAffiliateCouponProvider> providers,
        ISettingsStore settingsStore,
        ICouponSelector couponSelector,
        ILogger<AffiliateCouponSyncService> logger)
    {
        _providers = providers.ToArray();
        _settingsStore = settingsStore;
        _couponSelector = couponSelector;
        _logger = logger;
    }

    public async Task<AffiliateCouponSyncResult> SyncAsync(AffiliateCouponSyncRequest request, CancellationToken cancellationToken)
    {
        var normalizedFilter = _couponSelector.NormalizeStore(request.StoreFilter ?? string.Empty);
        var selectedProviders = _providers
            .Where(provider => string.IsNullOrWhiteSpace(normalizedFilter)
                               || _couponSelector.NormalizeStore(provider.Store) == normalizedFilter)
            .ToArray();

        if (selectedProviders.Length == 0)
        {
            return new AffiliateCouponSyncResult(
                false,
                "Nenhum provider encontrado para o filtro informado.",
                0,
                0,
                0,
                0,
                0,
                0,
                Array.Empty<AffiliateCouponProviderSyncOutcome>());
        }

        var settings = await _settingsStore.GetAsync(cancellationToken);
        settings.CouponHub ??= new CouponHubSettings();

        var outcomes = new List<AffiliateCouponProviderSyncOutcome>(selectedProviders.Length);
        var totalFetched = 0;
        var totalInserted = 0;
        var totalUpdated = 0;
        var totalIgnored = 0;
        var providersSucceeded = 0;
        var changed = false;

        foreach (var provider in selectedProviders)
        {
            if (!provider.IsConfigured)
            {
                outcomes.Add(new AffiliateCouponProviderSyncOutcome(
                    provider.Store,
                    false,
                    false,
                    "Provider sem configuracao de API oficial.",
                    0,
                    0,
                    0,
                    0));
                continue;
            }

            try
            {
                var fetchedCoupons = await provider.FetchAsync(cancellationToken);
                totalFetched += fetchedCoupons.Count;

                var inserted = 0;
                var updated = 0;
                var ignored = 0;

                foreach (var candidate in fetchedCoupons)
                {
                    var code = (candidate.Code ?? string.Empty).Trim();
                    if (string.IsNullOrWhiteSpace(code))
                    {
                        ignored++;
                        continue;
                    }

                    var existing = FindCoupon(settings.CouponHub.Coupons, provider.Store, code);
                    if (existing is null)
                    {
                        settings.CouponHub.Coupons.Add(new AffiliateCoupon
                        {
                            Id = Guid.NewGuid().ToString("N"),
                            Enabled = true,
                            Store = provider.Store,
                            Code = code,
                            Description = candidate.Description?.Trim() ?? string.Empty,
                            AffiliateLink = string.IsNullOrWhiteSpace(candidate.AffiliateLink) ? null : candidate.AffiliateLink.Trim(),
                            StartsAt = candidate.StartsAt,
                            EndsAt = candidate.EndsAt,
                            Priority = candidate.Priority ?? 100,
                            Source = ResolveSource(candidate.Source, provider.Store),
                            CreatedAt = DateTimeOffset.UtcNow
                        });

                        inserted++;
                        changed = true;
                        continue;
                    }

                    var updatedExisting = UpdateCoupon(existing, candidate, provider.Store);
                    if (updatedExisting)
                    {
                        updated++;
                        changed = true;
                    }
                    else
                    {
                        ignored++;
                    }
                }

                providersSucceeded++;
                totalInserted += inserted;
                totalUpdated += updated;
                totalIgnored += ignored;
                outcomes.Add(new AffiliateCouponProviderSyncOutcome(provider.Store, true, true, null, fetchedCoupons.Count, inserted, updated, ignored));
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Falha no sync oficial de cupons para {Store}", provider.Store);
                outcomes.Add(new AffiliateCouponProviderSyncOutcome(provider.Store, true, false, ex.Message, 0, 0, 0, 0));
            }
        }

        if (changed)
        {
            await _settingsStore.SaveAsync(settings, cancellationToken);
        }

        var success = providersSucceeded > 0;
        var message = success
            ? "Sync oficial concluido."
            : "Nao foi possivel sincronizar cupons oficiais.";

        return new AffiliateCouponSyncResult(
            success,
            message,
            selectedProviders.Length,
            providersSucceeded,
            totalFetched,
            totalInserted,
            totalUpdated,
            totalIgnored,
            outcomes);
    }

    private AffiliateCoupon? FindCoupon(List<AffiliateCoupon> coupons, string store, string code)
    {
        var normalizedStore = _couponSelector.NormalizeStore(store);
        return coupons.FirstOrDefault(x =>
            _couponSelector.NormalizeStore(x.Store) == normalizedStore &&
            x.Code.Equals(code, StringComparison.OrdinalIgnoreCase));
    }

    private static bool UpdateCoupon(AffiliateCoupon existing, AffiliateCouponCandidate candidate, string store)
    {
        var changed = false;
        var isManual = IsManualSource(existing.Source);
        if (!existing.Enabled)
        {
            existing.Enabled = true;
            changed = true;
        }

        if (!existing.Store.Equals(store, StringComparison.OrdinalIgnoreCase))
        {
            existing.Store = store;
            changed = true;
        }

        if (!isManual && !string.IsNullOrWhiteSpace(candidate.Description))
        {
            var description = candidate.Description.Trim();
            if (!existing.Description.Equals(description, StringComparison.Ordinal))
            {
                existing.Description = description;
                changed = true;
            }
        }
        else if (isManual && string.IsNullOrWhiteSpace(existing.Description) && !string.IsNullOrWhiteSpace(candidate.Description))
        {
            existing.Description = candidate.Description.Trim();
            changed = true;
        }

        if (!string.IsNullOrWhiteSpace(candidate.AffiliateLink))
        {
            var affiliateLink = candidate.AffiliateLink.Trim();
            if (string.IsNullOrWhiteSpace(existing.AffiliateLink) ||
                (!isManual && !existing.AffiliateLink.Equals(affiliateLink, StringComparison.Ordinal)))
            {
                existing.AffiliateLink = affiliateLink;
                changed = true;
            }
        }

        if (candidate.StartsAt.HasValue && (!existing.StartsAt.HasValue || !isManual))
        {
            if (existing.StartsAt != candidate.StartsAt)
            {
                existing.StartsAt = candidate.StartsAt;
                changed = true;
            }
        }

        if (candidate.EndsAt.HasValue && (!existing.EndsAt.HasValue || !isManual))
        {
            if (existing.EndsAt != candidate.EndsAt)
            {
                existing.EndsAt = candidate.EndsAt;
                changed = true;
            }
        }

        if (candidate.Priority.HasValue && !isManual && existing.Priority != candidate.Priority.Value)
        {
            existing.Priority = candidate.Priority.Value;
            changed = true;
        }

        var source = ResolveSource(candidate.Source, store);
        if (!isManual && !existing.Source.Equals(source, StringComparison.OrdinalIgnoreCase))
        {
            existing.Source = source;
            changed = true;
        }

        return changed;
    }

    private static bool IsManualSource(string source)
        => source.Equals("manual", StringComparison.OrdinalIgnoreCase)
           || source.StartsWith("manual:", StringComparison.OrdinalIgnoreCase);

    private static string ResolveSource(string? source, string store)
        => string.IsNullOrWhiteSpace(source)
            ? $"official:{store.ToLowerInvariant().Replace(" ", string.Empty, StringComparison.Ordinal)}"
            : source.Trim();
}
