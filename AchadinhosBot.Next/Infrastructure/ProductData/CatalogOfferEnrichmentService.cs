using AchadinhosBot.Next.Application.Abstractions;

namespace AchadinhosBot.Next.Infrastructure.ProductData;

public sealed class CatalogOfferEnrichmentService : ICatalogOfferEnrichmentService
{
    private readonly OfficialProductDataService _officialProductDataService;

    public CatalogOfferEnrichmentService(OfficialProductDataService officialProductDataService)
    {
        _officialProductDataService = officialProductDataService;
    }

    public async Task<CatalogOfferEnrichment?> TryEnrichAsync(string offerUrl, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(offerUrl))
        {
            return null;
        }

        var official = await _officialProductDataService.TryGetBestAsync(offerUrl, null, cancellationToken);
        if (official is null)
        {
            return null;
        }

        return new CatalogOfferEnrichment(
            official.CurrentPrice,
            official.IsLightningDeal,
            official.LightningDealExpiry,
            official.CouponCode,
            official.CouponDescription);
    }
}
