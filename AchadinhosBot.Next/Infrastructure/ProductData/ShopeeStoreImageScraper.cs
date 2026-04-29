using AchadinhosBot.Next.Application.Abstractions;

namespace AchadinhosBot.Next.Infrastructure.ProductData;

public sealed class ShopeeStoreImageScraper : IStoreImageScraper
{
    private readonly OfficialProductDataService _officialProductDataService;

    public ShopeeStoreImageScraper(OfficialProductDataService officialProductDataService)
    {
        _officialProductDataService = officialProductDataService;
    }

    public string Store => "Shopee";

    public async Task<OfferImageResolutionResult?> TryResolveAsync(OfferImageResolutionRequest request, CancellationToken cancellationToken)
    {
        var originalUrl = request.OriginalUrl ?? request.ConvertedUrl;
        if (string.IsNullOrWhiteSpace(originalUrl))
        {
            return OfferImageResolutionResult.Failure("store_api_failed", new[] { "shopee_official=no_url" }, "shopee_official");
        }

        var official = await _officialProductDataService.TryGetBestAsync(originalUrl, request.ConvertedUrl, cancellationToken);
        var imageUrl = official?.Images?.FirstOrDefault(static x => !string.IsNullOrWhiteSpace(x));
        if (string.IsNullOrWhiteSpace(imageUrl))
        {
            return OfferImageResolutionResult.Failure("store_api_failed", new[] { "shopee_official=no_image" }, "shopee_official");
        }

        return OfferImageResolutionResult.SuccessFromUrl(imageUrl, $"shopee_official:{official!.DataSource}", new[] { "shopee_official=ok" });
    }
}
