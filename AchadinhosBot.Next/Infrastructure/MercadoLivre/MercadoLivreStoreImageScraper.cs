using AchadinhosBot.Next.Application.Abstractions;

namespace AchadinhosBot.Next.Infrastructure.MercadoLivre;

public sealed class MercadoLivreStoreImageScraper : IStoreImageScraper
{
    private readonly MercadoLivreHtmlScraperService _mercadoLivreHtmlScraperService;

    public MercadoLivreStoreImageScraper(MercadoLivreHtmlScraperService mercadoLivreHtmlScraperService)
    {
        _mercadoLivreHtmlScraperService = mercadoLivreHtmlScraperService;
    }

    public string Store => "Mercado Livre";

    public async Task<OfferImageResolutionResult?> TryResolveAsync(OfferImageResolutionRequest request, CancellationToken cancellationToken)
    {
        var candidateUrl = !string.IsNullOrWhiteSpace(request.ConvertedUrl)
            ? request.ConvertedUrl
            : request.OriginalUrl;
        if (string.IsNullOrWhiteSpace(candidateUrl))
        {
            return OfferImageResolutionResult.Failure("store_scraper_failed", new[] { "mercadolivre_scraper=no_url" }, "mercadolivre_scraper");
        }

        var scraped = await _mercadoLivreHtmlScraperService.ScrapeUrlAsync(candidateUrl, cancellationToken);
        var imageUrl = scraped?.Images?.FirstOrDefault(static x => !string.IsNullOrWhiteSpace(x));
        if (string.IsNullOrWhiteSpace(imageUrl))
        {
            return OfferImageResolutionResult.Failure("store_scraper_failed", new[] { "mercadolivre_scraper=no_image" }, "mercadolivre_scraper");
        }

        return OfferImageResolutionResult.SuccessFromUrl(imageUrl, "mercadolivre_scraper", new[] { "mercadolivre_scraper=ok" });
    }
}
