namespace AchadinhosBot.Next.Application.Abstractions;

public interface IStoreImageScraper
{
    string Store { get; }

    Task<OfferImageResolutionResult?> TryResolveAsync(OfferImageResolutionRequest request, CancellationToken cancellationToken);
}
