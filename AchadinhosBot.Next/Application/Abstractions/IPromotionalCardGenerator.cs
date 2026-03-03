namespace AchadinhosBot.Next.Application.Abstractions;

public interface IPromotionalCardGenerator
{
    Task<byte[]?> GenerateCardAsync(
        string productName,
        string currentPrice,
        string? previousPrice,
        string? discountPercent,
        string imageUrl,
        CancellationToken cancellationToken);
}
