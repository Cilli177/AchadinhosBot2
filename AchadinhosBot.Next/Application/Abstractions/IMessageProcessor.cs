using AchadinhosBot.Next.Domain.Models;

namespace AchadinhosBot.Next.Application.Abstractions;

public interface IMessageProcessor
{
    Task<AchadinhosBot.Next.Domain.Models.ConversionResult> ProcessAsync(
        string input,
        string source,
        CancellationToken cancellationToken,
        long? originChatId = null,
        long? destinationChatId = null,
        string? originChatRef = null,
        string? destinationChatRef = null,
        string? sourceImageUrl = null);
    Task<(string EnrichedText, string? ProductImageUrl, string? ProductVideoUrl)> EnrichTextWithProductDataAsync(
        string convertedText,
        string originalText,
        CancellationToken cancellationToken);
}

// Removing duplicate ConversionResult here since it's already in Domain.Models
