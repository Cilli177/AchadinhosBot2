namespace AchadinhosBot.Next.Domain.Models;

public sealed record ConversionResult(bool Success, string? ConvertedText, int ConvertedLinks, string Source);
