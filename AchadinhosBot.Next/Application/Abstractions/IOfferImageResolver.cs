namespace AchadinhosBot.Next.Application.Abstractions;

public interface IOfferImageResolver
{
    Task<OfferImageResolutionResult> ResolveAsync(OfferImageResolutionRequest request, CancellationToken cancellationToken);
}

public sealed record OfferImageResolutionRequest(
    string? OriginalUrl,
    string? ConvertedUrl,
    string? OfferText,
    string? Store,
    string? PreferredImageUrl);

public sealed record OfferImageResolutionResult(
    bool Success,
    string? ResolvedImageUrl,
    byte[]? ResolvedImageBytes,
    string? MimeType,
    string Source,
    string? FailureReason,
    IReadOnlyList<string> Diagnostics)
{
    public static OfferImageResolutionResult Failure(string failureReason, IReadOnlyList<string>? diagnostics = null, string source = "resolver")
        => new(false, null, null, null, source, failureReason, diagnostics ?? Array.Empty<string>());

    public static OfferImageResolutionResult SuccessFromUrl(
        string imageUrl,
        string source,
        IReadOnlyList<string>? diagnostics = null,
        string? mimeType = null)
        => new(true, imageUrl, null, mimeType, source, null, diagnostics ?? Array.Empty<string>());

    public static OfferImageResolutionResult SuccessFromBytes(
        byte[] imageBytes,
        string mimeType,
        string source,
        IReadOnlyList<string>? diagnostics = null)
        => new(true, null, imageBytes, mimeType, source, null, diagnostics ?? Array.Empty<string>());
}
