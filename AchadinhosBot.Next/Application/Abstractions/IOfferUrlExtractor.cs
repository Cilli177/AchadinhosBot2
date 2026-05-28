namespace AchadinhosBot.Next.Application.Abstractions;

public interface IOfferUrlExtractor
{
    IReadOnlyList<OfferUrlCandidate> Extract(string input);
}

public sealed record OfferUrlCandidate(
    string Raw,
    string CleanedUrl,
    string Prefix,
    string Suffix,
    int Index,
    int Length,
    bool IsBlocked,
    bool ShouldConvert);
