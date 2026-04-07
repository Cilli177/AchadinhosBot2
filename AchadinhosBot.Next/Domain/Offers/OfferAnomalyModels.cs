namespace AchadinhosBot.Next.Domain.Offers;

public sealed record OfferAnomaly(
    string AnomalyId,
    string OfferId,
    string CatalogTarget,
    int RiskScore,
    string Severity,
    string Summary,
    IReadOnlyList<string> Reasons,
    DateTimeOffset DetectedAtUtc);
