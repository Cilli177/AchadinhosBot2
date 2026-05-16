namespace AchadinhosBot.Next.Domain.Offers;

public static class OfferNormalizationTargets
{
    public const string Review = "review";
    public const string Catalog = "catalog";
    public const string Queue = "queue";

    public static string Normalize(string? value)
    {
        var normalized = (value ?? string.Empty).Trim().ToLowerInvariant();
        return normalized switch
        {
            Catalog => Catalog,
            Queue => Queue,
            _ => Review
        };
    }
}

public static class OfferNormalizationStatuses
{
    public const string Normalized = "normalized";
    public const string ReviewRequired = "review_required";
    public const string SentToCatalog = "sent_to_catalog";
    public const string QueuedForAutomation = "queued_for_automation";
    public const string Failed = "failed";

    public static string FromTarget(string target)
        => OfferNormalizationTargets.Normalize(target) switch
        {
            OfferNormalizationTargets.Catalog => SentToCatalog,
            OfferNormalizationTargets.Queue => QueuedForAutomation,
            _ => ReviewRequired
        };
}

public sealed class CanonicalOfferRecord
{
    public string Source { get; set; } = string.Empty;
    public string ProductName { get; set; } = string.Empty;
    public string ProductUrl { get; set; } = string.Empty;
    public decimal? OriginalPrice { get; set; }
    public decimal? PromoPrice { get; set; }
    public decimal? DiscountPercent { get; set; }
    public string StoreName { get; set; } = string.Empty;
    public string Category { get; set; } = string.Empty;
    public string CommissionRaw { get; set; } = string.Empty;
    public Dictionary<string, string?> ExtraFields { get; set; } = new(StringComparer.OrdinalIgnoreCase);
}

public sealed class OfferNormalizationIssue
{
    public string Level { get; set; } = "warn";
    public string Message { get; set; } = string.Empty;
    public int? RowNumber { get; set; }
    public string? Field { get; set; }
}

public sealed class OfferNormalizationRun
{
    public string Id { get; set; } = Guid.NewGuid().ToString("n");
    public DateTimeOffset CreatedAtUtc { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset UpdatedAtUtc { get; set; } = DateTimeOffset.UtcNow;
    public string SourceType { get; set; } = "autodetect";
    public string InputPreview { get; set; } = string.Empty;
    public List<CanonicalOfferRecord> NormalizedOffers { get; set; } = [];
    public List<OfferNormalizationIssue> ValidationIssues { get; set; } = [];
    public string SelectedTarget { get; set; } = OfferNormalizationTargets.Review;
    public string Status { get; set; } = OfferNormalizationStatuses.Normalized;
    public string Operator { get; set; } = "unknown";
    public string? Notes { get; set; }
    public string Summary { get; set; } = string.Empty;
    public string NextStepHint { get; set; } = string.Empty;
    public OfferNormalizationDeliveryReference? AssistedDelivery { get; set; }
}

public sealed class OfferNormalizationDeliveryReference
{
    public string Kind { get; set; } = OfferNormalizationTargets.Review;
    public string Status { get; set; } = OfferNormalizationStatuses.ReviewRequired;
    public string Summary { get; set; } = string.Empty;
    public string? TargetScope { get; set; }
    public DateTimeOffset UpdatedAtUtc { get; set; } = DateTimeOffset.UtcNow;
    public List<string> ReferenceIds { get; set; } = [];
}

public sealed class OfferAutomationIntent
{
    public string Id { get; set; } = Guid.NewGuid().ToString("n");
    public string NormalizationRunId { get; set; } = string.Empty;
    public DateTimeOffset CreatedAtUtc { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset UpdatedAtUtc { get; set; } = DateTimeOffset.UtcNow;
    public string Status { get; set; } = "prepared";
    public string Operator { get; set; } = "unknown";
    public int OfferCount { get; set; }
    public string Summary { get; set; } = string.Empty;
    public string? Notes { get; set; }
}
