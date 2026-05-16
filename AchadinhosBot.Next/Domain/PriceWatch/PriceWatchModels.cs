namespace AchadinhosBot.Next.Domain.PriceWatch;

public static class PriceWatchStatuses
{
    public const string Active = "active";
    public const string Paused = "paused";
    public const string PendingReview = "pending_review";
    public const string Stopped = "stopped";
}

public static class PriceWatchSourceTypes
{
    public const string Link = "link";
    public const string Catalog = "catalog";
    public const string Search = "search";
}

public sealed class PriceWatchItem
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public string ContactJid { get; set; } = string.Empty;
    public string? ContactName { get; set; }
    public string? InstanceName { get; set; }
    public string SourceType { get; set; } = PriceWatchSourceTypes.Link;
    public string? ProductUrl { get; set; }
    public string? CatalogQuery { get; set; }
    public string? SearchTerm { get; set; }
    public string? ProductName { get; set; }
    public string? Store { get; set; }
    public decimal? DesiredPrice { get; set; }
    public bool AcceptSimilarProducts { get; set; }
    public decimal NearTargetPercent { get; set; } = 5m;
    public int IntervalHours { get; set; } = 12;
    public string Status { get; set; } = PriceWatchStatuses.Active;
    public string OptInSource { get; set; } = "admin";
    public decimal? LastFoundPrice { get; set; }
    public string? LastFoundPriceText { get; set; }
    public DateTimeOffset? LastFoundAt { get; set; }
    public decimal? LastSentPrice { get; set; }
    public string? LastSentPriceText { get; set; }
    public DateTimeOffset? LastSentAt { get; set; }
    public string? LastOfferUrl { get; set; }
    public string? LastAffiliateUrl { get; set; }
    public string? LastTrackingUrl { get; set; }
    public string? LastTrackingId { get; set; }
    public DateTimeOffset NextCheckAt { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset UpdatedAt { get; set; } = DateTimeOffset.UtcNow;
    public int ConsecutiveFailures { get; set; }
    public string? LastError { get; set; }
}

public sealed class PriceWatchReviewItem
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public string WatchId { get; set; } = string.Empty;
    public string Status { get; set; } = "pending";
    public string Reason { get; set; } = string.Empty;
    public string? CandidateProductName { get; set; }
    public string? CandidateUrl { get; set; }
    public string? CandidateStore { get; set; }
    public decimal? CandidatePrice { get; set; }
    public string? CandidatePriceText { get; set; }
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset? DecidedAt { get; set; }
}

public sealed record PriceWatchCreateRequest(
    string ContactJid,
    string? ProductUrl = null,
    string? CatalogQuery = null,
    string? SearchTerm = null,
    decimal? DesiredPrice = null,
    int? IntervalHours = null,
    string? InstanceName = null,
    string? ContactName = null,
    bool AcceptSimilarProducts = false,
    decimal? NearTargetPercent = null);

public sealed record PriceWatchRunResult(
    bool Success,
    string WatchId,
    bool Sent,
    bool ReviewCreated,
    string Message,
    decimal? CurrentPrice = null,
    decimal? PreviousSentPrice = null,
    string? TrackingUrl = null,
    string? Error = null);

public sealed record PriceWatchCandidate(
    string? ProductName,
    string? Store,
    string OfferUrl,
    decimal? Price,
    string? PriceText,
    double Confidence,
    string MatchReason);
