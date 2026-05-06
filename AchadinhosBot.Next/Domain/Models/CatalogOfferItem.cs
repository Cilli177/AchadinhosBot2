namespace AchadinhosBot.Next.Domain.Models;

public sealed class CatalogOfferItem
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public int ItemNumber { get; set; }
    public string Keyword { get; set; } = string.Empty;
    public string DraftId { get; set; } = string.Empty;
    public string ProductName { get; set; } = string.Empty;
    public string Store { get; set; } = "Loja";
    public string OfferUrl { get; set; } = string.Empty;
    public string? OriginalProductUrl { get; set; }
    public string? AffiliateTargetUrl { get; set; }
    public string? TrackingUrl { get; set; }
    public string? TrackingId { get; set; }
    public string AffiliateValidationStatus { get; set; } = CatalogAffiliateValidationStatuses.Pending;
    public string? AffiliateValidationError { get; set; }
    public DateTimeOffset? AffiliateValidatedAt { get; set; }
    public string? ImageUrl { get; set; }
    public List<string> SecondaryImageUrls { get; set; } = new();
    public string? PriceText { get; set; }
    public string PostType { get; set; } = "feed";
    public string CatalogTarget { get; set; } = CatalogTargets.Prod;
    public string? Niche { get; set; }
    public bool Active { get; set; } = true;
    public bool IsLightningDeal { get; set; }
    public DateTimeOffset? LightningDealExpiry { get; set; }
    public string? CouponCode { get; set; }
    public string? CouponDescription { get; set; }
    public DateTimeOffset PublishedAt { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset UpdatedAt { get; set; } = DateTimeOffset.UtcNow;
    /// <summary>Number of consecutive price-fetch failures. Resets to 0 when price is successfully fetched.</summary>
    public int PriceEnrichFailCount { get; set; }
    /// <summary>When set, the fast-retry scheduler will check this item at this time. Null = standard 12h cycle.</summary>
    public DateTimeOffset? NextPriceCheckAt { get; set; }
}

public static class CatalogAffiliateValidationStatuses
{
    public const string Pending = "pending";
    public const string Valid = "valid";
    public const string Invalid = "invalid";
}

public sealed class CatalogSyncResult
{
    public int Created { get; set; }
    public int Updated { get; set; }
    public int Deactivated { get; set; }
    public int TotalActive { get; set; }
    public int HighestItemNumber { get; set; }
    public CatalogLinkAuditResult? LinkAudit { get; set; }
    public DateTimeOffset SyncedAt { get; set; } = DateTimeOffset.UtcNow;
}

public sealed class CatalogLinkAuditResult
{
    public int TotalItems { get; set; }
    public int ActiveItems { get; set; }
    public int ValidTrackedItems { get; set; }
    public int ConvertedItems { get; set; }
    public int InvalidItems { get; set; }
    public int PendingItems { get; set; }
    public int DirectExternalItems { get; set; }
    public int SuspectedThirdPartyAffiliateItems { get; set; }
    public int BlockedItems { get; set; }
    public int RepairedItems { get; set; }
    public DateTimeOffset AuditedAt { get; set; } = DateTimeOffset.UtcNow;
    public List<CatalogLinkAuditItem> Items { get; set; } = new();
}

public sealed class CatalogLinkAuditItem
{
    public int ItemNumber { get; set; }
    public string DraftId { get; set; } = string.Empty;
    public string ProductName { get; set; } = string.Empty;
    public string Store { get; set; } = string.Empty;
    public bool Active { get; set; }
    public string Status { get; set; } = CatalogAffiliateValidationStatuses.Pending;
    public string? TrackingId { get; set; }
    public string? TrackingUrl { get; set; }
    public string? AffiliateTargetUrl { get; set; }
    public string? OriginalProductUrl { get; set; }
    public string? Error { get; set; }
    public bool DirectExternal { get; set; }
    public bool SuspectedThirdPartyAffiliate { get; set; }
}
