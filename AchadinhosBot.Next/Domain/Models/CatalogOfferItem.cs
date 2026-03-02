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
    public string? ImageUrl { get; set; }
    public string? PriceText { get; set; }
    public string PostType { get; set; } = "feed";
    public bool Active { get; set; } = true;
    public DateTimeOffset PublishedAt { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset UpdatedAt { get; set; } = DateTimeOffset.UtcNow;
}

public sealed class CatalogSyncResult
{
    public int Created { get; set; }
    public int Updated { get; set; }
    public int Deactivated { get; set; }
    public int TotalActive { get; set; }
    public int HighestItemNumber { get; set; }
    public DateTimeOffset SyncedAt { get; set; } = DateTimeOffset.UtcNow;
}
