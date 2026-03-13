namespace AchadinhosBot.Next.Domain.Instagram;

public sealed class InstagramPublishDraft
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
    public string PostType { get; set; } = "feed";
    public string ProductName { get; set; } = string.Empty;
    public string Caption { get; set; } = string.Empty;
    public string? OfferUrl { get; set; }
    public List<string> CaptionOptions { get; set; } = new();
    public int SelectedCaptionIndex { get; set; } = 1;
    public string Hashtags { get; set; } = string.Empty;
    public string? VideoUrl { get; set; }
    public string? VideoCoverUrl { get; set; }
    public double? VideoCoverAtSeconds { get; set; }
    public string? VideoMusicCue { get; set; }
    public double? VideoTrimStartSeconds { get; set; }
    public double? VideoTrimEndSeconds { get; set; }
    public string? MusicTrackUrl { get; set; }
    public double? MusicStartSeconds { get; set; }
    public double? MusicEndSeconds { get; set; }
    public double? MusicVolume { get; set; }
    public double? OriginalAudioVolume { get; set; }
    public List<string> ImageUrls { get; set; } = new();
    public List<int> SelectedImageIndexes { get; set; } = new();
    public List<InstagramCtaOption> Ctas { get; set; } = new();
    public bool AutoReplyEnabled { get; set; }
    public string? AutoReplyKeyword { get; set; }
    public string? AutoReplyMessage { get; set; }
    public string? AutoReplyLink { get; set; }
    public string? Store { get; set; }
    public string? CurrentPrice { get; set; }
    public string? PreviousPrice { get; set; }
    public int? DiscountPercent { get; set; }
    public string? EstimatedDelivery { get; set; }
    public bool IsLightningDeal { get; set; }
    public DateTimeOffset? LightningDealExpiry { get; set; }
    public string? CouponCode { get; set; }
    public string? CouponDescription { get; set; }
    public string? SourceDataOrigin { get; set; }
    public List<string> SuggestedImageUrls { get; set; } = new();
    public List<string> SuggestedVideoUrls { get; set; } = new();
    public DateTimeOffset? ScheduledFor { get; set; }
    public bool SendToCatalog { get; set; }
    public string CatalogTarget { get; set; } = "none";
    public bool CatalogIntentLocked { get; set; }
    public bool IsBioHighlighted { get; set; }
    public DateTimeOffset? BioHighlightedAt { get; set; }
    public string Status { get; set; } = "draft";
    public string? MediaId { get; set; }
    public string? Error { get; set; }
}
