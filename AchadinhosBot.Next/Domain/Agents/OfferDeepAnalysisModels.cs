namespace AchadinhosBot.Next.Domain.Agents;

public sealed class ChannelOfferDeepAnalysisRequest
{
    public string MessageId { get; set; } = string.Empty;
    public string SourceChannel { get; set; } = "telegram";
    public bool CreateDraft { get; set; } = true;
    public bool UseAiReasoning { get; set; } = true;
    public AchadinhosBot.Next.Domain.Settings.AutomationSettings? OverrideSettings { get; set; }
}

public sealed class ChannelOfferDeepAnalysisResult
{
    public string SourceChannel { get; set; } = "telegram";
    public string MessageId { get; set; } = string.Empty;
    public string DecisionSource { get; set; } = "ai_deep";
    public string RecommendedAction { get; set; } = WhatsAppOfferScoutActions.Review;
    public string ProductName { get; set; } = string.Empty;
    public string OfferUrl { get; set; } = string.Empty;
    public string? SelectedOfferUrlReason { get; set; }
    public string? OriginalSelectedOfferUrl { get; set; }
    public bool OfferUrlWasConverted { get; set; }
    public string? OfferUrlConversionNote { get; set; }
    public List<string> CandidateUrls { get; set; } = new();
    public string? Store { get; set; }
    public string? CurrentPrice { get; set; }
    public string? PreviousPrice { get; set; }
    public int? DiscountPercent { get; set; }
    public bool IsLightningDeal { get; set; }
    public DateTimeOffset? LightningDealExpiry { get; set; }
    public string? EstimatedDelivery { get; set; }
    public string? CouponCode { get; set; }
    public string? CouponDescription { get; set; }
    public string? DataSource { get; set; }
    public int UrlSelectionConfidence { get; set; }
    public int DataQualityScore { get; set; }
    public bool ScraperFallbackApplied { get; set; }
    public List<string> FallbacksUsed { get; set; } = new();
    public string SuggestedPostType { get; set; } = WhatsAppOfferScoutPostTypes.Feed;
    public string SuggestedKeyword { get; set; } = string.Empty;
    public int Score { get; set; }
    public int InstagramScore { get; set; }
    public int CatalogScore { get; set; }
    public string? PrimaryImageUrl { get; set; }
    public string? PrimaryVideoUrl { get; set; }
    public List<string> ImageUrls { get; set; } = new();
    public List<string> VideoUrls { get; set; } = new();
    public List<OfferMediaInsight> MediaInsights { get; set; } = new();
    public List<string> CaptionOptions { get; set; } = new();
    public string Caption { get; set; } = string.Empty;
    public string Hashtags { get; set; } = string.Empty;
    public List<string> CtaKeywords { get; set; } = new();
    public List<string> Reasons { get; set; } = new();
    public List<string> Risks { get; set; } = new();
    public string? AiReasoning { get; set; }
    public string SourceText { get; set; } = string.Empty;
    public string? DraftId { get; set; }
    public string? EditorUrl { get; set; }
    public string? PreviewMessage { get; set; }
    public bool SendToCatalog { get; set; }
    public string? CatalogTarget { get; set; }
    public string? AutoReplyMessage { get; set; }
    public string? SourceDataOrigin { get; set; }
    public string OfferType { get; set; } = "catalog";
    public string? LastOperatorFeedback { get; set; }
    public string? LastOperatorNote { get; set; }
    public string? LastAppliedAction { get; set; }
    public string? LastOutcome { get; set; }
    public DateTimeOffset? LastDecisionAt { get; set; }
}

public sealed class OfferMediaInsight
{
    public string Url { get; set; } = string.Empty;
    public string Kind { get; set; } = "image";
    public int Score { get; set; }
    public bool IsPrimary { get; set; }
    public bool IsMatch { get; set; }
    public string Reason { get; set; } = string.Empty;
    public string? StyleNotes { get; set; }
}
