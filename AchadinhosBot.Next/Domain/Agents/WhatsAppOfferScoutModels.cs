namespace AchadinhosBot.Next.Domain.Agents;

public sealed class WhatsAppOfferScoutRequest
{
    public int HoursWindow { get; set; } = 168;
    public int MaxItems { get; set; } = 10;
    public bool IncludeAiReasoning { get; set; }
    public bool UseAiDecision { get; set; }
    public string SourceChannel { get; set; } = "whatsapp";
    public string TargetSelectionMode { get; set; } = WhatsAppOfferScoutSelectionModes.SavedHistory;
    public List<string> TargetChatIds { get; set; } = new();
}

public sealed class WhatsAppOfferScoutResult
{
    public string AgentName { get; set; } = "whatsapp_offer_scout_v1";
    public string Mode { get; set; } = "suggestion_only";
    public string SourceChannel { get; set; } = "whatsapp";
    public string TargetSelectionMode { get; set; } = WhatsAppOfferScoutSelectionModes.SavedHistory;
    public DateTimeOffset GeneratedAt { get; set; } = DateTimeOffset.UtcNow;
    public string Summary { get; set; } = string.Empty;
    public int SourceMessagesAvailable { get; set; }
    public int EvaluatedMessages { get; set; }
    public int SuggestedActions { get; set; }
    public int PersistedTargetCount { get; set; }
    public int SelectionAnchoredTargetCount { get; set; }
    public List<string> Warnings { get; set; } = new();
    public List<WhatsAppOfferSuggestion> Suggestions { get; set; } = new();
}

public sealed class WhatsAppOfferSuggestion
{
    public string MessageId { get; set; } = string.Empty;
    public DateTimeOffset CreatedAt { get; set; }
    public string InstanceName { get; set; } = string.Empty;
    public string TargetChatId { get; set; } = string.Empty;
    public string SourceGroupTitle { get; set; } = string.Empty;
    public string ProductName { get; set; } = string.Empty;
    public string CaptionPreview { get; set; } = string.Empty;
    public string OfferUrl { get; set; } = string.Empty;
    public string OriginalOfferUrl { get; set; } = string.Empty;
    public string? ImageUrl { get; set; }
    public string MediaKind { get; set; } = "text";
    public string SuggestedPostType { get; set; } = "feed";
    public string RecommendedAction { get; set; } = WhatsAppOfferScoutActions.Review;
    public string DecisionSource { get; set; } = "heuristic";
    public string? DecisionProvider { get; set; }
    public int Score { get; set; }
    public int InstagramScore { get; set; }
    public int CatalogScore { get; set; }
    public int RecentClicks { get; set; }
    public bool HasImage { get; set; }
    public string SuggestedKeyword { get; set; } = string.Empty;
    public string? AiReasoning { get; set; }
    public bool HasExistingDraft { get; set; }
    public string? ExistingDraftId { get; set; }
    public string? ExistingDraftStatus { get; set; }
    public bool RequiresLinkConversion { get; set; }
    public bool LinkConversionApplied { get; set; }
    public bool IsPrimarySourceGroup { get; set; }
    public string? ConversionNote { get; set; }
    public string? LastAppliedAction { get; set; }
    public string? LastOperatorFeedback { get; set; }
    public string? LastOperatorNote { get; set; }
    public string? LastOutcome { get; set; }
    public DateTimeOffset? LastDecisionAt { get; set; }
    public bool InCatalogDev { get; set; }
    public bool InCatalogProd { get; set; }
    public List<string> Reasons { get; set; } = new();
    public List<string> Risks { get; set; } = new();
}

public sealed class WhatsAppOfferAiDecision
{
    public string RecommendedAction { get; set; } = WhatsAppOfferScoutActions.Review;
    public int InstagramScore { get; set; }
    public int CatalogScore { get; set; }
    public string SuggestedKeyword { get; set; } = string.Empty;
    public string Reasoning { get; set; } = string.Empty;
    public List<string> Risks { get; set; } = new();
    public string Provider { get; set; } = string.Empty;
}

public static class WhatsAppOfferScoutActions
{
    public const string ConvertLink = "convert_link";
    public const string CreateInstagramDraft = "create_instagram_draft";
    public const string AddToCatalog = "add_to_catalog";
    public const string ReviewAndPublish = "review_and_publish";
    public const string Review = "review";
    public const string NoAction = "no_action";
}

public static class WhatsAppOfferScoutPostTypes
{
    public const string Feed = "feed";
    public const string Reel = "reel";
    public const string Catalog = "catalog";
}

public static class WhatsAppOfferScoutSelectionModes
{
    public const string SavedHistory = "saved_history";
    public const string SinceSelection = "since_selection";
}
