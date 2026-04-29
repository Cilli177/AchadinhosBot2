namespace AchadinhosBot.Next.Domain.Agents;

public sealed class OfferCurationRequest
{
    public List<string> DraftIds { get; set; } = new();
    public int HoursWindow { get; set; } = 72;
    public int MaxItems { get; set; } = 10;
    public bool IncludeDrafts { get; set; } = true;
    public bool IncludeScheduled { get; set; } = true;
    public bool IncludePublished { get; set; } = true;
}

public sealed class OfferCurationResult
{
    public string AgentName { get; set; } = "offer_curator_v1";
    public string Mode { get; set; } = "suggestion_only";
    public DateTimeOffset GeneratedAt { get; set; } = DateTimeOffset.UtcNow;
    public string Summary { get; set; } = string.Empty;
    public int EvaluatedDrafts { get; set; }
    public int SuggestedActions { get; set; }
    public List<OfferCurationSuggestion> Suggestions { get; set; } = new();
}

public sealed class OfferCurationSuggestion
{
    public string DraftId { get; set; } = string.Empty;
    public string ProductName { get; set; } = string.Empty;
    public string Status { get; set; } = string.Empty;
    public string PostType { get; set; } = string.Empty;
    public string RecommendedAction { get; set; } = OfferCurationActions.Review;
    public int Score { get; set; }
    public int RecentClicks { get; set; }
    public bool InCatalogDev { get; set; }
    public bool InCatalogProd { get; set; }
    public string SuggestedCatalogTarget { get; set; } = "none";
    public bool HasOfferUrl { get; set; }
    public bool HasMedia { get; set; }
    public bool IsHighlightedOnBio { get; set; }
    public DateTimeOffset? BioHighlightedAt { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset? ScheduledFor { get; set; }
    public List<string> Reasons { get; set; } = new();
    public List<string> Risks { get; set; } = new();
    public ComparisonDeal? BestComparison { get; set; }
}

public sealed class ComparisonDeal
{
    public string Store { get; set; } = string.Empty;
    public string Price { get; set; } = string.Empty;
    public string Url { get; set; } = string.Empty;
    public string? Coupon { get; set; }
}

public static class OfferCurationActions
{
    public const string AddToCatalog = "add_to_catalog";
    public const string ReviewAndPublish = "review_and_publish";
    public const string HighlightOnBio = "highlight_on_bio";
    public const string Review = "review";
    public const string NoAction = "no_action";
}
