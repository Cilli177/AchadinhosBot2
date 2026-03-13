namespace AchadinhosBot.Next.Domain.Agents;

public sealed class WhatsAppAgentMemoryEntry
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public string MessageId { get; set; } = string.Empty;
    public DateTimeOffset CreatedAtUtc { get; set; } = DateTimeOffset.UtcNow;
    public string EventType { get; set; } = "decision";
    public string RecommendedAction { get; set; } = string.Empty;
    public string? AppliedAction { get; set; }
    public string? SuggestedPostType { get; set; }
    public string? MediaKind { get; set; }
    public string? DecisionSource { get; set; }
    public string? DecisionProvider { get; set; }
    public int Score { get; set; }
    public int InstagramScore { get; set; }
    public int CatalogScore { get; set; }
    public string? ExistingDraftId { get; set; }
    public string? DraftId { get; set; }
    public string? OperatorFeedback { get; set; }
    public string? OperatorNote { get; set; }
    public string? Outcome { get; set; }
    public string? SelectedCaptionPreview { get; set; }
    public List<string> SelectedMediaUrls { get; set; } = new();
    public string? OfferUrl { get; set; }
}
