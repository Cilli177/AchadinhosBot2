namespace AchadinhosBot.Next.Domain.Compliance;

public sealed class MercadoLivrePendingApproval
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
    public string Status { get; set; } = "pending";
    public string Source { get; set; } = string.Empty;
    public string Reason { get; set; } = string.Empty;
    public string OriginalText { get; set; } = string.Empty;
    public List<string> ExtractedUrls { get; set; } = new();
    public long? OriginChatId { get; set; }
    public long? DestinationChatId { get; set; }
    public string? OriginChatRef { get; set; }
    public string? DestinationChatRef { get; set; }
    public DateTimeOffset? ReviewedAt { get; set; }
    public string? ReviewedBy { get; set; }
    public string? ReviewNote { get; set; }
    public string? ConvertedText { get; set; }
    public int ConvertedLinks { get; set; }
}
