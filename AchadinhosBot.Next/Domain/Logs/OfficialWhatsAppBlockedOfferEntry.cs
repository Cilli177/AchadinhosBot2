namespace AchadinhosBot.Next.Domain.Logs;

public sealed class OfficialWhatsAppBlockedOfferEntry
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public DateTimeOffset Timestamp { get; set; } = DateTimeOffset.UtcNow;
    public string Source { get; set; } = "WhatsApp";
    public string? InstanceName { get; set; }
    public long? OriginChatId { get; set; }
    public string? OriginChatRef { get; set; }
    public string? DestinationChatRef { get; set; }
    public string Reason { get; set; } = string.Empty;
    public string? Detail { get; set; }
    public string? Text { get; set; }
    public bool HasImageCandidate { get; set; }
    public string? ImageSource { get; set; }
    public string? Store { get; set; }
    public string? OfferUrl { get; set; }
    public string? TrackingUrl { get; set; }
}
