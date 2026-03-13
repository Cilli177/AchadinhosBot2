namespace AchadinhosBot.Next.Domain.Agents;

public sealed class ChannelOfferCandidate
{
    public string SourceChannel { get; set; } = "telegram";
    public string MessageId { get; set; } = string.Empty;
    public DateTimeOffset CreatedAtUtc { get; set; } = DateTimeOffset.UtcNow;
    public string ChatId { get; set; } = string.Empty;
    public string ChatTitle { get; set; } = string.Empty;
    public string SourceText { get; set; } = string.Empty;
    public string EffectiveText { get; set; } = string.Empty;
    public string? MediaUrl { get; set; }
    public string MediaKind { get; set; } = "text";
    public string? OriginalOfferUrl { get; set; }
    public string? EffectiveOfferUrl { get; set; }
    public bool RequiresLinkConversion { get; set; }
    public bool LinkConversionApplied { get; set; }
    public string? ConversionNote { get; set; }
    public bool IsPrimarySourceGroup { get; set; }
}
