namespace AchadinhosBot.Next.Domain.Logs;

public sealed class WhatsAppOutboundLogEntry
{
    public string MessageId { get; set; } = string.Empty;
    public DateTimeOffset CreatedAtUtc { get; set; } = DateTimeOffset.UtcNow;
    public string Kind { get; set; } = "text";
    public string? InstanceName { get; set; }
    public string To { get; set; } = string.Empty;
    public string? Text { get; set; }
    public string? MediaUrl { get; set; }
    public string? MimeType { get; set; }
    public string? FileName { get; set; }
}
