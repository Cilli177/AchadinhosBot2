namespace AchadinhosBot.Next.Application.Consumers;

public sealed class ProcessContentCalendarDueCommand
{
    public string MessageId { get; set; } = Guid.NewGuid().ToString("N");
    public string DeduplicationKey { get; set; } = string.Empty;
    public string? RequestedBy { get; set; }
    public DateTimeOffset CreatedAtUtc { get; set; } = DateTimeOffset.UtcNow;
}

public sealed class ContentCalendarCommandEnvelope
{
    public string MessageId { get; set; } = Guid.NewGuid().ToString("N");
    public string PayloadJson { get; set; } = string.Empty;
    public DateTimeOffset CreatedAtUtc { get; set; } = DateTimeOffset.UtcNow;
}
