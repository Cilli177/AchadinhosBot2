namespace AchadinhosBot.Next.Domain.Logs;

public sealed class WhatsAppParticipantBlastProgressEntry
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public DateTimeOffset Timestamp { get; set; } = DateTimeOffset.UtcNow;
    public string OperationId { get; set; } = string.Empty;
    public string ScheduleId { get; set; } = string.Empty;
    public string ScheduleName { get; set; } = string.Empty;
    public string Stage { get; set; } = string.Empty;
    public string Level { get; set; } = "info";
    public string? ParticipantId { get; set; }
    public int? Processed { get; set; }
    public int? Total { get; set; }
    public string? Message { get; set; }
    public string? InstanceName { get; set; }
    public string? GroupId { get; set; }
}
