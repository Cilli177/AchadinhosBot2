namespace AchadinhosBot.Next.Domain.Models;

public sealed class WhatsAppGroupMembershipEvent
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public string? InstanceName { get; set; }
    public string GroupId { get; set; } = string.Empty;
    public string GroupName { get; set; } = string.Empty;
    public string ParticipantId { get; set; } = string.Empty;
    public string Action { get; set; } = string.Empty; // join, leave, add, remove
    public DateTimeOffset Timestamp { get; set; } = DateTimeOffset.UtcNow;
    public bool IsSyncDetection { get; set; }
}
