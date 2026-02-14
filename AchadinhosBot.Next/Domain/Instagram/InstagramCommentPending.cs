namespace AchadinhosBot.Next.Domain.Instagram;

public sealed class InstagramCommentPending
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public DateTimeOffset Timestamp { get; set; } = DateTimeOffset.UtcNow;
    public string CommentId { get; set; } = string.Empty;
    public string MediaId { get; set; } = string.Empty;
    public string From { get; set; } = string.Empty;
    public string Text { get; set; } = string.Empty;
    public string Status { get; set; } = "pending";
    public string? SuggestedReply { get; set; }
    public string? ApprovedReply { get; set; }
}
