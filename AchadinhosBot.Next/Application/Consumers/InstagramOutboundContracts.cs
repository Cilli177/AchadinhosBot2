namespace AchadinhosBot.Next.Application.Consumers;

public sealed class PublishInstagramPostCommand
{
    public string MessageId { get; set; } = Guid.NewGuid().ToString("N");
    public string DeduplicationKey { get; set; } = string.Empty;
    public string DraftId { get; set; } = string.Empty;
    public string? RequestedBy { get; set; }
    public DateTimeOffset CreatedAtUtc { get; set; } = DateTimeOffset.UtcNow;
}

public sealed class ReplyInstagramCommentCommand
{
    public string MessageId { get; set; } = Guid.NewGuid().ToString("N");
    public string DeduplicationKey { get; set; } = string.Empty;
    public string CommentStoreId { get; set; } = string.Empty;
    public string CommentId { get; set; } = string.Empty;
    public string? MediaId { get; set; }
    public string ReplyText { get; set; } = string.Empty;
    public string? Keyword { get; set; }
    public DateTimeOffset CreatedAtUtc { get; set; } = DateTimeOffset.UtcNow;
}

public sealed class SendInstagramDirectMessageCommand
{
    public string MessageId { get; set; } = Guid.NewGuid().ToString("N");
    public string DeduplicationKey { get; set; } = string.Empty;
    public string RecipientId { get; set; } = string.Empty;
    public string MessageText { get; set; } = string.Empty;
    public string? CommentStoreId { get; set; }
    public string? MediaId { get; set; }
    public string? Keyword { get; set; }
    public string Provider { get; set; } = "meta";
    public DateTimeOffset CreatedAtUtc { get; set; } = DateTimeOffset.UtcNow;
}

public sealed class InstagramOutboundEnvelope
{
    public string MessageId { get; set; } = Guid.NewGuid().ToString("N");
    public string MessageType { get; set; } = string.Empty;
    public string PayloadJson { get; set; } = string.Empty;
    public DateTimeOffset CreatedAtUtc { get; set; } = DateTimeOffset.UtcNow;
}
