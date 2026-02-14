namespace AchadinhosBot.Next.Domain.Instagram;

public sealed class InstagramPublishDraft
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
    public string ProductName { get; set; } = string.Empty;
    public string Caption { get; set; } = string.Empty;
    public string Hashtags { get; set; } = string.Empty;
    public List<string> ImageUrls { get; set; } = new();
    public List<InstagramCtaOption> Ctas { get; set; } = new();
    public string Status { get; set; } = "draft";
    public string? MediaId { get; set; }
    public string? Error { get; set; }
}
