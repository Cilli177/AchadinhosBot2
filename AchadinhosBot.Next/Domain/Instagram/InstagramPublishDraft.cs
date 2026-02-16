namespace AchadinhosBot.Next.Domain.Instagram;

public sealed class InstagramPublishDraft
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
    public string PostType { get; set; } = "feed";
    public string ProductName { get; set; } = string.Empty;
    public string Caption { get; set; } = string.Empty;
    public List<string> CaptionOptions { get; set; } = new();
    public int SelectedCaptionIndex { get; set; } = 1;
    public string Hashtags { get; set; } = string.Empty;
    public List<string> ImageUrls { get; set; } = new();
    public List<InstagramCtaOption> Ctas { get; set; } = new();
    public string Status { get; set; } = "draft";
    public string? MediaId { get; set; }
    public string? Error { get; set; }
}
