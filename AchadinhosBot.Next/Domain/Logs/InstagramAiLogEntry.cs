namespace AchadinhosBot.Next.Domain.Logs;

public sealed class InstagramAiLogEntry
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public DateTimeOffset Timestamp { get; set; } = DateTimeOffset.UtcNow;
    public string Provider { get; set; } = string.Empty;
    public string Model { get; set; } = string.Empty;
    public bool Success { get; set; }
    public string? Error { get; set; }
    public int Variations { get; set; }
    public string PromptPreset { get; set; } = string.Empty;
    public bool UltraPrompt { get; set; }
    public bool ShortName { get; set; }
    public bool BenefitBullets { get; set; }
    public int QualityScore { get; set; }
    public string QualityNotes { get; set; } = string.Empty;
    public string InputSnippet { get; set; } = string.Empty;
    public string? Link { get; set; }
    public int ImageCount { get; set; }
    public List<string> ImageUrls { get; set; } = new();
    public int OutputLength { get; set; }
    public long DurationMs { get; set; }
}
