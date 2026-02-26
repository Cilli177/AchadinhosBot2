namespace AchadinhosBot.Next.Configuration;

public sealed class HeartbeatOptions
{
    public bool Enabled { get; set; } = false;
    public string? PingUrl { get; set; }
    public int IntervalSeconds { get; set; } = 60;
    public int TimeoutSeconds { get; set; } = 10;
    public bool LogSuccess { get; set; } = false;
    public bool TelegramAlertEnabled { get; set; } = true;
    public long TelegramAlertChatId { get; set; }
    public int FailureAlertThreshold { get; set; } = 3;
    public bool RecoveryAlertEnabled { get; set; } = true;
}
