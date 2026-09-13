namespace AchadinhosBot.Next.Configuration;

public sealed class LogSnapshotRetentionOptions
{
    public const string SectionName = "LogSnapshotRetention";
    public int RetentionDays { get; set; } = 30;
    public int MaxSnapshotsPerScope { get; set; } = 30;
    public int MinimumSnapshotsPerScope { get; set; } = 3;
    public long MaxTotalBytes { get; set; } = 2L * 1024 * 1024 * 1024;
    public int WarningPercent { get; set; } = 80;
}
