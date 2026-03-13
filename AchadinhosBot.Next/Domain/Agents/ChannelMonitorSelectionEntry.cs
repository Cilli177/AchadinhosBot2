namespace AchadinhosBot.Next.Domain.Agents;

public sealed class ChannelMonitorSelectionEntry
{
    public string SourceChannel { get; set; } = "telegram";
    public string ChatId { get; set; } = string.Empty;
    public string Title { get; set; } = string.Empty;
    public DateTimeOffset SelectedAtUtc { get; set; } = DateTimeOffset.UtcNow;
}
