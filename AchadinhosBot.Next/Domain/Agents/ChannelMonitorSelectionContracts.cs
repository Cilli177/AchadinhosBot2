namespace AchadinhosBot.Next.Domain.Agents;

public sealed class ChannelMonitorSelectionUpsertRequest
{
    public string SourceChannel { get; set; } = "telegram";
    public List<ChannelMonitorSelectionEntry> Selections { get; set; } = new();
}

public sealed class ChannelMonitorSelectionResponse
{
    public string SourceChannel { get; set; } = "telegram";
    public int Count { get; set; }
    public List<ChannelMonitorSelectionEntry> Items { get; set; } = new();
}

public sealed class ChannelMonitorSeedLogRequest
{
    public string SourceChannel { get; set; } = "telegram";
    public string ChatId { get; set; } = string.Empty;
    public string? Title { get; set; }
}
