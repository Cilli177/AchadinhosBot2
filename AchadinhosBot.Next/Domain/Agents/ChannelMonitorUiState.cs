namespace AchadinhosBot.Next.Domain.Agents;

public sealed class ChannelMonitorUiState
{
    public string SourceChannel { get; set; } = "telegram";
    public string SelectionMode { get; set; } = WhatsAppOfferScoutSelectionModes.SavedHistory;
    public int HoursWindow { get; set; } = 168;
    public int MaxItems { get; set; } = 10;
    public bool IncludeAiReasoning { get; set; }
    public bool UseAiDecision { get; set; }
    public Dictionary<string, List<string>> ManualTargetIdsBySource { get; set; } = new(StringComparer.OrdinalIgnoreCase);
}
