namespace AchadinhosBot.Next.Application.Abstractions;

public interface IInstagramAutoPilotService
{
    Task<InstagramAutoPilotRunResult> RunNowAsync(InstagramAutoPilotRunRequest? request, CancellationToken cancellationToken);
}

public sealed class InstagramAutoPilotRunRequest
{
    public string? PostType { get; set; }
    public int? TopCount { get; set; }
    public int? LookbackHours { get; set; }
    public int? RepeatWindowHours { get; set; }
    public bool? SendForApproval { get; set; }
    public string? ApprovalChannel { get; set; }
    public long? ApprovalTelegramChatId { get; set; }
    public string? ApprovalWhatsAppGroupId { get; set; }
    public string? ApprovalWhatsAppInstanceName { get; set; }
    public bool ForceIncludeExisting { get; set; }
    public bool DryRun { get; set; }
}

public sealed class InstagramAutoPilotRunResult
{
    public DateTimeOffset Timestamp { get; set; } = DateTimeOffset.UtcNow;
    public string PostType { get; set; } = "feed";
    public bool Success { get; set; }
    public string Message { get; set; } = string.Empty;
    public int CandidatesEvaluated { get; set; }
    public int SelectedCount { get; set; }
    public int DraftsCreated { get; set; }
    public bool ApprovalSent { get; set; }
    public string? ApprovalChannel { get; set; }
    public string? ApprovalTarget { get; set; }
    public List<InstagramAutoPilotSelectionItem> Selected { get; set; } = new();
}

public sealed class InstagramAutoPilotSelectionItem
{
    public string ProductUrl { get; set; } = string.Empty;
    public string Store { get; set; } = "Unknown";
    public string? ProductName { get; set; }
    public string? ProductDataSource { get; set; }
    public string? ImageUrl { get; set; }
    public int? ImageMatchScore { get; set; }
    public string? ImageMatchReason { get; set; }
    public int SalesSignal { get; set; }
    public int ReturnSignal { get; set; }
    public int DiscountSignal { get; set; }
    public int RecencySignal { get; set; }
    public int EngagementSignal { get; set; }
    public int FinalScore { get; set; }
    public string? DraftId { get; set; }
    public string? Note { get; set; }
}
