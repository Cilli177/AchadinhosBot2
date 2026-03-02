namespace AchadinhosBot.Next.Domain.Requests;

public sealed record ContentCalendarCreateRequest(
    DateTimeOffset? ScheduledAt,
    string? PostType,
    string? SourceInput,
    string? OfferContext,
    string? MediaUrl,
    string? OfferUrl,
    string? Keyword,
    string? Hashtags,
    string? GeneratedCaption,
    bool? AutoPublish,
    string? ReferenceUrl,
    string? ReferenceCaption,
    string? ReferenceMediaUrl);

public sealed record ContentReferenceImportRequest(
    DateTimeOffset? ScheduledAt,
    string? PostType,
    string? ReferenceUrl,
    string? ReferenceCaption,
    string? ReferenceMediaUrl,
    string? OfferUrl,
    string? OfferContext,
    string? Keyword,
    string? Hashtags,
    bool? AutoPublish);

public sealed record ContentCalendarRunSummary(
    int TotalDue,
    int Processed,
    int Published,
    int DraftsCreated,
    int Failed);
