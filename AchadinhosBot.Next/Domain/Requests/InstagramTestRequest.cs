namespace AchadinhosBot.Next.Domain.Requests;

public sealed record InstagramTestRequest(
    string Input,
    string? Context,
    string? Provider = null,
    List<string>? Providers = null,
    string? Mode = null);
