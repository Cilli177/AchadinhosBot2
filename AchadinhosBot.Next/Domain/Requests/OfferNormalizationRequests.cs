namespace AchadinhosBot.Next.Domain.Requests;

public sealed record NormalizeOffersRequest(
    string RawInput,
    string? InputType,
    string? SelectedTarget,
    string? Notes);

public sealed record RouteOfferNormalizationRunRequest(
    string? SelectedTarget,
    string? Notes);
