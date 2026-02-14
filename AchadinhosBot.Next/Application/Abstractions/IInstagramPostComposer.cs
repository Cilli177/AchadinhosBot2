using AchadinhosBot.Next.Domain.Settings;

namespace AchadinhosBot.Next.Application.Abstractions;

public interface IInstagramPostComposer
{
    Task<string> BuildAsync(string productInput, string? offerContext, InstagramPostSettings settings, CancellationToken cancellationToken);
}
