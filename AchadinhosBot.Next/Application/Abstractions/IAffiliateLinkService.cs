namespace AchadinhosBot.Next.Application.Abstractions;

public interface IAffiliateLinkService
{
    Task<string?> ConvertAsync(string rawUrl, CancellationToken cancellationToken);
}
