namespace AchadinhosBot.Next.Application.Abstractions;

public interface IMercadoLivreOAuthService
{
    Task<string?> GetAccessTokenAsync(CancellationToken cancellationToken);
    Task<MercadoLivreOAuthStatus> GetStatusAsync(CancellationToken cancellationToken);
    Task<MercadoLivreOAuthStatus> RefreshAndCheckAsync(CancellationToken cancellationToken);
}

public sealed record MercadoLivreOAuthStatus(
    bool Configured,
    bool Success,
    string Message,
    long? UserId,
    string? Nickname,
    string? Email,
    DateTimeOffset? AccessTokenExpiresAt,
    bool RefreshTokenRotated);
