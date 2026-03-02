using System.Text.Json;
using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Configuration;
using Microsoft.Extensions.Options;

namespace AchadinhosBot.Next.Infrastructure.MercadoLivre;

public sealed class MercadoLivreOAuthService : IMercadoLivreOAuthService
{
    private static readonly TimeSpan StatusCacheTtl = TimeSpan.FromMinutes(2);

    private readonly AffiliateOptions _options;
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly ILogger<MercadoLivreOAuthService> _logger;
    private readonly SemaphoreSlim _mutex = new(1, 1);

    private string? _accessToken;
    private DateTimeOffset? _accessTokenExpiresAt;
    private string? _runtimeRefreshToken;
    private bool _refreshTokenRotated;
    private MercadoLivreOAuthStatus? _cachedStatus;
    private DateTimeOffset _cachedStatusAt;

    public MercadoLivreOAuthService(
        IOptions<AffiliateOptions> options,
        IHttpClientFactory httpClientFactory,
        ILogger<MercadoLivreOAuthService> logger)
    {
        _options = options.Value;
        _httpClientFactory = httpClientFactory;
        _logger = logger;
    }

    public async Task<string?> GetAccessTokenAsync(CancellationToken cancellationToken)
    {
        var config = ResolveConfig();
        if (!config.IsConfigured)
        {
            return null;
        }

        await _mutex.WaitAsync(cancellationToken);
        try
        {
            if (!string.IsNullOrWhiteSpace(_accessToken) &&
                _accessTokenExpiresAt.HasValue &&
                _accessTokenExpiresAt.Value > DateTimeOffset.UtcNow.AddSeconds(45))
            {
                return _accessToken;
            }

            var refreshToken = string.IsNullOrWhiteSpace(_runtimeRefreshToken)
                ? config.RefreshToken
                : _runtimeRefreshToken;

            if (string.IsNullOrWhiteSpace(refreshToken))
            {
                _logger.LogWarning("Mercado Livre OAuth sem refresh token configurado.");
                return null;
            }

            var body = $"grant_type=refresh_token" +
                       $"&client_id={Uri.EscapeDataString(config.ClientId)}" +
                       $"&client_secret={Uri.EscapeDataString(config.ClientSecret)}" +
                       $"&refresh_token={Uri.EscapeDataString(refreshToken)}";

            var client = _httpClientFactory.CreateClient("default");
            using var req = new HttpRequestMessage(HttpMethod.Post, "https://api.mercadolibre.com/oauth/token")
            {
                Content = new StringContent(body, System.Text.Encoding.UTF8, "application/x-www-form-urlencoded")
            };

            using var res = await client.SendAsync(req, cancellationToken);
            var json = await res.Content.ReadAsStringAsync(cancellationToken);
            if (!res.IsSuccessStatusCode)
            {
                _logger.LogWarning("Mercado Livre OAuth refresh falhou: {Status} {Body}", (int)res.StatusCode, json);
                return null;
            }

            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;

            var accessToken = root.TryGetProperty("access_token", out var tokenNode)
                ? tokenNode.GetString()
                : null;
            if (string.IsNullOrWhiteSpace(accessToken))
            {
                _logger.LogWarning("Mercado Livre OAuth resposta sem access_token.");
                return null;
            }

            var expiresIn = root.TryGetProperty("expires_in", out var expiresNode) && expiresNode.TryGetInt32(out var sec)
                ? sec
                : 300;
            var safety = Math.Clamp(expiresIn / 10, 20, 120);
            _accessToken = accessToken;
            _accessTokenExpiresAt = DateTimeOffset.UtcNow.AddSeconds(Math.Max(60, expiresIn - safety));

            var responseRefresh = root.TryGetProperty("refresh_token", out var refreshNode)
                ? refreshNode.GetString()
                : null;
            if (!string.IsNullOrWhiteSpace(responseRefresh) &&
                !string.Equals(responseRefresh, refreshToken, StringComparison.Ordinal))
            {
                _runtimeRefreshToken = responseRefresh;
                _refreshTokenRotated = true;
                _logger.LogWarning("Mercado Livre retornou refresh_token novo. Atualize o .env.");
            }

            _cachedStatus = null;
            return _accessToken;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Erro ao renovar token do Mercado Livre.");
            return null;
        }
        finally
        {
            _mutex.Release();
        }
    }

    public async Task<MercadoLivreOAuthStatus> GetStatusAsync(CancellationToken cancellationToken)
    {
        await _mutex.WaitAsync(cancellationToken);
        try
        {
            if (_cachedStatus is not null &&
                DateTimeOffset.UtcNow - _cachedStatusAt < StatusCacheTtl)
            {
                return _cachedStatus;
            }
        }
        finally
        {
            _mutex.Release();
        }

        return await CheckInternalAsync(forceRefresh: false, cancellationToken);
    }

    public Task<MercadoLivreOAuthStatus> RefreshAndCheckAsync(CancellationToken cancellationToken)
        => CheckInternalAsync(forceRefresh: true, cancellationToken);

    private async Task<MercadoLivreOAuthStatus> CheckInternalAsync(bool forceRefresh, CancellationToken cancellationToken)
    {
        var config = ResolveConfig();
        if (!config.IsConfigured)
        {
            return await CacheStatusAsync(new MercadoLivreOAuthStatus(
                Configured: false,
                Success: false,
                Message: "Mercado Livre OAuth nao configurado (client_id/client_secret/refresh_token).",
                UserId: null,
                Nickname: null,
                Email: null,
                AccessTokenExpiresAt: _accessTokenExpiresAt,
                RefreshTokenRotated: _refreshTokenRotated), cancellationToken);
        }

        if (forceRefresh)
        {
            await _mutex.WaitAsync(cancellationToken);
            try
            {
                _accessToken = null;
                _accessTokenExpiresAt = null;
                _cachedStatus = null;
            }
            finally
            {
                _mutex.Release();
            }
        }

        var token = await GetAccessTokenAsync(cancellationToken);
        if (string.IsNullOrWhiteSpace(token))
        {
            return await CacheStatusAsync(new MercadoLivreOAuthStatus(
                Configured: true,
                Success: false,
                Message: "Falha ao obter access_token via refresh_token.",
                UserId: null,
                Nickname: null,
                Email: null,
                AccessTokenExpiresAt: _accessTokenExpiresAt,
                RefreshTokenRotated: _refreshTokenRotated), cancellationToken);
        }

        try
        {
            var client = _httpClientFactory.CreateClient("default");
            using var req = new HttpRequestMessage(HttpMethod.Get, "https://api.mercadolibre.com/users/me");
            req.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);

            using var res = await client.SendAsync(req, cancellationToken);
            var json = await res.Content.ReadAsStringAsync(cancellationToken);
            if (!res.IsSuccessStatusCode)
            {
                _logger.LogWarning("Mercado Livre users/me falhou: {Status} {Body}", (int)res.StatusCode, json);
                return await CacheStatusAsync(new MercadoLivreOAuthStatus(
                    Configured: true,
                    Success: false,
                    Message: $"users/me falhou ({(int)res.StatusCode}).",
                    UserId: null,
                    Nickname: null,
                    Email: null,
                    AccessTokenExpiresAt: _accessTokenExpiresAt,
                    RefreshTokenRotated: _refreshTokenRotated), cancellationToken);
            }

            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;
            var userId = root.TryGetProperty("id", out var idNode) && idNode.TryGetInt64(out var id) ? id : (long?)null;
            var nickname = root.TryGetProperty("nickname", out var nickNode) ? nickNode.GetString() : null;
            var email = root.TryGetProperty("email", out var emailNode) ? emailNode.GetString() : null;

            var expectedUser = config.ExpectedUserId;
            if (expectedUser.HasValue && userId.HasValue && expectedUser.Value != userId.Value)
            {
                var mismatch = $"Usuario divergente. Esperado={expectedUser.Value} Atual={userId.Value}.";
                _logger.LogWarning("Mercado Livre OAuth {Message}", mismatch);
                return await CacheStatusAsync(new MercadoLivreOAuthStatus(
                    Configured: true,
                    Success: false,
                    Message: mismatch,
                    UserId: userId,
                    Nickname: nickname,
                    Email: email,
                    AccessTokenExpiresAt: _accessTokenExpiresAt,
                    RefreshTokenRotated: _refreshTokenRotated), cancellationToken);
            }

            var okMessage = userId.HasValue
                ? $"Mercado Livre OAuth valido para user {userId.Value} ({nickname ?? "sem nickname"})."
                : "Mercado Livre OAuth valido.";

            return await CacheStatusAsync(new MercadoLivreOAuthStatus(
                Configured: true,
                Success: true,
                Message: okMessage,
                UserId: userId,
                Nickname: nickname,
                Email: email,
                AccessTokenExpiresAt: _accessTokenExpiresAt,
                RefreshTokenRotated: _refreshTokenRotated), cancellationToken);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Erro ao validar users/me do Mercado Livre.");
            return await CacheStatusAsync(new MercadoLivreOAuthStatus(
                Configured: true,
                Success: false,
                Message: $"Erro ao validar users/me: {ex.Message}",
                UserId: null,
                Nickname: null,
                Email: null,
                AccessTokenExpiresAt: _accessTokenExpiresAt,
                RefreshTokenRotated: _refreshTokenRotated), cancellationToken);
        }
    }

    private async Task<MercadoLivreOAuthStatus> CacheStatusAsync(MercadoLivreOAuthStatus status, CancellationToken cancellationToken)
    {
        await _mutex.WaitAsync(cancellationToken);
        try
        {
            _cachedStatus = status;
            _cachedStatusAt = DateTimeOffset.UtcNow;
            _refreshTokenRotated = false;
            return status;
        }
        finally
        {
            _mutex.Release();
        }
    }

    private MercadoLivreOAuthConfig ResolveConfig()
    {
        var clientId = ResolveString(
            _options.MercadoLivreClientId,
            ReadEnv("AFFILIATE__MERCADOLIVRE_CLIENT_ID", "AFFILIATE__MERCADOLIVRECLIENTID"));

        var clientSecret = ResolveString(
            _options.MercadoLivreClientSecret,
            ReadEnv("AFFILIATE__MERCADOLIVRE_CLIENT_SECRET", "AFFILIATE__MERCADOLIVRECLIENTSECRET"));

        var refreshToken = ResolveString(
            _options.MercadoLivreRefreshToken,
            ReadEnv("AFFILIATE__MERCADOLIVRE_REFRESH_TOKEN", "AFFILIATE__MERCADOLIVREREFRESHTOKEN"));

        var userIdRaw = ResolveString(
            _options.MercadoLivreUserId,
            ReadEnv("AFFILIATE__MERCADOLIVRE_USER_ID", "AFFILIATE__MERCADOLIVREUSERID"));

        long? expectedUserId = null;
        if (!string.IsNullOrWhiteSpace(userIdRaw) && long.TryParse(userIdRaw, out var parsed))
        {
            expectedUserId = parsed;
        }

        var configured = !string.IsNullOrWhiteSpace(clientId)
                         && !string.IsNullOrWhiteSpace(clientSecret)
                         && !string.IsNullOrWhiteSpace(refreshToken);

        return new MercadoLivreOAuthConfig(
            configured,
            clientId ?? string.Empty,
            clientSecret ?? string.Empty,
            refreshToken ?? string.Empty,
            expectedUserId);
    }

    private static string? ResolveString(params string?[] values)
        => values.FirstOrDefault(v => !string.IsNullOrWhiteSpace(v))?.Trim();

    private static string? ReadEnv(params string[] keys)
    {
        foreach (var key in keys)
        {
            var value = Environment.GetEnvironmentVariable(key);
            if (!string.IsNullOrWhiteSpace(value))
            {
                return value;
            }
        }

        return null;
    }

    private sealed record MercadoLivreOAuthConfig(
        bool IsConfigured,
        string ClientId,
        string ClientSecret,
        string RefreshToken,
        long? ExpectedUserId);
}
