using System.Text;
using System.Text.Json;
using AchadinhosBot.Next.Configuration;
using Microsoft.Extensions.Options;
using System.Net;

namespace AchadinhosBot.Next.Infrastructure.Amazon;

public sealed class AmazonCreatorApiClient
{
    private readonly AffiliateOptions _affiliateOptions;
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly ILogger<AmazonCreatorApiClient> _logger;
    private readonly SemaphoreSlim _tokenLock = new(1, 1);
    private string? _accessToken;
    private DateTimeOffset _accessTokenExpiresAt = DateTimeOffset.MinValue;

    public AmazonCreatorApiClient(
        IOptions<AffiliateOptions> affiliateOptions,
        IHttpClientFactory httpClientFactory,
        ILogger<AmazonCreatorApiClient> logger)
    {
        _affiliateOptions = affiliateOptions.Value;
        _httpClientFactory = httpClientFactory;
        _logger = logger;
    }

    public bool IsConfigured
    {
        get
        {
            var api = _affiliateOptions.AmazonCreatorApi ?? new AmazonCreatorApiOptions();
            return api.Enabled
                   && !string.IsNullOrWhiteSpace(api.ClientId)
                   && !string.IsNullOrWhiteSpace(api.ClientSecret)
                   && !string.IsNullOrWhiteSpace(api.TokenEndpoint)
                   && Uri.TryCreate(api.TokenEndpoint.Trim(), UriKind.Absolute, out _)
                   && !string.IsNullOrWhiteSpace(api.CatalogEndpoint)
                   && Uri.TryCreate(api.CatalogEndpoint.Trim(), UriKind.Absolute, out _)
                   && !string.IsNullOrWhiteSpace(api.Version);
        }
    }

    public async Task<AmazonCreatorApiItemResult?> GetItemAsync(
        string asin,
        string partnerTag,
        CancellationToken ct)
    {
        if (!IsConfigured || string.IsNullOrWhiteSpace(asin) || string.IsNullOrWhiteSpace(partnerTag))
        {
            return null;
        }

        var api = _affiliateOptions.AmazonCreatorApi ?? new AmazonCreatorApiOptions();
        if (!Uri.TryCreate(api.CatalogEndpoint.Trim(), UriKind.Absolute, out var catalogEndpoint))
        {
            return null;
        }

        var token = await GetAccessTokenAsync(ct);
        if (string.IsNullOrWhiteSpace(token))
        {
            return null;
        }

        var marketplace = string.IsNullOrWhiteSpace(api.Marketplace)
            ? "www.amazon.com.br"
            : api.Marketplace.Trim();
        var version = api.Version.Trim();
        var resources = (api.Resources ?? new List<string>())
            .Where(x => !string.IsNullOrWhiteSpace(x))
            .Select(x => x.Trim())
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
        if (resources.Length == 0)
        {
            resources = new[]
            {
                "itemInfo.title",
                "images.primary.large",
                "images.primary.medium",
                "images.variants.large",
                "images.variants.medium",
                "offersV2.listings.price"
            };
        }

        var payload = JsonSerializer.Serialize(new
        {
            itemIds = new[] { asin.Trim().ToUpperInvariant() },
            partnerTag = partnerTag.Trim(),
            marketplace,
            resources
        });

        try
        {
            var client = _httpClientFactory.CreateClient("default");
            using var request = new HttpRequestMessage(HttpMethod.Post, catalogEndpoint)
            {
                Content = new StringContent(payload, Encoding.UTF8, "application/json")
            };
            request.Headers.TryAddWithoutValidation("Authorization", $"Bearer {token}, Version {version}");
            request.Headers.TryAddWithoutValidation("x-marketplace", marketplace);

            foreach (var header in api.Headers)
            {
                if (string.IsNullOrWhiteSpace(header.Key) || string.IsNullOrWhiteSpace(header.Value))
                {
                    continue;
                }

                if (string.Equals(header.Key, "Authorization", StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(header.Key, "x-marketplace", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                request.Headers.TryAddWithoutValidation(header.Key.Trim(), header.Value.Trim());
            }

            using var response = await client.SendAsync(request, ct);
            var body = await response.Content.ReadAsStringAsync(ct);
            if (!response.IsSuccessStatusCode)
            {
                _logger.LogWarning(
                    "Amazon Creator API getItems failed. Status={Status} Body={Body}",
                    (int)response.StatusCode,
                    TrimBody(body));
                return null;
            }

            var item = ParseItem(body);
            if (item is null)
            {
                _logger.LogWarning("Amazon Creator API resposta sem item valido. Body={Body}", TrimBody(body));
                return null;
            }

            return item;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Amazon Creator API request failed.");
            return null;
        }
    }

    private async Task<string?> GetAccessTokenAsync(CancellationToken ct)
    {
        var now = DateTimeOffset.UtcNow;
        if (!string.IsNullOrWhiteSpace(_accessToken) && _accessTokenExpiresAt > now.AddSeconds(30))
        {
            return _accessToken;
        }

        await _tokenLock.WaitAsync(ct);
        try
        {
            now = DateTimeOffset.UtcNow;
            if (!string.IsNullOrWhiteSpace(_accessToken) && _accessTokenExpiresAt > now.AddSeconds(30))
            {
                return _accessToken;
            }

            var api = _affiliateOptions.AmazonCreatorApi ?? new AmazonCreatorApiOptions();
            if (!Uri.TryCreate(api.TokenEndpoint.Trim(), UriKind.Absolute, out var tokenEndpoint))
            {
                return null;
            }

            var preferBodyCredentials = string.Equals(tokenEndpoint.Host, "api.amazon.com", StringComparison.OrdinalIgnoreCase);
            var authModes = preferBodyCredentials
                ? new[] { TokenAuthMode.BodyClientCredentials, TokenAuthMode.BasicHeader }
                : new[] { TokenAuthMode.BasicHeader, TokenAuthMode.BodyClientCredentials };

            TokenRequestResult? lastFailure = null;
            var client = _httpClientFactory.CreateClient("default");
            foreach (var mode in authModes)
            {
                var result = await RequestAccessTokenAsync(client, tokenEndpoint, api, mode, ct);
                if (!result.Success || string.IsNullOrWhiteSpace(result.AccessToken))
                {
                    lastFailure = result;
                    continue;
                }

                _accessToken = result.AccessToken.Trim();
                _accessTokenExpiresAt = DateTimeOffset.UtcNow.AddSeconds(Math.Max(60, result.ExpiresInSeconds));
                return _accessToken;
            }

            if (lastFailure is not null)
            {
                _logger.LogWarning(
                    "Amazon Creator OAuth token request failed. Endpoint={Endpoint} Status={Status} Body={Body}",
                    tokenEndpoint.ToString(),
                    (int)lastFailure.StatusCode,
                    TrimBody(lastFailure.ResponseBody ?? string.Empty));
            }

            return null;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Amazon Creator OAuth token request crashed.");
            return null;
        }
        finally
        {
            _tokenLock.Release();
        }
    }

    private async Task<TokenRequestResult> RequestAccessTokenAsync(
        HttpClient client,
        Uri tokenEndpoint,
        AmazonCreatorApiOptions api,
        TokenAuthMode mode,
        CancellationToken ct)
    {
        var values = new List<KeyValuePair<string, string>>
        {
            new("grant_type", "client_credentials")
        };
        if (!string.IsNullOrWhiteSpace(api.Scope))
        {
            values.Add(new KeyValuePair<string, string>("scope", api.Scope.Trim()));
        }
        if (mode == TokenAuthMode.BodyClientCredentials)
        {
            values.Add(new KeyValuePair<string, string>("client_id", api.ClientId.Trim()));
            values.Add(new KeyValuePair<string, string>("client_secret", api.ClientSecret.Trim()));
        }

        using var request = new HttpRequestMessage(HttpMethod.Post, tokenEndpoint)
        {
            Content = new FormUrlEncodedContent(values)
        };
        if (mode == TokenAuthMode.BasicHeader)
        {
            request.Headers.TryAddWithoutValidation("Authorization", $"Basic {BuildBasicCredential(api.ClientId, api.ClientSecret)}");
        }

        using var response = await client.SendAsync(request, ct);
        var body = await response.Content.ReadAsStringAsync(ct);
        if (!response.IsSuccessStatusCode)
        {
            return new TokenRequestResult(false, null, 0, response.StatusCode, body);
        }

        if (!TryParseTokenResponse(body, out var token, out var expiresInSeconds))
        {
            return new TokenRequestResult(false, null, 0, response.StatusCode, body);
        }

        return new TokenRequestResult(true, token, expiresInSeconds, response.StatusCode, body);
    }

    private static AmazonCreatorApiItemResult? ParseItem(string body)
    {
        if (string.IsNullOrWhiteSpace(body))
        {
            return null;
        }

        try
        {
            using var doc = JsonDocument.Parse(body);
            if (!TryGetElement(doc.RootElement, out var items, "itemsResult", "items") ||
                items.ValueKind != JsonValueKind.Array)
            {
                return null;
            }

            var first = items.EnumerateArray().FirstOrDefault();
            if (first.ValueKind != JsonValueKind.Object)
            {
                return null;
            }

            var title = TryGetString(first, "itemInfo", "title", "displayValue");
            var detailPageUrl = TryGetString(first, "detailPageUrl")
                                ?? TryGetString(first, "detailPageURL");

            var price = TryGetString(first, "offersV2", "listings", "0", "price", "displayAmount")
                        ?? TryGetString(first, "offers", "listings", "0", "price", "displayAmount");

            var images = new List<string>();
            AddImage(images, TryGetString(first, "images", "primary", "large", "url"));
            AddImage(images, TryGetString(first, "images", "primary", "medium", "url"));

            if (TryGetElement(first, out var variants, "images", "variants") && variants.ValueKind == JsonValueKind.Array)
            {
                foreach (var variant in variants.EnumerateArray().Take(8))
                {
                    AddImage(images, TryGetString(variant, "large", "url"));
                    AddImage(images, TryGetString(variant, "medium", "url"));
                }
            }

            images = images.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
            if (string.IsNullOrWhiteSpace(detailPageUrl))
            {
                return null;
            }

            return new AmazonCreatorApiItemResult(
                title?.Trim(),
                detailPageUrl.Trim(),
                price?.Trim(),
                images);
        }
        catch
        {
            return null;
        }
    }

    private static bool TryGetElement(JsonElement source, out JsonElement element, params string[] path)
    {
        element = source;
        foreach (var part in path)
        {
            if (element.ValueKind == JsonValueKind.Array)
            {
                if (!int.TryParse(part, out var index))
                {
                    return false;
                }

                var item = element.EnumerateArray().Skip(index).FirstOrDefault();
                if (item.ValueKind == JsonValueKind.Undefined)
                {
                    return false;
                }

                element = item;
                continue;
            }

            if (element.ValueKind != JsonValueKind.Object)
            {
                return false;
            }

            if (!TryGetPropertyIgnoreCase(element, part, out var nested))
            {
                return false;
            }

            element = nested;
        }

        return true;
    }

    private static string? TryGetString(JsonElement source, params string[] path)
    {
        if (!TryGetElement(source, out var element, path))
        {
            return null;
        }

        return element.ValueKind == JsonValueKind.String ? element.GetString() : null;
    }

    private static bool TryGetPropertyIgnoreCase(JsonElement source, string propertyName, out JsonElement value)
    {
        foreach (var property in source.EnumerateObject())
        {
            if (string.Equals(property.Name, propertyName, StringComparison.OrdinalIgnoreCase))
            {
                value = property.Value;
                return true;
            }
        }

        value = default;
        return false;
    }

    private static void AddImage(List<string> images, string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return;
        }

        if (!Uri.TryCreate(value, UriKind.Absolute, out var uri))
        {
            return;
        }

        if (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps)
        {
            return;
        }

        images.Add(value.Trim());
    }

    private static bool TryParseTokenResponse(string body, out string token, out int expiresInSeconds)
    {
        token = string.Empty;
        expiresInSeconds = 3600;

        if (string.IsNullOrWhiteSpace(body))
        {
            return false;
        }

        try
        {
            using var doc = JsonDocument.Parse(body);
            if (!TryGetPropertyIgnoreCase(doc.RootElement, "access_token", out var tokenNode) ||
                tokenNode.ValueKind != JsonValueKind.String)
            {
                return false;
            }

            token = tokenNode.GetString()?.Trim() ?? string.Empty;
            if (string.IsNullOrWhiteSpace(token))
            {
                return false;
            }

            if (TryGetPropertyIgnoreCase(doc.RootElement, "expires_in", out var expiresNode))
            {
                if (expiresNode.ValueKind == JsonValueKind.Number && expiresNode.TryGetInt32(out var numeric))
                {
                    expiresInSeconds = numeric;
                }
                else if (expiresNode.ValueKind == JsonValueKind.String &&
                         int.TryParse(expiresNode.GetString(), out var parsed))
                {
                    expiresInSeconds = parsed;
                }
            }

            return true;
        }
        catch
        {
            return false;
        }
    }

    private static string BuildBasicCredential(string clientId, string clientSecret)
    {
        var raw = $"{clientId?.Trim() ?? string.Empty}:{clientSecret?.Trim() ?? string.Empty}";
        return Convert.ToBase64String(Encoding.UTF8.GetBytes(raw));
    }

    private static string TrimBody(string body)
    {
        if (string.IsNullOrWhiteSpace(body))
        {
            return string.Empty;
        }

        return body.Length <= 800 ? body : body[..800];
    }

    private enum TokenAuthMode
    {
        BasicHeader = 0,
        BodyClientCredentials = 1
    }

    private sealed record TokenRequestResult(
        bool Success,
        string? AccessToken,
        int ExpiresInSeconds,
        HttpStatusCode StatusCode,
        string? ResponseBody);
}

public sealed record AmazonCreatorApiItemResult(
    string? Title,
    string? DetailPageUrl,
    string? PriceDisplay,
    List<string> Images);
