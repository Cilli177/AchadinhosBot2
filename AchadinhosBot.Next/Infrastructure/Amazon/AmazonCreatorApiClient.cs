using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using AchadinhosBot.Next.Configuration;
using Microsoft.Extensions.Options;

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
                   && !string.IsNullOrWhiteSpace(api.LinkEndpoint)
                   && Uri.TryCreate(api.LinkEndpoint.Trim(), UriKind.Absolute, out _);
        }
    }

    public async Task<AmazonCreatorApiLinkResult?> CreateAffiliateLinkAsync(
        Uri productUrl,
        string partnerTag,
        string? asin,
        CancellationToken ct)
    {
        if (!IsConfigured)
        {
            return null;
        }

        var api = _affiliateOptions.AmazonCreatorApi ?? new AmazonCreatorApiOptions();
        if (!Uri.TryCreate(api.LinkEndpoint.Trim(), UriKind.Absolute, out var linkEndpoint))
        {
            return null;
        }

        var token = await GetAccessTokenAsync(ct);
        if (string.IsNullOrWhiteSpace(token))
        {
            return null;
        }

        var method = ResolveHttpMethod(api.Method);
        var requestUri = linkEndpoint;
        var payload = string.Empty;

        if (method == HttpMethod.Get)
        {
            requestUri = AppendCommonQuery(linkEndpoint, productUrl, partnerTag, asin);
        }
        else
        {
            payload = BuildPayload(api.PayloadJson, productUrl.ToString(), partnerTag, asin);
        }

        try
        {
            var client = _httpClientFactory.CreateClient("default");
            using var request = new HttpRequestMessage(method, requestUri);
            request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);

            foreach (var header in api.Headers)
            {
                if (string.IsNullOrWhiteSpace(header.Key) || string.IsNullOrWhiteSpace(header.Value))
                {
                    continue;
                }

                if (string.Equals(header.Key, "Authorization", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                request.Headers.TryAddWithoutValidation(header.Key.Trim(), header.Value.Trim());
            }

            if (method != HttpMethod.Get)
            {
                request.Content = new StringContent(payload, Encoding.UTF8, "application/json");
            }

            using var response = await client.SendAsync(request, ct);
            var body = await response.Content.ReadAsStringAsync(ct);
            if (!response.IsSuccessStatusCode)
            {
                _logger.LogWarning(
                    "Amazon Creator API failed. Status={Status} Body={Body}",
                    (int)response.StatusCode,
                    TrimBody(body));
                return null;
            }

            var resultUrl = ExtractResultUrl(body, api.ResultUrlPaths);
            if (string.IsNullOrWhiteSpace(resultUrl))
            {
                _logger.LogWarning(
                    "Amazon Creator API response sem URL rastreavel. Body={Body}",
                    TrimBody(body));
                return null;
            }

            return new AmazonCreatorApiLinkResult(resultUrl.Trim(), "Link oficial via Creator API.");
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

            var values = new List<KeyValuePair<string, string>>
            {
                new("grant_type", "client_credentials"),
                new("client_id", api.ClientId.Trim()),
                new("client_secret", api.ClientSecret.Trim())
            };
            if (!string.IsNullOrWhiteSpace(api.Scope))
            {
                values.Add(new KeyValuePair<string, string>("scope", api.Scope.Trim()));
            }

            var client = _httpClientFactory.CreateClient("default");
            using var request = new HttpRequestMessage(HttpMethod.Post, tokenEndpoint)
            {
                Content = new FormUrlEncodedContent(values)
            };

            using var response = await client.SendAsync(request, ct);
            var body = await response.Content.ReadAsStringAsync(ct);
            if (!response.IsSuccessStatusCode)
            {
                _logger.LogWarning(
                    "Amazon OAuth token request failed. Status={Status} Body={Body}",
                    (int)response.StatusCode,
                    TrimBody(body));
                return null;
            }

            if (!TryParseTokenResponse(body, out var token, out var expiresInSeconds))
            {
                _logger.LogWarning("Amazon OAuth token response invalido. Body={Body}", TrimBody(body));
                return null;
            }

            _accessToken = token;
            _accessTokenExpiresAt = DateTimeOffset.UtcNow.AddSeconds(Math.Max(60, expiresInSeconds));
            return _accessToken;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Amazon OAuth token request crashed.");
            return null;
        }
        finally
        {
            _tokenLock.Release();
        }
    }

    private static Uri AppendCommonQuery(Uri endpoint, Uri productUrl, string partnerTag, string? asin)
    {
        var pairs = ParseQuery(endpoint.Query);
        pairs["url"] = productUrl.ToString();
        pairs["link"] = productUrl.ToString();
        pairs["partnerTag"] = partnerTag;
        pairs["tag"] = partnerTag;
        if (!string.IsNullOrWhiteSpace(asin))
        {
            pairs["asin"] = asin.Trim();
        }

        var encodedQuery = BuildQueryString(pairs);
        var builder = new UriBuilder(endpoint)
        {
            Query = encodedQuery
        };
        return builder.Uri;
    }

    private static string BuildPayload(string template, string url, string partnerTag, string? asin)
    {
        var content = string.IsNullOrWhiteSpace(template)
            ? "{\"url\":\"{{url}}\",\"partnerTag\":\"{{partnerTag}}\"}"
            : template;

        content = content
            .Replace("{{url}}", EscapeJson(url), StringComparison.Ordinal)
            .Replace("{{partnerTag}}", EscapeJson(partnerTag), StringComparison.Ordinal)
            .Replace("{{asin}}", EscapeJson(asin ?? string.Empty), StringComparison.Ordinal);
        return content;
    }

    private static HttpMethod ResolveHttpMethod(string? method)
    {
        if (string.IsNullOrWhiteSpace(method))
        {
            return HttpMethod.Post;
        }

        if (HttpMethod.Get.Method.Equals(method.Trim(), StringComparison.OrdinalIgnoreCase))
        {
            return HttpMethod.Get;
        }

        return HttpMethod.Post;
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
            if (!doc.RootElement.TryGetProperty("access_token", out var tokenNode) ||
                tokenNode.ValueKind != JsonValueKind.String)
            {
                return false;
            }

            token = tokenNode.GetString()?.Trim() ?? string.Empty;
            if (string.IsNullOrWhiteSpace(token))
            {
                return false;
            }

            if (doc.RootElement.TryGetProperty("expires_in", out var expiresNode))
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

    private static string? ExtractResultUrl(string body, List<string>? resultUrlPaths)
    {
        if (string.IsNullOrWhiteSpace(body))
        {
            return null;
        }

        try
        {
            using var doc = JsonDocument.Parse(body);
            var root = doc.RootElement;

            if (resultUrlPaths is not null)
            {
                foreach (var rawPath in resultUrlPaths.Where(x => !string.IsNullOrWhiteSpace(x)))
                {
                    var path = rawPath.Trim();
                    if (TryGetPath(root, path.Split('.', StringSplitOptions.RemoveEmptyEntries), out var node) &&
                        node.ValueKind == JsonValueKind.String)
                    {
                        var value = node.GetString();
                        if (IsAbsoluteHttpUrl(value))
                        {
                            return value;
                        }
                    }
                }
            }

            var discovered = FindFirstHttpUrlByKeyHint(root);
            if (IsAbsoluteHttpUrl(discovered))
            {
                return discovered;
            }
        }
        catch
        {
            // fallback regex below
        }

        var match = Regex.Match(body, @"https?://[^\s""'<>]+", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        return match.Success && IsAbsoluteHttpUrl(match.Value) ? match.Value : null;
    }

    private static string? FindFirstHttpUrlByKeyHint(JsonElement root)
    {
        if (root.ValueKind == JsonValueKind.Object)
        {
            foreach (var property in root.EnumerateObject())
            {
                if (property.Value.ValueKind == JsonValueKind.String)
                {
                    var name = property.Name;
                    var value = property.Value.GetString();
                    if (name.Contains("url", StringComparison.OrdinalIgnoreCase) && IsAbsoluteHttpUrl(value))
                    {
                        return value;
                    }
                }

                var nested = FindFirstHttpUrlByKeyHint(property.Value);
                if (!string.IsNullOrWhiteSpace(nested))
                {
                    return nested;
                }
            }
        }
        else if (root.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in root.EnumerateArray())
            {
                var nested = FindFirstHttpUrlByKeyHint(item);
                if (!string.IsNullOrWhiteSpace(nested))
                {
                    return nested;
                }
            }
        }

        return null;
    }

    private static bool TryGetPath(JsonElement source, IReadOnlyList<string> path, out JsonElement node)
    {
        node = source;
        foreach (var part in path)
        {
            if (node.ValueKind == JsonValueKind.Array && int.TryParse(part, out var index))
            {
                var value = node.EnumerateArray().Skip(index).FirstOrDefault();
                if (value.ValueKind == JsonValueKind.Undefined)
                {
                    return false;
                }

                node = value;
                continue;
            }

            if (node.ValueKind != JsonValueKind.Object || !node.TryGetProperty(part, out node))
            {
                return false;
            }
        }

        return true;
    }

    private static bool IsAbsoluteHttpUrl(string? value)
    {
        if (!Uri.TryCreate(value, UriKind.Absolute, out var uri))
        {
            return false;
        }

        return uri.Scheme is "http" or "https";
    }

    private static Dictionary<string, string> ParseQuery(string query)
    {
        var output = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (string.IsNullOrWhiteSpace(query))
        {
            return output;
        }

        var input = query.TrimStart('?');
        foreach (var pair in input.Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            var parts = pair.Split('=', 2);
            var key = Uri.UnescapeDataString(parts[0]).Trim();
            if (string.IsNullOrWhiteSpace(key))
            {
                continue;
            }

            var value = parts.Length > 1 ? Uri.UnescapeDataString(parts[1]).Trim() : string.Empty;
            output[key] = value;
        }

        return output;
    }

    private static string BuildQueryString(Dictionary<string, string> query)
    {
        return string.Join("&", query.Select(pair =>
            $"{Uri.EscapeDataString(pair.Key)}={Uri.EscapeDataString(pair.Value ?? string.Empty)}"));
    }

    private static string EscapeJson(string value)
    {
        if (value is null)
        {
            return string.Empty;
        }

        var json = JsonSerializer.Serialize(value);
        return json.Length >= 2 ? json[1..^1] : value;
    }

    private static string TrimBody(string body)
    {
        if (string.IsNullOrWhiteSpace(body))
        {
            return string.Empty;
        }

        return body.Length <= 800 ? body : body[..800];
    }
}

public sealed record AmazonCreatorApiLinkResult(
    string Url,
    string? Note);
