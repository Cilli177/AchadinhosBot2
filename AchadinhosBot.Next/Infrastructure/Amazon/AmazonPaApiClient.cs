using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using AchadinhosBot.Next.Configuration;
using Microsoft.Extensions.Options;

namespace AchadinhosBot.Next.Infrastructure.Amazon;

public sealed class AmazonPaApiClient
{
    private const string ServiceName = "ProductAdvertisingAPI";
    private const string Target = "com.amazon.paapi5.v1.ProductAdvertisingAPIv1.GetItems";
    private readonly AffiliateOptions _affiliateOptions;
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly ILogger<AmazonPaApiClient> _logger;

    public AmazonPaApiClient(
        IOptions<AffiliateOptions> affiliateOptions,
        IHttpClientFactory httpClientFactory,
        ILogger<AmazonPaApiClient> logger)
    {
        _affiliateOptions = affiliateOptions.Value;
        _httpClientFactory = httpClientFactory;
        _logger = logger;
    }

    public bool IsConfigured
    {
        get
        {
            var api = _affiliateOptions.AmazonProductApi ?? new AmazonProductApiOptions();
            var partnerTag = ResolvePartnerTag();
            return api.Enabled
                   && !string.IsNullOrWhiteSpace(api.AccessKey)
                   && !string.IsNullOrWhiteSpace(api.SecretKey)
                   && !string.IsNullOrWhiteSpace(api.Host)
                   && !string.IsNullOrWhiteSpace(api.Region)
                   && !string.IsNullOrWhiteSpace(partnerTag);
        }
    }

    public async Task<AmazonPaApiItemResult?> GetItemAsync(string asin, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(asin))
        {
            return null;
        }

        var api = _affiliateOptions.AmazonProductApi ?? new AmazonProductApiOptions();
        if (!IsConfigured)
        {
            return null;
        }

        var host = api.Host.Trim();
        var region = api.Region.Trim();
        var path = string.IsNullOrWhiteSpace(api.Path) ? "/paapi5/getitems" : api.Path.Trim();
        if (!path.StartsWith("/", StringComparison.Ordinal))
        {
            path = "/" + path;
        }

        var marketplace = string.IsNullOrWhiteSpace(api.Marketplace) ? "www.amazon.com.br" : api.Marketplace.Trim();
        var partnerType = string.IsNullOrWhiteSpace(api.PartnerType) ? "Associates" : api.PartnerType.Trim();
        var partnerTag = ResolvePartnerTag();
        if (string.IsNullOrWhiteSpace(partnerTag))
        {
            return null;
        }

        var requestPayload = new
        {
            ItemIds = new[] { asin.Trim().ToUpperInvariant() },
            PartnerTag = partnerTag,
            PartnerType = partnerType,
            Marketplace = marketplace,
            Resources = new[]
            {
                "ItemInfo.Title",
                "Images.Primary.Large",
                "Images.Primary.Medium",
                "Images.Variants.Large",
                "Images.Variants.Medium",
                "OffersV2.Listings.Price"
            }
        };
        var payload = JsonSerializer.Serialize(requestPayload);

        var utcNow = DateTimeOffset.UtcNow;
        var amzDate = utcNow.ToString("yyyyMMdd'T'HHmmss'Z'");
        var dateStamp = utcNow.ToString("yyyyMMdd");
        var credentialScope = $"{dateStamp}/{region}/{ServiceName}/aws4_request";
        var signedHeaders = "content-encoding;content-type;host;x-amz-date;x-amz-target";

        var canonicalHeaders = new StringBuilder();
        canonicalHeaders.Append("content-encoding:amz-1.0\n");
        canonicalHeaders.Append("content-type:application/json; charset=utf-8\n");
        canonicalHeaders.Append("host:").Append(host).Append('\n');
        canonicalHeaders.Append("x-amz-date:").Append(amzDate).Append('\n');
        canonicalHeaders.Append("x-amz-target:").Append(Target).Append('\n');

        var payloadHash = ToHex(HashSha256(payload));
        var canonicalRequest = new StringBuilder();
        canonicalRequest.Append("POST\n");
        canonicalRequest.Append(path).Append('\n');
        canonicalRequest.Append('\n');
        canonicalRequest.Append(canonicalHeaders).Append('\n');
        canonicalRequest.Append(signedHeaders).Append('\n');
        canonicalRequest.Append(payloadHash);

        var canonicalRequestHash = ToHex(HashSha256(canonicalRequest.ToString()));
        var stringToSign = $"AWS4-HMAC-SHA256\n{amzDate}\n{credentialScope}\n{canonicalRequestHash}";
        var signingKey = BuildSigningKey(api.SecretKey.Trim(), dateStamp, region, ServiceName);
        var signature = ToHex(HmacSha256(signingKey, stringToSign));
        var authorization = $"AWS4-HMAC-SHA256 Credential={api.AccessKey.Trim()}/{credentialScope}, SignedHeaders={signedHeaders}, Signature={signature}";

        try
        {
            var client = _httpClientFactory.CreateClient("default");
            var requestUri = $"https://{host}{path}";

            using var request = new HttpRequestMessage(HttpMethod.Post, requestUri)
            {
                Content = new StringContent(payload, Encoding.UTF8, "application/json")
            };
            request.Headers.TryAddWithoutValidation("x-amz-target", Target);
            request.Headers.TryAddWithoutValidation("content-encoding", "amz-1.0");
            request.Headers.TryAddWithoutValidation("x-amz-date", amzDate);
            request.Headers.TryAddWithoutValidation("Authorization", authorization);

            using var response = await client.SendAsync(request, ct);
            var body = await response.Content.ReadAsStringAsync(ct);
            if (!response.IsSuccessStatusCode)
            {
                _logger.LogWarning(
                    "Amazon PA-API GetItems failed. Status={Status} Body={Body}",
                    (int)response.StatusCode,
                    TrimBody(body));
                return null;
            }

            return ParseItem(body);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Amazon PA-API request failed.");
            return null;
        }
    }

    private string ResolvePartnerTag()
    {
        var fromApi = _affiliateOptions.AmazonProductApi?.PartnerTag;
        if (!string.IsNullOrWhiteSpace(fromApi))
        {
            return fromApi.Trim();
        }

        return _affiliateOptions.AmazonTag?.Trim() ?? string.Empty;
    }

    private static AmazonPaApiItemResult? ParseItem(string body)
    {
        if (string.IsNullOrWhiteSpace(body))
        {
            return null;
        }

        try
        {
            using var doc = JsonDocument.Parse(body);
            if (!doc.RootElement.TryGetProperty("ItemsResult", out var itemsResult) ||
                itemsResult.ValueKind != JsonValueKind.Object ||
                !itemsResult.TryGetProperty("Items", out var items) ||
                items.ValueKind != JsonValueKind.Array)
            {
                return null;
            }

            var first = items.EnumerateArray().FirstOrDefault();
            if (first.ValueKind != JsonValueKind.Object)
            {
                return null;
            }

            var title = TryGetString(first, "ItemInfo", "Title", "DisplayValue");
            var detailPageUrl = TryGetString(first, "DetailPageURL");
            var price = TryGetString(first, "OffersV2", "Listings", 0, "Price", "DisplayAmount")
                        ?? TryGetString(first, "Offers", "Listings", 0, "Price", "DisplayAmount");

            var images = new List<string>();
            AddImage(images, TryGetString(first, "Images", "Primary", "Large", "URL"));
            AddImage(images, TryGetString(first, "Images", "Primary", "Medium", "URL"));

            if (TryGetElement(first, out var variants, "Images", "Variants") && variants.ValueKind == JsonValueKind.Array)
            {
                foreach (var variant in variants.EnumerateArray().Take(8))
                {
                    AddImage(images, TryGetString(variant, "Large", "URL"));
                    AddImage(images, TryGetString(variant, "Medium", "URL"));
                }
            }

            images = images.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
            if (string.IsNullOrWhiteSpace(title) && images.Count == 0)
            {
                return null;
            }

            return new AmazonPaApiItemResult(
                title?.Trim(),
                detailPageUrl?.Trim(),
                price?.Trim(),
                images);
        }
        catch
        {
            return null;
        }
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

    private static string? TryGetString(JsonElement source, params string[] path)
    {
        if (!TryGetElement(source, out var element, path))
        {
            return null;
        }

        return element.ValueKind == JsonValueKind.String ? element.GetString() : null;
    }

    private static string? TryGetString(JsonElement source, string key1, string key2, int index, string key3, string key4)
    {
        if (!TryGetElement(source, out var level1, key1) || level1.ValueKind != JsonValueKind.Object)
        {
            return null;
        }

        if (!TryGetElement(level1, out var level2, key2) || level2.ValueKind != JsonValueKind.Array)
        {
            return null;
        }

        var item = level2.EnumerateArray().Skip(index).FirstOrDefault();
        if (item.ValueKind != JsonValueKind.Object)
        {
            return null;
        }

        return TryGetString(item, key3, key4);
    }

    private static bool TryGetElement(JsonElement source, out JsonElement element, params string[] path)
    {
        element = source;
        foreach (var key in path)
        {
            if (element.ValueKind != JsonValueKind.Object || !element.TryGetProperty(key, out element))
            {
                return false;
            }
        }

        return true;
    }

    private static byte[] BuildSigningKey(string secretKey, string dateStamp, string region, string service)
    {
        var kSecret = Encoding.UTF8.GetBytes("AWS4" + secretKey);
        var kDate = HmacSha256(kSecret, dateStamp);
        var kRegion = HmacSha256(kDate, region);
        var kService = HmacSha256(kRegion, service);
        return HmacSha256(kService, "aws4_request");
    }

    private static byte[] HashSha256(string text)
    {
        using var sha = SHA256.Create();
        return sha.ComputeHash(Encoding.UTF8.GetBytes(text));
    }

    private static byte[] HmacSha256(byte[] key, string data)
    {
        using var hmac = new HMACSHA256(key);
        return hmac.ComputeHash(Encoding.UTF8.GetBytes(data));
    }

    private static string ToHex(byte[] bytes)
        => Convert.ToHexString(bytes).ToLowerInvariant();

    private static string TrimBody(string body)
    {
        if (string.IsNullOrWhiteSpace(body))
        {
            return string.Empty;
        }

        return body.Length <= 800 ? body : body[..800];
    }
}

public sealed record AmazonPaApiItemResult(
    string? Title,
    string? DetailPageUrl,
    string? PriceDisplay,
    List<string> Images);
