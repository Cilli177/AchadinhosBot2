using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Configuration;
using Microsoft.Extensions.Options;

namespace AchadinhosBot.Next.Infrastructure.Coupons;

public abstract class OfficialCouponProviderBase : IAffiliateCouponProvider
{
    protected AffiliateOptions AffiliateOptions { get; }
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly ILogger _logger;
    private static readonly HashSet<string> BlockedCodeTokens = new(StringComparer.OrdinalIgnoreCase)
    {
        "SHOP", "SHOPEE", "OFERTA", "OFFER", "OFFERS", "COUPON", "CUPOM", "CODIGO", "CODE", "VOUCHER"
    };

    protected OfficialCouponProviderBase(
        IOptions<AffiliateOptions> affiliateOptions,
        IHttpClientFactory httpClientFactory,
        ILogger logger)
    {
        AffiliateOptions = affiliateOptions.Value;
        _httpClientFactory = httpClientFactory;
        _logger = logger;
    }

    public abstract string Store { get; }

    public bool IsConfigured
    {
        get
        {
            var options = GetApiOptions(AffiliateOptions);
            return options.Enabled && !string.IsNullOrWhiteSpace(options.Endpoint);
        }
    }

    public async Task<IReadOnlyList<AffiliateCouponCandidate>> FetchAsync(CancellationToken cancellationToken)
    {
        var options = GetApiOptions(AffiliateOptions);
        if (!options.Enabled || string.IsNullOrWhiteSpace(options.Endpoint))
        {
            return Array.Empty<AffiliateCouponCandidate>();
        }

        using var request = BuildRequest(options);
        var client = _httpClientFactory.CreateClient("default");
        using var response = await client.SendAsync(request, cancellationToken);
        var body = await response.Content.ReadAsStringAsync(cancellationToken);

        if (!response.IsSuccessStatusCode)
        {
            throw new InvalidOperationException($"API oficial retornou {(int)response.StatusCode} para {Store}. Body: {TrimBody(body)}");
        }

        var parsedCoupons = ParseCoupons(body);
        _logger.LogInformation("Provider oficial {Store} retornou {Count} cupons", Store, parsedCoupons.Count);
        return parsedCoupons;
    }

    protected abstract OfficialCouponApiOptions GetApiOptions(AffiliateOptions options);

    protected virtual HttpRequestMessage BuildRequest(OfficialCouponApiOptions options)
    {
        var method = ParseMethod(options.Method);
        var request = new HttpRequestMessage(method, options.Endpoint.Trim());

        if (!string.IsNullOrWhiteSpace(options.BearerToken))
        {
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", options.BearerToken.Trim());
        }

        if (!string.IsNullOrWhiteSpace(options.ApiKey))
        {
            request.Headers.TryAddWithoutValidation(
                string.IsNullOrWhiteSpace(options.ApiKeyHeader) ? "X-API-Key" : options.ApiKeyHeader.Trim(),
                options.ApiKey.Trim());
        }

        if (options.Headers.Count > 0)
        {
            foreach (var pair in options.Headers)
            {
                if (string.IsNullOrWhiteSpace(pair.Key) || string.IsNullOrWhiteSpace(pair.Value))
                {
                    continue;
                }

                request.Headers.TryAddWithoutValidation(pair.Key.Trim(), pair.Value.Trim());
            }
        }

        if ((method == HttpMethod.Post || method == HttpMethod.Put || method.Method.Equals("PATCH", StringComparison.OrdinalIgnoreCase)) &&
            !string.IsNullOrWhiteSpace(options.PayloadJson))
        {
            request.Content = new StringContent(options.PayloadJson, Encoding.UTF8, "application/json");
        }

        return request;
    }

    private static HttpMethod ParseMethod(string? method)
    {
        var value = (method ?? string.Empty).Trim().ToUpperInvariant();
        return value switch
        {
            "POST" => HttpMethod.Post,
            "PUT" => HttpMethod.Put,
            "PATCH" => HttpMethod.Patch,
            _ => HttpMethod.Get
        };
    }

    private List<AffiliateCouponCandidate> ParseCoupons(string json)
    {
        using var document = JsonDocument.Parse(json);
        var arrayNode = FindCouponArray(document.RootElement);
        if (arrayNode is null)
        {
            return new List<AffiliateCouponCandidate>();
        }

        var source = $"official:{Store.ToLowerInvariant().Replace(" ", string.Empty, StringComparison.Ordinal)}";
        var list = new List<AffiliateCouponCandidate>();
        var dedupe = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var item in arrayNode.Value.EnumerateArray())
        {
            if (item.ValueKind != JsonValueKind.Object)
            {
                continue;
            }

            var code = GetString(item, "code", "couponCode", "coupon_code", "promoCode", "promo_code", "voucherCode", "voucher_code");
            code ??= ExtractCouponCodeFromText(
                GetString(item, "offerName", "name", "title", "description", "couponDescription"));
            if (string.IsNullOrWhiteSpace(code))
            {
                continue;
            }

            code = code.Trim();
            if (!dedupe.Add(code))
            {
                continue;
            }

            var description = GetString(item, "description", "title", "name", "offerName", "couponDescription");
            var affiliateLink = GetString(item, "offerLink", "affiliateLink", "affiliate_link", "link", "url", "landingUrl", "landing_url", "originalLink");
            var startsAt = GetDate(item, "startsAt", "startAt", "startDate", "start_date", "validFrom", "valid_from", "periodStartTime", "period_start_time");
            var endsAt = GetDate(item, "endsAt", "endAt", "endDate", "end_date", "validTo", "valid_to", "expireAt", "expire_at", "periodEndTime", "period_end_time");
            if (!IsActiveNow(startsAt, endsAt))
            {
                continue;
            }

            var priority = GetInt(item, "priority", "weight", "rank", "order");

            list.Add(new AffiliateCouponCandidate(
                code,
                description,
                affiliateLink,
                startsAt,
                endsAt,
                priority,
                source));
        }

        return list;
    }

    private static bool IsActiveNow(DateTimeOffset? startsAt, DateTimeOffset? endsAt)
    {
        var now = DateTimeOffset.UtcNow;
        if (startsAt.HasValue && startsAt.Value > now)
        {
            return false;
        }

        if (endsAt.HasValue && endsAt.Value < now)
        {
            return false;
        }

        return true;
    }

    private static JsonElement? FindCouponArray(JsonElement root)
    {
        if (root.ValueKind == JsonValueKind.Array)
        {
            return LooksLikeCouponArray(root) ? root : null;
        }

        if (root.ValueKind != JsonValueKind.Object)
        {
            return null;
        }

        foreach (var property in root.EnumerateObject())
        {
            if (property.Value.ValueKind == JsonValueKind.Array)
            {
                if (LooksLikeCouponArray(property.Value))
                {
                    return property.Value;
                }
            }
            else if (property.Value.ValueKind == JsonValueKind.Object)
            {
                var nested = FindCouponArray(property.Value);
                if (nested is not null)
                {
                    return nested;
                }
            }
        }

        return null;
    }

    private static bool LooksLikeCouponArray(JsonElement array)
    {
        var inspected = 0;
        foreach (var item in array.EnumerateArray())
        {
            inspected++;
            if (item.ValueKind != JsonValueKind.Object)
            {
                if (inspected >= 3)
                {
                    break;
                }

                continue;
            }

            var code = GetString(item, "code", "couponCode", "coupon_code", "promoCode", "promo_code", "voucherCode", "voucher_code");
            if (!string.IsNullOrWhiteSpace(code))
            {
                return true;
            }

            if (inspected >= 3)
            {
                break;
            }
        }

        return false;
    }

    private static string? GetString(JsonElement element, params string[] keys)
    {
        foreach (var key in keys)
        {
            if (!TryGetPropertyIgnoreCase(element, key, out var value))
            {
                continue;
            }

            if (value.ValueKind == JsonValueKind.String)
            {
                return value.GetString();
            }

            if (value.ValueKind == JsonValueKind.Number)
            {
                return value.GetRawText();
            }
        }

        return null;
    }

    private static string? ExtractCouponCodeFromText(string? text)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            return null;
        }

        var normalized = text.Trim();
        var directPattern = Regex.Match(
            normalized,
            @"(?:cupom|coupon|codigo|c[oó]digo|code|voucher)\s*[:\-]?\s*([A-Za-z0-9]{4,16})",
            RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        if (directPattern.Success)
        {
            var found = directPattern.Groups[1].Value.Trim().ToUpperInvariant();
            if (!BlockedCodeTokens.Contains(found))
            {
                return found;
            }
        }

        var tokens = Regex.Matches(normalized.ToUpperInvariant(), @"\b[A-Z0-9]{4,16}\b");
        foreach (Match tokenMatch in tokens)
        {
            var token = tokenMatch.Value.Trim();
            if (BlockedCodeTokens.Contains(token))
            {
                continue;
            }

            // Prefere tokens com ao menos um digito para reduzir falso positivo em texto de oferta.
            if (!token.Any(char.IsDigit))
            {
                continue;
            }

            return token;
        }

        return null;
    }

    private static int? GetInt(JsonElement element, params string[] keys)
    {
        foreach (var key in keys)
        {
            if (!TryGetPropertyIgnoreCase(element, key, out var value))
            {
                continue;
            }

            if (value.ValueKind == JsonValueKind.Number && value.TryGetInt32(out var number))
            {
                return number;
            }

            if (value.ValueKind == JsonValueKind.String && int.TryParse(value.GetString(), out var parsed))
            {
                return parsed;
            }
        }

        return null;
    }

    private static DateTimeOffset? GetDate(JsonElement element, params string[] keys)
    {
        foreach (var key in keys)
        {
            if (!TryGetPropertyIgnoreCase(element, key, out var value))
            {
                continue;
            }

            if (value.ValueKind == JsonValueKind.String)
            {
                if (DateTimeOffset.TryParse(value.GetString(), out var parsed))
                {
                    return parsed;
                }
            }

            if (value.ValueKind == JsonValueKind.Number)
            {
                if (value.TryGetInt64(out var unixValue))
                {
                    if (unixValue > 1_000_000_000_000)
                    {
                        return DateTimeOffset.FromUnixTimeMilliseconds(unixValue);
                    }

                    return DateTimeOffset.FromUnixTimeSeconds(unixValue);
                }
            }
        }

        return null;
    }

    private static bool TryGetPropertyIgnoreCase(JsonElement element, string propertyName, out JsonElement value)
    {
        if (element.ValueKind != JsonValueKind.Object)
        {
            value = default;
            return false;
        }

        foreach (var property in element.EnumerateObject())
        {
            if (!property.Name.Equals(propertyName, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            value = property.Value;
            return true;
        }

        value = default;
        return false;
    }

    private static string TrimBody(string body)
    {
        if (string.IsNullOrWhiteSpace(body))
        {
            return string.Empty;
        }

        return body.Length <= 600 ? body : body[..600];
    }
}
