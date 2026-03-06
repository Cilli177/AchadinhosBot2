using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Http;

namespace AchadinhosBot.Next.Infrastructure.Security;

public static class WebhookSignatureVerifier
{
    public const string SignatureHeaderName = "x-signature";

    public static bool TryValidate(HttpRequest request, string body, string? secret)
    {
        if (string.IsNullOrWhiteSpace(secret))
        {
            return false;
        }

        if (request.Headers.TryGetValue(SignatureHeaderName, out var signatureHeader))
        {
            if (TryValidate(body, secret, signatureHeader.ToString())) return true;
        }

        if (request.Headers.TryGetValue("webhook-signature", out var webhookSignatureHeader))
        {
            if (TryValidate(body, secret, webhookSignatureHeader.ToString())) return true;
        }

        return false;
    }

    public static bool TryValidate(string body, string? secret, string? providedSignature)
    {
        if (string.IsNullOrWhiteSpace(secret) || string.IsNullOrWhiteSpace(providedSignature))
        {
            return false;
        }

        if (!TryDecodeHexSignature(providedSignature, out var providedBytes))
        {
            return false;
        }

        var payload = body ?? string.Empty;
        using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(secret.Trim()));
        var expectedBytes = hmac.ComputeHash(Encoding.UTF8.GetBytes(payload));

        return providedBytes.Length == expectedBytes.Length &&
               CryptographicOperations.FixedTimeEquals(providedBytes, expectedBytes);
    }

    private static bool TryDecodeHexSignature(string rawSignature, out byte[] bytes)
    {
        var value = (rawSignature ?? string.Empty).Trim();
        if (value.StartsWith("sha256=", StringComparison.OrdinalIgnoreCase))
        {
            value = value["sha256=".Length..];
        }

        try
        {
            bytes = Convert.FromHexString(value);
            return bytes.Length > 0;
        }
        catch
        {
            try
            {
                bytes = Convert.FromBase64String(value);
                return bytes.Length > 0;
            }
            catch
            {
                bytes = Array.Empty<byte>();
                return false;
            }
        }
    }
}
