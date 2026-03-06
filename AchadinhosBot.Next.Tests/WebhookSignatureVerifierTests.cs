using System.Security.Cryptography;
using System.Text;
using AchadinhosBot.Next.Infrastructure.Security;

namespace AchadinhosBot.Next.Tests;

public sealed class WebhookSignatureVerifierTests
{
    [Fact]
    public void TryValidate_ReturnsTrue_ForValidHexSignature()
    {
        const string secret = "super-secret";
        const string body = "{\"event\":\"connection.update\"}";
        var signature = ComputeHmacHex(secret, body);

        var ok = WebhookSignatureVerifier.TryValidate(body, secret, signature);

        Assert.True(ok);
    }

    [Fact]
    public void TryValidate_ReturnsTrue_ForSha256PrefixedSignature()
    {
        const string secret = "super-secret";
        const string body = "{\"event\":\"connection.update\"}";
        var signature = "sha256=" + ComputeHmacHex(secret, body);

        var ok = WebhookSignatureVerifier.TryValidate(body, secret, signature);

        Assert.True(ok);
    }

    [Fact]
    public void TryValidate_ReturnsFalse_ForInvalidSignature()
    {
        const string secret = "super-secret";
        const string body = "{\"event\":\"connection.update\"}";

        var ok = WebhookSignatureVerifier.TryValidate(body, secret, "0000");

        Assert.False(ok);
    }

    [Fact]
    public void TryValidate_ReturnsTrue_ForValidBase64Signature()
    {
        const string secret = "super-secret";
        const string body = "{\"event\":\"connection.update\"}";
        var signatureHex = ComputeHmacHex(secret, body);
        var signatureBase64 = Convert.ToBase64String(Convert.FromHexString(signatureHex));

        var ok = WebhookSignatureVerifier.TryValidate(body, secret, signatureBase64);

        Assert.True(ok);
    }

    private static string ComputeHmacHex(string secret, string body)
    {
        using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(secret));
        var hash = hmac.ComputeHash(Encoding.UTF8.GetBytes(body));
        return Convert.ToHexString(hash).ToLowerInvariant();
    }
}
