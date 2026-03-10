using System.Security.Cryptography;
using System.Text;

namespace AchadinhosBot.Next.Infrastructure.Resilience;

internal static class OutboundMessageFingerprint
{
    public static string Compute(params string?[] values)
    {
        var normalized = string.Join("||", values.Select(value => value?.Trim() ?? string.Empty));
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(normalized));
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }
}
