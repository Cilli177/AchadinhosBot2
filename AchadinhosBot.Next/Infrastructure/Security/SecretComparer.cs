using System.Security.Cryptography;
using System.Text;

namespace AchadinhosBot.Next.Infrastructure.Security;

public static class SecretComparer
{
    public static bool EqualsConstantTime(string? expected, string? provided)
    {
        if (string.IsNullOrWhiteSpace(expected) || string.IsNullOrWhiteSpace(provided))
        {
            return false;
        }

        var left = Encoding.UTF8.GetBytes(expected.Trim());
        var right = Encoding.UTF8.GetBytes(provided.Trim());

        return left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);
    }
}
