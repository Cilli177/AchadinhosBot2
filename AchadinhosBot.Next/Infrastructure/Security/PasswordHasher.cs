using System.Security.Cryptography;

namespace AchadinhosBot.Next.Infrastructure.Security;

public static class PasswordHasher
{
    public static bool Verify(string password, string stored)
    {
        // expected: pbkdf2$iterations$saltBase64$hashBase64
        var parts = stored.Split('$', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length != 4 || !parts[0].Equals("pbkdf2", StringComparison.OrdinalIgnoreCase)) return false;

        if (!int.TryParse(parts[1], out var iterations)) return false;
        var salt = Convert.FromBase64String(parts[2]);
        var expected = Convert.FromBase64String(parts[3]);

        var actual = Rfc2898DeriveBytes.Pbkdf2(password, salt, iterations, HashAlgorithmName.SHA256, expected.Length);
        return CryptographicOperations.FixedTimeEquals(actual, expected);
    }
}
