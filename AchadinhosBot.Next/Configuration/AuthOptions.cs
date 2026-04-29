using System.ComponentModel.DataAnnotations;

namespace AchadinhosBot.Next.Configuration;

public sealed class AuthOptions
{
    public List<AuthUser> Users { get; init; } = [];
}

public sealed class AuthUser
{
    public string Username { get; init; } = string.Empty;

    public string PasswordHash { get; init; } = string.Empty; // pbkdf2$iterations$saltBase64$hashBase64

    public string Role { get; init; } = "operator";

    public bool Enabled { get; init; } = true;
}
