using System.ComponentModel.DataAnnotations;

namespace AchadinhosBot.Next.Configuration;

public sealed class AuthOptions
{
    [Required]
    public List<AuthUser> Users { get; init; } = [];
}

public sealed class AuthUser
{
    [Required]
    public string Username { get; init; } = string.Empty;

    [Required]
    public string PasswordHash { get; init; } = string.Empty; // pbkdf2$iterations$saltBase64$hashBase64

    [Required]
    public string Role { get; init; } = "operator";

    public bool Enabled { get; init; } = true;
}
