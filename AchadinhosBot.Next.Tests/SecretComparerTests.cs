using AchadinhosBot.Next.Infrastructure.Security;

namespace AchadinhosBot.Next.Tests;

public sealed class SecretComparerTests
{
    [Fact]
    public void EqualsConstantTime_ReturnsTrue_WhenSecretsMatch()
    {
        var ok = SecretComparer.EqualsConstantTime("abc123", "abc123");
        Assert.True(ok);
    }

    [Fact]
    public void EqualsConstantTime_ReturnsFalse_WhenSecretsDiffer()
    {
        var ok = SecretComparer.EqualsConstantTime("abc123", "abc124");
        Assert.False(ok);
    }

    [Fact]
    public void EqualsConstantTime_ReturnsFalse_WhenAnySecretIsBlank()
    {
        Assert.False(SecretComparer.EqualsConstantTime("abc123", ""));
        Assert.False(SecretComparer.EqualsConstantTime("", "abc123"));
    }
}
