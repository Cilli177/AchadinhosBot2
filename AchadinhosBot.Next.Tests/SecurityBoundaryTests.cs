using System.Text.Encodings.Web;
using AchadinhosBot.Next.Configuration;
using AchadinhosBot.Next.Infrastructure.Security;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Configuration;

namespace AchadinhosBot.Next.Tests;

public sealed class SecurityBoundaryTests
{
    [Fact]
    public async Task AdminApiKeyHandler_ValidHeader_AuthenticatesAsAdminWithDedicatedScheme()
    {
        var context = new DefaultHttpContext();
        context.Request.Headers[AdminAuthenticationSchemes.HeaderName] = "test-admin-key";
        var handler = CreateHandler("test-admin-key");
        await handler.InitializeAsync(CreateScheme(), context);

        var result = await handler.AuthenticateAsync();

        Assert.True(result.Succeeded);
        Assert.Equal(AdminAuthenticationSchemes.AdminApiKey, result.Ticket!.AuthenticationScheme);
        Assert.Equal("admin", result.Principal!.FindFirst(System.Security.Claims.ClaimTypes.Role)?.Value);
    }

    [Fact]
    public async Task AdminApiKeyHandler_InvalidHeader_FailsWithoutCookieFallback()
    {
        var context = new DefaultHttpContext();
        context.Request.Headers[AdminAuthenticationSchemes.HeaderName] = "wrong-key";
        var handler = CreateHandler("test-admin-key");
        await handler.InitializeAsync(CreateScheme(), context);

        var result = await handler.AuthenticateAsync();

        Assert.False(result.Succeeded);
        Assert.True(result.Failure is not null);
    }

    [Fact]
    public void DataProtectionValidator_ProductionRejectsRelativePath()
    {
        var validator = new DataProtectionStorageOptionsValidator(new TestHostEnvironment("Production"));

        var result = validator.Validate(null, new DataProtectionStorageOptions
        {
            KeysPath = "relative/keys",
            ApplicationName = "AchadinhosBot.Next"
        });

        Assert.True(result.Failed);
    }

    [Fact]
    public void AuthOptionsValidator_ProductionRejectsWebhookCredentialReuse()
    {
        const string sharedCredential = "this-is-a-long-enough-test-credential";
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Webhook:ApiKey"] = sharedCredential
            })
            .Build();
        var validator = new AuthOptionsValidator(new TestHostEnvironment("Production"), configuration);

        var result = validator.Validate(null, new AuthOptions { AdminApiKey = sharedCredential });

        Assert.True(result.Failed);
    }

    private static AdminApiKeyAuthenticationHandler CreateHandler(string apiKey) => new(
        new StaticOptionsMonitor<AuthenticationSchemeOptions>(new AuthenticationSchemeOptions()),
        NullLoggerFactory.Instance,
        UrlEncoder.Default,
        new StaticOptionsMonitor<AuthOptions>(new AuthOptions { AdminApiKey = apiKey }));

    private static AuthenticationScheme CreateScheme() => new(
        AdminAuthenticationSchemes.AdminApiKey,
        null,
        typeof(AdminApiKeyAuthenticationHandler));

    private sealed class StaticOptionsMonitor<T> : IOptionsMonitor<T>
    {
        public StaticOptionsMonitor(T currentValue) => CurrentValue = currentValue;

        public T CurrentValue { get; }

        public T Get(string? name) => CurrentValue;

        public IDisposable? OnChange(Action<T, string?> listener) => null;
    }

    private sealed class TestHostEnvironment : IHostEnvironment
    {
        public TestHostEnvironment(string environmentName) => EnvironmentName = environmentName;

        public string EnvironmentName { get; set; }
        public string ApplicationName { get; set; } = "AchadinhosBot.Next.Tests";
        public string ContentRootPath { get; set; } = AppContext.BaseDirectory;
        public Microsoft.Extensions.FileProviders.IFileProvider ContentRootFileProvider { get; set; } = new Microsoft.Extensions.FileProviders.NullFileProvider();
    }
}
