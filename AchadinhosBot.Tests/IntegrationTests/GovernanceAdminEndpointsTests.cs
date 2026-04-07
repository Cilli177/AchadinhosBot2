using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;

namespace AchadinhosBot.Tests.IntegrationTests;

public class GovernanceAdminEndpointsTests : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly HttpClient _client;
    private readonly string _password = "Admin#123";

    public GovernanceAdminEndpointsTests(WebApplicationFactory<Program> factory)
    {
        var hash = CreatePasswordHash(_password);

        var configuredFactory = factory.WithWebHostBuilder(builder =>
        {
            builder.ConfigureAppConfiguration((_, config) =>
            {
                config.AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["Auth:Users:0:Username"] = "admin",
                    ["Auth:Users:0:PasswordHash"] = hash,
                    ["Auth:Users:0:Role"] = "admin",
                    ["Auth:Users:0:Enabled"] = "true"
                });
            });
        });

        _client = configuredFactory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
            HandleCookies = true
        });
    }

    [Fact]
    public async Task GivenNotAuthenticated_WhenGetGovernanceStatus_ThenReturnsUnauthorized()
    {
        var response = await _client.GetAsync("/api/admin/governance/status");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task GivenAdminLogin_WhenGetGovernanceStatus_ThenReturnsSnapshot()
    {
        await LoginAsAdminAsync();

        var response = await _client.GetAsync("/api/admin/governance/status");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var json = await response.Content.ReadFromJsonAsync<JsonElement>();
        Assert.True(json.TryGetProperty("snapshot", out var snapshot));
        Assert.True(snapshot.TryGetProperty("openIncidents", out _));
    }

    [Fact]
    public async Task GivenAdminLogin_WhenPostCanaryRules_ThenRulesAreNormalizedAndReturned()
    {
        await LoginAsAdminAsync();

        var payload = new[]
        {
            new
            {
                ruleId = "",
                enabled = true,
                actionType = "",
                groupId = "group-a",
                instanceName = "inst-a",
                channel = "whatsapp",
                canaryPercent = 250
            }
        };

        var saveResponse = await _client.PostAsJsonAsync("/api/admin/canary/rules", payload);
        Assert.Equal(HttpStatusCode.OK, saveResponse.StatusCode);

        var listResponse = await _client.GetAsync("/api/admin/canary/rules");
        Assert.Equal(HttpStatusCode.OK, listResponse.StatusCode);
        var rules = await listResponse.Content.ReadFromJsonAsync<JsonElement>();

        Assert.Equal(JsonValueKind.Array, rules.ValueKind);
        Assert.True(rules.GetArrayLength() >= 1);

        var saved = rules.EnumerateArray().Last();
        Assert.Equal("global", saved.GetProperty("actionType").GetString());
        Assert.Equal(100, saved.GetProperty("canaryPercent").GetInt32());
        Assert.False(string.IsNullOrWhiteSpace(saved.GetProperty("ruleId").GetString()));
    }

    private async Task LoginAsAdminAsync()
    {
        var response = await _client.PostAsJsonAsync("/auth/login", new
        {
            username = "admin",
            password = _password,
            rememberMe = false
        });

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    private static string CreatePasswordHash(string password)
    {
        var salt = RandomNumberGenerator.GetBytes(16);
        const int iterations = 10_000;
        var hash = Rfc2898DeriveBytes.Pbkdf2(password, salt, iterations, HashAlgorithmName.SHA256, 32);
        return $"pbkdf2${iterations}${Convert.ToBase64String(salt)}${Convert.ToBase64String(hash)}";
    }
}
