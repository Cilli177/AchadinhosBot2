using System.ComponentModel.DataAnnotations;
using Microsoft.Extensions.Options;

namespace AchadinhosBot.Next.Configuration;

public sealed class AuthOptions
{
    public List<AuthUser> Users { get; init; } = [];

    public string AdminApiKey { get; set; } = string.Empty;
}

public sealed class AuthOptionsValidator : IValidateOptions<AuthOptions>
{
    private const int MinimumAdminApiKeyLength = 32;
    private readonly IHostEnvironment _environment;
    private readonly IConfiguration _configuration;

    public AuthOptionsValidator(IHostEnvironment environment, IConfiguration configuration)
    {
        _environment = environment;
        _configuration = configuration;
    }

    public ValidateOptionsResult Validate(string? name, AuthOptions options)
    {
        if (!_environment.IsProduction())
        {
            return ValidateOptionsResult.Success;
        }

        var key = options.AdminApiKey?.Trim() ?? string.Empty;
        var webhookApiKey = (_configuration["Webhook:ApiKey"] ?? _configuration["WEBHOOK__API_KEY"] ?? string.Empty).Trim();
        var failures = new List<string>();

        if (string.IsNullOrWhiteSpace(key))
        {
            failures.Add("Auth:AdminApiKey precisa ser configurada em producao.");
        }
        else
        {
            if (key.Length < MinimumAdminApiKeyLength)
            {
                failures.Add($"Auth:AdminApiKey precisa ter ao menos {MinimumAdminApiKeyLength} caracteres em producao.");
            }

            if (key.Contains("change_me", StringComparison.OrdinalIgnoreCase) ||
                key.Contains("dev-local", StringComparison.OrdinalIgnoreCase) ||
                key.Contains("example", StringComparison.OrdinalIgnoreCase))
            {
                failures.Add("Auth:AdminApiKey nao pode usar placeholder ou valor de desenvolvimento em producao.");
            }

            if (!string.IsNullOrWhiteSpace(webhookApiKey) &&
                string.Equals(key, webhookApiKey, StringComparison.Ordinal))
            {
                failures.Add("Auth:AdminApiKey precisa ser diferente de Webhook:ApiKey em producao.");
            }
        }

        return failures.Count == 0
            ? ValidateOptionsResult.Success
            : ValidateOptionsResult.Fail(failures);
    }
}

public sealed class AuthUser
{
    public string Username { get; init; } = string.Empty;

    public string PasswordHash { get; init; } = string.Empty; // pbkdf2$iterations$saltBase64$hashBase64

    public string Role { get; init; } = "operator";

    public bool Enabled { get; init; } = true;
}
