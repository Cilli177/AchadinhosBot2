using Microsoft.Extensions.Options;

namespace AchadinhosBot.Next.Configuration;

public sealed class DataProtectionStorageOptions
{
    public string KeysPath { get; set; } = string.Empty;

    public string ApplicationName { get; set; } = "AchadinhosBot.Next";
}

public sealed class DataProtectionStorageOptionsValidator : IValidateOptions<DataProtectionStorageOptions>
{
    private readonly IHostEnvironment _environment;

    public DataProtectionStorageOptionsValidator(IHostEnvironment environment)
    {
        _environment = environment;
    }

    public ValidateOptionsResult Validate(string? name, DataProtectionStorageOptions options)
    {
        var failures = new List<string>();

        if (string.IsNullOrWhiteSpace(options.KeysPath))
        {
            failures.Add("DataProtection:KeysPath precisa ser configurado.");
        }
        else if (_environment.IsProduction() && !Path.IsPathFullyQualified(options.KeysPath))
        {
            failures.Add("DataProtection:KeysPath precisa ser um caminho absoluto em producao.");
        }

        if (string.IsNullOrWhiteSpace(options.ApplicationName))
        {
            failures.Add("DataProtection:ApplicationName precisa ser configurado.");
        }

        return failures.Count == 0
            ? ValidateOptionsResult.Success
            : ValidateOptionsResult.Fail(failures);
    }
}
