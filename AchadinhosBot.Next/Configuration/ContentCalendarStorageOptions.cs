using Microsoft.Extensions.Options;

namespace AchadinhosBot.Next.Configuration;

public sealed class ContentCalendarStorageOptions
{
    public const string SectionName = "ContentCalendarStorage";
    public string Provider { get; init; } = "csv";
    public string? ConnectionString { get; init; }
    public bool MigrateCsvOnStartup { get; init; }
}

public sealed class ContentCalendarStorageOptionsValidator : IValidateOptions<ContentCalendarStorageOptions>
{
    public ValidateOptionsResult Validate(string? name, ContentCalendarStorageOptions options)
    {
        var provider = (options.Provider ?? string.Empty).Trim().ToLowerInvariant();
        if (provider is not "csv" and not "postgres") return ValidateOptionsResult.Fail("ContentCalendarStorage.Provider deve ser csv ou postgres.");
        if (provider == "postgres" && string.IsNullOrWhiteSpace(options.ConnectionString)) return ValidateOptionsResult.Fail("ContentCalendarStorage.ConnectionString e obrigatoria para postgres.");
        return ValidateOptionsResult.Success;
    }
}
