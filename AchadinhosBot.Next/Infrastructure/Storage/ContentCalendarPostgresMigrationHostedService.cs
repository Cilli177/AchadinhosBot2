using System.Security.Cryptography;
using System.Text;
using AchadinhosBot.Next.Configuration;
using Microsoft.Extensions.Options;

namespace AchadinhosBot.Next.Infrastructure.Storage;

/// <summary>
/// Explicit, one-time CSV-to-PostgreSQL cutover. It never removes or modifies the CSV source;
/// rollback is therefore a configuration change back to the csv provider.
/// </summary>
public sealed class ContentCalendarPostgresMigrationHostedService : IHostedService
{
    private readonly CsvContentCalendarStore _csv;
    private readonly ContentCalendarStorageOptions _options;
    private readonly ILogger<ContentCalendarPostgresMigrationHostedService> _logger;

    public ContentCalendarPostgresMigrationHostedService(
        CsvContentCalendarStore csv,
        IOptions<ContentCalendarStorageOptions> options,
        ILogger<ContentCalendarPostgresMigrationHostedService> logger)
    {
        _csv = csv;
        _options = options.Value;
        _logger = logger;
    }

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        if (!string.Equals(_options.Provider, "postgres", StringComparison.OrdinalIgnoreCase) || !_options.MigrateCsvOnStartup)
        {
            return;
        }

        var csv = await _csv.ExportCsvAsync(cancellationToken);
        var hash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(csv))).ToLowerInvariant();
        var items = await _csv.ListAsync(cancellationToken);
        var store = new PostgresContentCalendarStore(_options.ConnectionString!);
        var imported = await store.ImportCsvSnapshotAsync(items, hash, cancellationToken);

        if (imported)
        {
            _logger.LogInformation("Content calendar CSV import completed: {Count} item(s), sha256 {Hash}.", items.Count, hash);
        }
        else
        {
            _logger.LogInformation("Content calendar CSV import was already applied for sha256 {Hash}.", hash);
        }
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
