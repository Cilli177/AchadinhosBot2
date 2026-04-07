using System.Text.Json;
using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Domain.Governance;

namespace AchadinhosBot.Next.Infrastructure.Governance;

public sealed class FileCanaryRuleStore : ICanaryRuleStore
{
    private readonly string _path;
    private readonly SemaphoreSlim _mutex = new(1, 1);

    public FileCanaryRuleStore()
    {
        var dataDir = Path.Combine(AppContext.BaseDirectory, "data");
        Directory.CreateDirectory(dataDir);
        _path = Path.Combine(dataDir, "canary-rules.json");
    }

    public async Task<IReadOnlyList<CanaryRule>> ListAsync(CancellationToken cancellationToken)
    {
        await _mutex.WaitAsync(cancellationToken);
        try
        {
            if (!File.Exists(_path))
            {
                return Array.Empty<CanaryRule>();
            }

            await using var stream = File.OpenRead(_path);
            var rules = await JsonSerializer.DeserializeAsync<List<CanaryRule>>(stream, cancellationToken: cancellationToken);
            return rules ?? new List<CanaryRule>();
        }
        finally
        {
            _mutex.Release();
        }
    }

    public async Task SaveAsync(IReadOnlyList<CanaryRule> rules, CancellationToken cancellationToken)
    {
        await _mutex.WaitAsync(cancellationToken);
        try
        {
            await using var stream = File.Create(_path);
            await JsonSerializer.SerializeAsync(stream, rules, new JsonSerializerOptions { WriteIndented = true }, cancellationToken);
        }
        finally
        {
            _mutex.Release();
        }
    }
}
