using System.Text.Json;
using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Domain.Offers;

namespace AchadinhosBot.Next.Infrastructure.Storage;

public sealed class OfferAutomationIntentStore : IOfferAutomationIntentStore
{
    private readonly string _path;
    private readonly SemaphoreSlim _mutex = new(1, 1);

    public OfferAutomationIntentStore()
    {
        _path = Path.Combine(AppContext.BaseDirectory, "data", "offer-automation-intents.json");
    }

    public async Task<OfferAutomationIntent> SaveAsync(OfferAutomationIntent intent, CancellationToken cancellationToken)
    {
        await _mutex.WaitAsync(cancellationToken);
        try
        {
            var all = await ReadAllUnsafeAsync(cancellationToken);
            var existingIndex = all.FindIndex(x => string.Equals(x.NormalizationRunId, intent.NormalizationRunId, StringComparison.OrdinalIgnoreCase));
            intent.UpdatedAtUtc = DateTimeOffset.UtcNow;
            if (existingIndex >= 0)
            {
                intent.Id = all[existingIndex].Id;
                intent.CreatedAtUtc = all[existingIndex].CreatedAtUtc;
                all[existingIndex] = Clone(intent);
            }
            else
            {
                all.Add(Clone(intent));
            }

            await WriteAllUnsafeAsync(all, cancellationToken);
            return Clone(intent);
        }
        finally
        {
            _mutex.Release();
        }
    }

    public async Task<OfferAutomationIntent?> GetByNormalizationRunIdAsync(string normalizationRunId, CancellationToken cancellationToken)
    {
        await _mutex.WaitAsync(cancellationToken);
        try
        {
            var all = await ReadAllUnsafeAsync(cancellationToken);
            var match = all.FirstOrDefault(x => string.Equals(x.NormalizationRunId, normalizationRunId, StringComparison.OrdinalIgnoreCase));
            return match is null ? null : Clone(match);
        }
        finally
        {
            _mutex.Release();
        }
    }

    private async Task<List<OfferAutomationIntent>> ReadAllUnsafeAsync(CancellationToken cancellationToken)
    {
        if (!File.Exists(_path))
        {
            return [];
        }

        try
        {
            var json = await File.ReadAllTextAsync(_path, cancellationToken);
            return JsonSerializer.Deserialize<List<OfferAutomationIntent>>(json) ?? [];
        }
        catch
        {
            return [];
        }
    }

    private async Task WriteAllUnsafeAsync(List<OfferAutomationIntent> intents, CancellationToken cancellationToken)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(_path)!);
        var json = JsonSerializer.Serialize(
            intents.OrderByDescending(x => x.CreatedAtUtc),
            new JsonSerializerOptions { WriteIndented = true });
        await File.WriteAllTextAsync(_path, json, cancellationToken);
    }

    private static OfferAutomationIntent Clone(OfferAutomationIntent intent)
    {
        var json = JsonSerializer.Serialize(intent);
        return JsonSerializer.Deserialize<OfferAutomationIntent>(json) ?? new OfferAutomationIntent();
    }
}
