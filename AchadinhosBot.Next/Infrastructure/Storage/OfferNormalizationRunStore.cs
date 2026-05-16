using System.Text.Json;
using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Domain.Offers;

namespace AchadinhosBot.Next.Infrastructure.Storage;

public sealed class OfferNormalizationRunStore : IOfferNormalizationRunStore
{
    private readonly string _path;
    private readonly SemaphoreSlim _mutex = new(1, 1);

    public OfferNormalizationRunStore()
    {
        _path = Path.Combine(AppContext.BaseDirectory, "data", "offer-normalization-runs.json");
    }

    public async Task<OfferNormalizationRun> SaveAsync(OfferNormalizationRun run, CancellationToken cancellationToken)
    {
        await _mutex.WaitAsync(cancellationToken);
        try
        {
            var all = await ReadAllUnsafeAsync(cancellationToken);
            var existingIndex = all.FindIndex(x => string.Equals(x.Id, run.Id, StringComparison.OrdinalIgnoreCase));
            run.UpdatedAtUtc = DateTimeOffset.UtcNow;
            if (existingIndex >= 0)
            {
                all[existingIndex] = Clone(run);
            }
            else
            {
                all.Add(Clone(run));
            }

            await WriteAllUnsafeAsync(all, cancellationToken);
            return Clone(run);
        }
        finally
        {
            _mutex.Release();
        }
    }

    public async Task<OfferNormalizationRun?> GetAsync(string id, CancellationToken cancellationToken)
    {
        await _mutex.WaitAsync(cancellationToken);
        try
        {
            var all = await ReadAllUnsafeAsync(cancellationToken);
            return all
                .FirstOrDefault(x => string.Equals(x.Id, id, StringComparison.OrdinalIgnoreCase))
                is { } match
                ? Clone(match)
                : null;
        }
        finally
        {
            _mutex.Release();
        }
    }

    public async Task<IReadOnlyList<OfferNormalizationRun>> ListAsync(string? status, string? target, int limit, CancellationToken cancellationToken)
    {
        var normalizedStatus = string.IsNullOrWhiteSpace(status) ? null : status.Trim().ToLowerInvariant();
        var normalizedTarget = string.IsNullOrWhiteSpace(target) ? null : OfferNormalizationTargets.Normalize(target);
        var safeLimit = Math.Clamp(limit, 1, 200);

        await _mutex.WaitAsync(cancellationToken);
        try
        {
            var all = await ReadAllUnsafeAsync(cancellationToken);
            return all
                .Where(x => normalizedStatus is null || string.Equals(x.Status, normalizedStatus, StringComparison.OrdinalIgnoreCase))
                .Where(x => normalizedTarget is null || string.Equals(x.SelectedTarget, normalizedTarget, StringComparison.OrdinalIgnoreCase))
                .OrderByDescending(x => x.CreatedAtUtc)
                .Take(safeLimit)
                .Select(Clone)
                .ToArray();
        }
        finally
        {
            _mutex.Release();
        }
    }

    private async Task<List<OfferNormalizationRun>> ReadAllUnsafeAsync(CancellationToken cancellationToken)
    {
        if (!File.Exists(_path))
        {
            return [];
        }

        try
        {
            var json = await File.ReadAllTextAsync(_path, cancellationToken);
            return JsonSerializer.Deserialize<List<OfferNormalizationRun>>(json) ?? [];
        }
        catch
        {
            return [];
        }
    }

    private async Task WriteAllUnsafeAsync(List<OfferNormalizationRun> runs, CancellationToken cancellationToken)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(_path)!);
        var json = JsonSerializer.Serialize(
            runs.OrderByDescending(x => x.CreatedAtUtc),
            new JsonSerializerOptions { WriteIndented = true });
        await File.WriteAllTextAsync(_path, json, cancellationToken);
    }

    private static OfferNormalizationRun Clone(OfferNormalizationRun run)
    {
        var json = JsonSerializer.Serialize(run);
        return JsonSerializer.Deserialize<OfferNormalizationRun>(json) ?? new OfferNormalizationRun();
    }
}
