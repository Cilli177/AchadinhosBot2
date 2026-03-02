using System.Text.Json;
using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Domain.Compliance;

namespace AchadinhosBot.Next.Infrastructure.Storage;

public sealed class MercadoLivreApprovalStore : IMercadoLivreApprovalStore
{
    private readonly string _path;
    private readonly SemaphoreSlim _mutex = new(1, 1);

    public MercadoLivreApprovalStore()
    {
        _path = Path.Combine(AppContext.BaseDirectory, "data", "mercadolivre-pending.json");
    }

    public async Task AppendAsync(MercadoLivrePendingApproval entry, CancellationToken cancellationToken)
    {
        await _mutex.WaitAsync(cancellationToken);
        try
        {
            var items = await ReadAllInternalAsync(cancellationToken);
            items.Add(entry);
            await WriteAllInternalAsync(items, cancellationToken);
        }
        finally
        {
            _mutex.Release();
        }
    }

    public async Task<IReadOnlyList<MercadoLivrePendingApproval>> ListAsync(string? status, int limit, CancellationToken cancellationToken)
    {
        await _mutex.WaitAsync(cancellationToken);
        try
        {
            var items = await ReadAllInternalAsync(cancellationToken);
            if (!string.IsNullOrWhiteSpace(status))
            {
                items = items
                    .Where(x => string.Equals(x.Status, status, StringComparison.OrdinalIgnoreCase))
                    .ToList();
            }

            return items
                .OrderByDescending(x => x.CreatedAt)
                .Take(Math.Clamp(limit, 1, 500))
                .ToArray();
        }
        finally
        {
            _mutex.Release();
        }
    }

    public async Task<MercadoLivrePendingApproval?> GetAsync(string id, CancellationToken cancellationToken)
    {
        await _mutex.WaitAsync(cancellationToken);
        try
        {
            var items = await ReadAllInternalAsync(cancellationToken);
            return items.FirstOrDefault(x => string.Equals(x.Id, id, StringComparison.OrdinalIgnoreCase));
        }
        finally
        {
            _mutex.Release();
        }
    }

    public async Task<bool> DecideAsync(
        string id,
        string status,
        string reviewedBy,
        string? reviewNote,
        string? convertedText,
        int convertedLinks,
        CancellationToken cancellationToken)
    {
        await _mutex.WaitAsync(cancellationToken);
        try
        {
            var items = await ReadAllInternalAsync(cancellationToken);
            var entry = items.FirstOrDefault(x => string.Equals(x.Id, id, StringComparison.OrdinalIgnoreCase));
            if (entry is null)
            {
                return false;
            }

            entry.Status = status;
            entry.ReviewedBy = reviewedBy;
            entry.ReviewedAt = DateTimeOffset.UtcNow;
            entry.ReviewNote = reviewNote;
            entry.ConvertedText = convertedText;
            entry.ConvertedLinks = convertedLinks;
            await WriteAllInternalAsync(items, cancellationToken);
            return true;
        }
        finally
        {
            _mutex.Release();
        }
    }

    private async Task<List<MercadoLivrePendingApproval>> ReadAllInternalAsync(CancellationToken cancellationToken)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(_path)!);
        if (!File.Exists(_path))
        {
            return new List<MercadoLivrePendingApproval>();
        }

        await using var stream = File.OpenRead(_path);
        var items = await JsonSerializer.DeserializeAsync<List<MercadoLivrePendingApproval>>(stream, cancellationToken: cancellationToken);
        return items ?? new List<MercadoLivrePendingApproval>();
    }

    private async Task WriteAllInternalAsync(List<MercadoLivrePendingApproval> items, CancellationToken cancellationToken)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(_path)!);
        await using var stream = File.Create(_path);
        await JsonSerializer.SerializeAsync(stream, items, new JsonSerializerOptions { WriteIndented = true }, cancellationToken);
    }
}
