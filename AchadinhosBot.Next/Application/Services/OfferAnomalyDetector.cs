using System.Globalization;
using System.Text.RegularExpressions;
using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Domain.Models;
using AchadinhosBot.Next.Domain.Offers;

namespace AchadinhosBot.Next.Application.Services;

public sealed class OfferAnomalyDetector : IOfferAnomalyDetector
{
    private static readonly Regex SuspiciousCharsRegex = new(@"[<>{}\[\]]", RegexOptions.Compiled | RegexOptions.CultureInvariant);
    private readonly ICatalogOfferStore _catalogOfferStore;

    public OfferAnomalyDetector(ICatalogOfferStore catalogOfferStore)
    {
        _catalogOfferStore = catalogOfferStore;
    }

    public async Task<IReadOnlyList<OfferAnomaly>> DetectAsync(CancellationToken cancellationToken)
    {
        var allItems = await _catalogOfferStore.ListAsync(null, 500, cancellationToken, CatalogTargets.Both);
        var active = allItems.Where(x => x.Active).ToList();
        var anomalies = new List<OfferAnomaly>();
        foreach (var item in active)
        {
            var reasons = new List<string>();
            var score = 0;

            if (!Uri.TryCreate(item.OfferUrl, UriKind.Absolute, out _))
            {
                reasons.Add("Link inválido ou malformado.");
                score += 45;
            }

            if (string.IsNullOrWhiteSpace(item.ProductName) || item.ProductName.Trim().Length < 4)
            {
                reasons.Add("Nome do produto muito curto ou ausente.");
                score += 20;
            }

            if (!string.IsNullOrWhiteSpace(item.ProductName) && SuspiciousCharsRegex.IsMatch(item.ProductName))
            {
                reasons.Add("Descrição contém caracteres suspeitos.");
                score += 20;
            }

            var price = TryParsePrice(item.PriceText);
            if (price is <= 0)
            {
                reasons.Add("Preço ausente, inválido ou não numérico.");
                score += 15;
            }

            if (price is > 50000)
            {
                reasons.Add("Preço muito acima da faixa esperada.");
                score += 25;
            }

            var duplicateCount = active.Count(x =>
                x.Id != item.Id &&
                string.Equals(x.OfferUrl, item.OfferUrl, StringComparison.OrdinalIgnoreCase));
            if (duplicateCount > 0)
            {
                reasons.Add($"Duplicidade de link detectada ({duplicateCount + 1} itens).");
                score += 20;
            }

            if (score <= 0)
            {
                continue;
            }

            var severity = score >= 60 ? "critical" : score >= 35 ? "warning" : "info";
            anomalies.Add(new OfferAnomaly(
                Guid.NewGuid().ToString("N"),
                item.Id,
                item.CatalogTarget,
                Math.Clamp(score, 1, 100),
                severity,
                $"Anomalia detectada em oferta {item.ItemNumber} ({item.ProductName}).",
                reasons,
                DateTimeOffset.UtcNow));
        }

        return anomalies
            .OrderByDescending(x => x.RiskScore)
            .Take(100)
            .ToArray();
    }

    private static decimal? TryParsePrice(string? priceText)
    {
        if (string.IsNullOrWhiteSpace(priceText))
        {
            return null;
        }

        var cleaned = priceText
            .Replace("R$", string.Empty, StringComparison.OrdinalIgnoreCase)
            .Replace(" ", string.Empty)
            .Replace(".", string.Empty)
            .Replace(",", ".", StringComparison.Ordinal);

        if (decimal.TryParse(cleaned, NumberStyles.Any, CultureInfo.InvariantCulture, out var parsed))
        {
            return parsed;
        }

        return null;
    }
}
