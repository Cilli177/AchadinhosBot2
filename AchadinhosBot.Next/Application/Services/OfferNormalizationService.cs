using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using AchadinhosBot.Next.Domain.Offers;

namespace AchadinhosBot.Next.Application.Services;

public sealed class OfferNormalizationService
{
    private static readonly string[] SourceAliases = ["source", "platform", "marketplace", "origin"];
    private static readonly string[] ProductNameAliases = ["productname", "product_name", "title", "name", "produto", "nomeproduto", "product"];
    private static readonly string[] ProductUrlAliases = ["producturl", "product_url", "url", "link", "offerurl", "affiliateurl", "produto_url"];
    private static readonly string[] OriginalPriceAliases = ["originalprice", "original_price", "listprice", "fullprice", "pricebefore", "oldprice", "precooriginal"];
    private static readonly string[] PromoPriceAliases = ["promoprice", "promo_price", "price", "saleprice", "currentprice", "priceafter", "preco", "precopromo"];
    private static readonly string[] DiscountAliases = ["discountpercent", "discount_percent", "discount", "discountrate", "percentualdesconto"];
    private static readonly string[] StoreAliases = ["storename", "store_name", "store", "seller", "shop", "loja"];
    private static readonly string[] CategoryAliases = ["category", "segment", "categoria"];
    private static readonly string[] CommissionAliases = ["commissionraw", "commission_raw", "commission", "commissionrate", "commissiontext", "comissao"];

    public OfferNormalizationRun Normalize(
        string rawInput,
        string? inputType,
        string? selectedTarget,
        string? notes,
        string actor)
    {
        var run = new OfferNormalizationRun
        {
            Id = Guid.NewGuid().ToString("n"),
            CreatedAtUtc = DateTimeOffset.UtcNow,
            UpdatedAtUtc = DateTimeOffset.UtcNow,
            Operator = string.IsNullOrWhiteSpace(actor) ? "unknown" : actor.Trim(),
            Notes = string.IsNullOrWhiteSpace(notes) ? null : notes.Trim(),
            SelectedTarget = OfferNormalizationTargets.Normalize(selectedTarget),
            InputPreview = BuildInputPreview(rawInput)
        };

        if (string.IsNullOrWhiteSpace(rawInput))
        {
            run.SourceType = NormalizeInputType(inputType, "autodetect");
            run.Status = OfferNormalizationStatuses.Failed;
            run.ValidationIssues.Add(new OfferNormalizationIssue
            {
                Level = "error",
                Message = "Nenhum conteúdo foi enviado para normalização."
            });
            run.Summary = "Entrada vazia. Nenhuma oferta foi normalizada.";
            run.NextStepHint = "Cole JSON, CSV ou texto tabular antes de tentar normalizar.";
            return run;
        }

        var resolvedInputType = DetectInputType(rawInput, inputType);
        run.SourceType = resolvedInputType;

        try
        {
            var offers = resolvedInputType == "json"
                ? NormalizeJson(rawInput, run.ValidationIssues)
                : NormalizeDelimited(rawInput, resolvedInputType, run.ValidationIssues);

            run.NormalizedOffers = offers;
            run.Status = offers.Count > 0 ? OfferNormalizationStatuses.Normalized : OfferNormalizationStatuses.Failed;
            run.Summary = BuildSummary(resolvedInputType, offers.Count, run.ValidationIssues.Count);
            run.NextStepHint = offers.Count > 0
                ? "Revise o preview e escolha se esta execução segue para revisão, catálogo ou fila de automação."
                : "Corrija as lacunas indicadas e tente normalizar novamente.";
        }
        catch (Exception ex)
        {
            run.Status = OfferNormalizationStatuses.Failed;
            run.ValidationIssues.Add(new OfferNormalizationIssue
            {
                Level = "error",
                Message = $"Falha ao normalizar a entrada: {ex.Message}"
            });
            run.Summary = "A entrada não pôde ser normalizada.";
            run.NextStepHint = "Verifique o formato enviado e tente novamente com JSON, CSV ou texto tabular válido.";
        }

        return run;
    }

    public OfferNormalizationRun Route(OfferNormalizationRun run, string? selectedTarget, string? notes)
    {
        var normalizedTarget = OfferNormalizationTargets.Normalize(selectedTarget);
        run.SelectedTarget = normalizedTarget;
        if (!string.IsNullOrWhiteSpace(notes))
        {
            run.Notes = notes.Trim();
        }

        if (run.NormalizedOffers.Count == 0)
        {
            run.Status = OfferNormalizationStatuses.Failed;
            run.NextStepHint = "Esta execução não possui ofertas válidas para encaminhamento.";
            return run;
        }

        run.Status = OfferNormalizationStatuses.FromTarget(normalizedTarget);
        run.NextStepHint = normalizedTarget switch
        {
            OfferNormalizationTargets.Catalog => "Execução marcada para fluxo assistido de catálogo. Revise os itens antes de promover ao catálogo final.",
            OfferNormalizationTargets.Queue => "Execução marcada para fila de automação. Use esta trilha como intenção auditável antes de ligar qualquer automação posterior.",
            _ => "Execução mantida em revisão. Confira gaps e aprove somente o que estiver pronto."
        };

        return run;
    }

    private static string DetectInputType(string rawInput, string? inputType)
    {
        var normalized = NormalizeInputType(inputType, "autodetect");
        if (normalized != "autodetect")
        {
            return normalized;
        }

        var trimmed = rawInput.TrimStart();
        if (trimmed.StartsWith("{", StringComparison.Ordinal) || trimmed.StartsWith("[", StringComparison.Ordinal))
        {
            return "json";
        }

        var firstLine = rawInput.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).FirstOrDefault() ?? string.Empty;
        if (firstLine.Contains('\t'))
        {
            return "tsv";
        }

        if (firstLine.Contains('|'))
        {
            return "table";
        }

        if (firstLine.Contains(';'))
        {
            return "csv";
        }

        return firstLine.Contains(',') ? "csv" : "table";
    }

    private static string NormalizeInputType(string? inputType, string fallback)
    {
        var normalized = (inputType ?? string.Empty).Trim().ToLowerInvariant();
        return normalized switch
        {
            "json" => "json",
            "csv" => "csv",
            "tsv" => "tsv",
            "table" => "table",
            "api" => "json",
            "api-payload" => "json",
            _ => fallback
        };
    }

    private static string BuildInputPreview(string rawInput)
    {
        var compact = Regex.Replace(rawInput.Trim(), @"\s+", " ");
        return compact.Length <= 500 ? compact : compact[..500];
    }

    private static string BuildSummary(string sourceType, int offersCount, int issueCount)
        => $"{offersCount} oferta(s) normalizadas via {sourceType}. {issueCount} issue(s) detectada(s).";

    private static List<CanonicalOfferRecord> NormalizeJson(string rawInput, List<OfferNormalizationIssue> issues)
    {
        var root = JsonNode.Parse(rawInput);
        var candidateArray = ResolveJsonArray(root);
        if (candidateArray is null)
        {
            issues.Add(new OfferNormalizationIssue
            {
                Level = "error",
                Message = "JSON recebido sem coleção reconhecível de ofertas."
            });
            return [];
        }

        var offers = new List<CanonicalOfferRecord>();
        var rowNumber = 1;
        foreach (var node in candidateArray)
        {
            if (node is JsonObject obj)
            {
                var mapped = MapObjectToOffer(obj.ToDictionary(k => k.Key, v => JsonNodeToString(v.Value)), rowNumber, issues);
                if (mapped is not null)
                {
                    offers.Add(mapped);
                }
            }
            else
            {
                issues.Add(new OfferNormalizationIssue
                {
                    Level = "warn",
                    Message = "Item JSON ignorado por não ser um objeto.",
                    RowNumber = rowNumber
                });
            }

            rowNumber++;
        }

        return offers;
    }

    private static JsonArray? ResolveJsonArray(JsonNode? root)
    {
        if (root is JsonArray array)
        {
            return array;
        }

        if (root is not JsonObject obj)
        {
            return null;
        }

        foreach (var key in new[] { "offers", "items", "results", "data", "products" })
        {
            if (obj[key] is JsonArray candidate)
            {
                return candidate;
            }
        }

        foreach (var property in obj)
        {
            if (property.Value is JsonArray candidate)
            {
                return candidate;
            }
        }

        return new JsonArray(obj);
    }

    private static List<CanonicalOfferRecord> NormalizeDelimited(string rawInput, string sourceType, List<OfferNormalizationIssue> issues)
    {
        var lines = rawInput
            .Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries)
            .Select(x => x.Trim())
            .Where(x => !string.IsNullOrWhiteSpace(x))
            .ToList();

        if (lines.Count < 2)
        {
            issues.Add(new OfferNormalizationIssue
            {
                Level = "error",
                Message = "Formato tabular insuficiente. Envie cabeçalho + linhas de dados."
            });
            return [];
        }

        var delimiter = sourceType switch
        {
            "tsv" => '\t',
            "table" => '|',
            _ => DetectDelimiter(lines[0])
        };

        var rows = lines
            .Where(x => !LooksLikeMarkdownSeparator(x))
            .Select(x => ParseDelimitedLine(x, delimiter))
            .Where(x => x.Count > 0)
            .ToList();

        if (rows.Count < 2)
        {
            issues.Add(new OfferNormalizationIssue
            {
                Level = "error",
                Message = "Não foi possível identificar linhas de dados após o cabeçalho."
            });
            return [];
        }

        var headers = rows[0].Select(NormalizeHeader).ToList();
        var offers = new List<CanonicalOfferRecord>();

        for (var rowIndex = 1; rowIndex < rows.Count; rowIndex++)
        {
            var row = rows[rowIndex];
            var map = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);
            for (var col = 0; col < headers.Count; col++)
            {
                var value = col < row.Count ? row[col] : null;
                map[headers[col]] = string.IsNullOrWhiteSpace(value) ? null : value?.Trim();
            }

            var offer = MapObjectToOffer(map, rowIndex + 1, issues);
            if (offer is not null)
            {
                offers.Add(offer);
            }
        }

        return offers;
    }

    private static CanonicalOfferRecord? MapObjectToOffer(
        IDictionary<string, string?> values,
        int rowNumber,
        List<OfferNormalizationIssue> issues)
    {
        var source = GetFirst(values, SourceAliases);
        var productName = GetFirst(values, ProductNameAliases);
        var productUrl = GetFirst(values, ProductUrlAliases);
        var originalPrice = ParseDecimal(GetFirst(values, OriginalPriceAliases));
        var promoPrice = ParseDecimal(GetFirst(values, PromoPriceAliases));
        var discount = ParseDecimal(GetFirst(values, DiscountAliases));
        var storeName = GetFirst(values, StoreAliases);
        var category = GetFirst(values, CategoryAliases);
        var commissionRaw = GetFirst(values, CommissionAliases);

        if (discount is null && originalPrice is > 0 && promoPrice is > 0 && promoPrice <= originalPrice)
        {
            discount = decimal.Round((1 - (promoPrice.Value / originalPrice.Value)) * 100m, 2);
        }

        if (string.IsNullOrWhiteSpace(productName) && string.IsNullOrWhiteSpace(productUrl))
        {
            issues.Add(new OfferNormalizationIssue
            {
                Level = "warn",
                Message = "Linha ignorada por não ter nome de produto nem URL.",
                RowNumber = rowNumber
            });
            return null;
        }

        if (string.IsNullOrWhiteSpace(productName))
        {
            issues.Add(new OfferNormalizationIssue
            {
                Level = "warn",
                Message = "Produto sem nome legível.",
                RowNumber = rowNumber,
                Field = "product_name"
            });
        }

        if (string.IsNullOrWhiteSpace(productUrl))
        {
            issues.Add(new OfferNormalizationIssue
            {
                Level = "warn",
                Message = "Produto sem URL.",
                RowNumber = rowNumber,
                Field = "product_url"
            });
        }

        var consumedKeys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        AddConsumed(consumedKeys, SourceAliases, values);
        AddConsumed(consumedKeys, ProductNameAliases, values);
        AddConsumed(consumedKeys, ProductUrlAliases, values);
        AddConsumed(consumedKeys, OriginalPriceAliases, values);
        AddConsumed(consumedKeys, PromoPriceAliases, values);
        AddConsumed(consumedKeys, DiscountAliases, values);
        AddConsumed(consumedKeys, StoreAliases, values);
        AddConsumed(consumedKeys, CategoryAliases, values);
        AddConsumed(consumedKeys, CommissionAliases, values);

        var extra = values
            .Where(kvp => !consumedKeys.Contains(kvp.Key))
            .ToDictionary(kvp => kvp.Key, kvp => kvp.Value, StringComparer.OrdinalIgnoreCase);

        return new CanonicalOfferRecord
        {
            Source = source ?? string.Empty,
            ProductName = productName ?? string.Empty,
            ProductUrl = productUrl ?? string.Empty,
            OriginalPrice = originalPrice,
            PromoPrice = promoPrice,
            DiscountPercent = discount,
            StoreName = storeName ?? string.Empty,
            Category = category ?? string.Empty,
            CommissionRaw = commissionRaw ?? string.Empty,
            ExtraFields = extra
        };
    }

    private static string? JsonNodeToString(JsonNode? node)
    {
        return node switch
        {
            null => null,
            JsonValue value => value.ToJsonString().Trim('"'),
            _ => node.ToJsonString()
        };
    }

    private static char DetectDelimiter(string headerLine)
    {
        var candidates = new[] { ',', ';', '\t', '|' };
        return candidates
            .Select(delimiter => new { delimiter, count = headerLine.Count(ch => ch == delimiter) })
            .OrderByDescending(x => x.count)
            .First().delimiter;
    }

    private static bool LooksLikeMarkdownSeparator(string line)
    {
        var stripped = line.Replace("|", string.Empty).Replace("-", string.Empty).Replace(":", string.Empty).Trim();
        return stripped.Length == 0 && line.Contains('-');
    }

    private static List<string> ParseDelimitedLine(string line, char delimiter)
    {
        var effective = delimiter == '|' ? line.Trim().Trim('|') : line;
        var values = new List<string>();
        var current = new StringBuilder();
        var inQuotes = false;

        for (var i = 0; i < effective.Length; i++)
        {
            var ch = effective[i];
            if (ch == '"')
            {
                if (inQuotes && i + 1 < effective.Length && effective[i + 1] == '"')
                {
                    current.Append('"');
                    i++;
                }
                else
                {
                    inQuotes = !inQuotes;
                }

                continue;
            }

            if (ch == delimiter && !inQuotes)
            {
                values.Add(current.ToString().Trim());
                current.Clear();
                continue;
            }

            current.Append(ch);
        }

        values.Add(current.ToString().Trim());
        return values;
    }

    private static string NormalizeHeader(string value)
    {
        var cleaned = Regex.Replace(value ?? string.Empty, @"[^\p{L}\p{N}]+", string.Empty, RegexOptions.CultureInvariant);
        return cleaned.Trim().ToLowerInvariant();
    }

    private static string? GetFirst(IDictionary<string, string?> values, IEnumerable<string> aliases)
    {
        foreach (var alias in aliases)
        {
            foreach (var entry in values)
            {
                if (NormalizeHeader(entry.Key) == NormalizeHeader(alias) && !string.IsNullOrWhiteSpace(entry.Value))
                {
                    return entry.Value?.Trim();
                }
            }
        }

        return null;
    }

    private static void AddConsumed(HashSet<string> consumed, IEnumerable<string> aliases, IDictionary<string, string?> values)
    {
        foreach (var entry in values.Keys)
        {
            if (aliases.Any(alias => NormalizeHeader(alias) == NormalizeHeader(entry)))
            {
                consumed.Add(entry);
            }
        }
    }

    private static decimal? ParseDecimal(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        var normalized = value.Trim()
            .Replace("R$", string.Empty, StringComparison.OrdinalIgnoreCase)
            .Replace("%", string.Empty, StringComparison.OrdinalIgnoreCase)
            .Replace(" ", string.Empty)
            .Trim();

        var hasComma = normalized.Contains(',');
        var hasDot = normalized.Contains('.');

        if (hasDot && !hasComma && decimal.TryParse(normalized, NumberStyles.Any, CultureInfo.InvariantCulture, out var dottedInvariant))
        {
            return dottedInvariant;
        }

        if (hasComma && !hasDot)
        {
            normalized = normalized.Replace(".", string.Empty).Replace(",", ".");
            if (decimal.TryParse(normalized, NumberStyles.Any, CultureInfo.InvariantCulture, out var commaInvariant))
            {
                return commaInvariant;
            }
        }

        if (decimal.TryParse(normalized, NumberStyles.Any, CultureInfo.InvariantCulture, out var invariant))
        {
            return invariant;
        }

        if (decimal.TryParse(normalized, NumberStyles.Any, CultureInfo.GetCultureInfo("pt-BR"), out var ptBr))
        {
            return ptBr;
        }

        normalized = normalized.Replace(".", string.Empty).Replace(",", ".");
        return decimal.TryParse(normalized, NumberStyles.Any, CultureInfo.InvariantCulture, out var fallback)
            ? fallback
            : null;
    }
}
