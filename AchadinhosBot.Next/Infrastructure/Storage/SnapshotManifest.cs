using System.Text.Json;

namespace AchadinhosBot.Next.Infrastructure.Storage;

internal sealed record SnapshotFileEntry(string RelativePath, long Bytes, long Lines, string Sha256, bool Exists = true);

internal sealed record SnapshotManifest(string SnapshotId, string ScopeId, DateTimeOffset CreatedAtUtc, string State, IReadOnlyList<SnapshotFileEntry> Files)
{
    internal static string CreateSnapshotId() => $"log-{DateTimeOffset.UtcNow:yyyyMMddHHmmssfff}-{Guid.NewGuid():N}";
    internal static bool IsValidSnapshotId(string? value) => value is not null && System.Text.RegularExpressions.Regex.IsMatch(value, "^log-[0-9]{17}-[0-9a-f]{32}$", System.Text.RegularExpressions.RegexOptions.CultureInvariant);
    internal string ToJson() => JsonSerializer.Serialize(this, new JsonSerializerOptions(JsonSerializerDefaults.Web));
    internal static SnapshotManifest? FromJson(string json) => JsonSerializer.Deserialize<SnapshotManifest>(json, new JsonSerializerOptions(JsonSerializerDefaults.Web));
}
