using AchadinhosBot.Next.Infrastructure.Storage;

namespace AchadinhosBot.Next.Tests;

public sealed class SnapshotManifestTests
{
    [Fact]
    public void ServerSnapshotId_IsValidAndManifestRoundTrips()
    {
        var id = SnapshotManifest.CreateSnapshotId();
        var manifest = new SnapshotManifest(id, "conversion-logs", DateTimeOffset.UtcNow, "prepared", [new("conversion-logs.jsonl", 3, 1, "abc")]);
        var restored = SnapshotManifest.FromJson(manifest.ToJson());
        Assert.True(SnapshotManifest.IsValidSnapshotId(id));
        Assert.NotNull(restored);
        Assert.Equal(manifest.SnapshotId, restored!.SnapshotId);
        Assert.Equal(manifest.Files.Single(), restored.Files.Single());
    }

    [Theory]
    [InlineData("../log-20260101000000000-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")]
    [InlineData("log-invalid")]
    public void InvalidSnapshotId_IsRejected(string id) => Assert.False(SnapshotManifest.IsValidSnapshotId(id));
}
