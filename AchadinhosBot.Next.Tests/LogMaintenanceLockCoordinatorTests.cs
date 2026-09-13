using AchadinhosBot.Next.Infrastructure.Storage;

namespace AchadinhosBot.Next.Tests;

public sealed class LogMaintenanceLockCoordinatorTests
{
    [Fact]
    public async Task SameScope_ExcludesConcurrentAcquisition()
    {
        var root = Path.Combine(Path.GetTempPath(), $"achadinhos-lock-{Guid.NewGuid():N}");
        try
        {
            var coordinator = new LogMaintenanceLockCoordinator(root);
            await using var first = await coordinator.AcquireAsync("clicks", CancellationToken.None);
            using var timeout = new CancellationTokenSource(TimeSpan.FromMilliseconds(50));
            await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
            {
                await using var second = await coordinator.AcquireAsync("clicks", timeout.Token);
            });
        }
        finally { if (Directory.Exists(root)) Directory.Delete(root, recursive: true); }
    }

    [Fact]
    public async Task SeparateCoordinators_SharingDataRoot_ExcludeEachOther()
    {
        var root = Path.Combine(Path.GetTempPath(), $"achadinhos-lock-{Guid.NewGuid():N}");
        try
        {
            var firstCoordinator = new LogMaintenanceLockCoordinator(root);
            var secondCoordinator = new LogMaintenanceLockCoordinator(root);
            await using var first = await firstCoordinator.AcquireAsync("conversion-logs", CancellationToken.None);
            using var timeout = new CancellationTokenSource(TimeSpan.FromMilliseconds(150));

            await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
            {
                await using var second = await secondCoordinator.AcquireAsync("conversion-logs", timeout.Token);
            });
        }
        finally { if (Directory.Exists(root)) Directory.Delete(root, recursive: true); }
    }
}
