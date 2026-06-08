using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Application.Services;
using AchadinhosBot.Next.Domain.Logs;
using Microsoft.Extensions.Logging.Abstractions;

namespace AchadinhosBot.Next.Tests;

public sealed class ConversionAuditLoggerTests
{
    [Fact]
    public async Task AppendAsync_PersistsEntryThroughStore()
    {
        var store = new CapturingConversionLogStore();
        var logger = new ConversionAuditLogger(store, NullLogger<ConversionAuditLogger>.Instance);
        var entry = new ConversionLogEntry
        {
            Source = "telegram",
            Store = "Shopee",
            Success = true,
            OriginalUrl = "https://s.shopee.com.br/AUpvSsCTgY",
            ConvertedUrl = "https://s.shopee.com.br/converted"
        };

        await logger.AppendAsync(entry, CancellationToken.None);

        var captured = Assert.Single(store.Entries);
        Assert.Same(entry, captured);
    }

    [Fact]
    public async Task AppendAsync_DoesNotThrowWhenAuditStoreFails()
    {
        var store = new CapturingConversionLogStore { ThrowOnAppend = true };
        var logger = new ConversionAuditLogger(store, NullLogger<ConversionAuditLogger>.Instance);

        await logger.AppendAsync(new ConversionLogEntry
        {
            Source = "telegram",
            Store = "Shopee",
            Success = false,
            OriginalUrl = "https://s.shopee.com.br/AUpvSsCTgY",
            Error = "disk unavailable"
        }, CancellationToken.None);

        Assert.Empty(store.Entries);
    }

    private sealed class CapturingConversionLogStore : IConversionLogStore
    {
        public List<ConversionLogEntry> Entries { get; } = new();
        public bool ThrowOnAppend { get; set; }

        public Task AppendAsync(ConversionLogEntry entry, CancellationToken cancellationToken)
        {
            if (ThrowOnAppend)
            {
                throw new InvalidOperationException("audit failed");
            }

            Entries.Add(entry);
            return Task.CompletedTask;
        }

        public Task<IReadOnlyList<ConversionLogEntry>> QueryAsync(ConversionLogQuery query, CancellationToken cancellationToken)
            => Task.FromResult<IReadOnlyList<ConversionLogEntry>>(Entries);

        public Task ClearAsync(CancellationToken cancellationToken)
        {
            Entries.Clear();
            return Task.CompletedTask;
        }
    }
}
