using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Application.Services;
using AchadinhosBot.Next.Domain.Logs;

namespace AchadinhosBot.Next.Tests;

public sealed class WhatsAppOutboundDedupeKeyBuilderTests
{
    [Fact]
    public async Task BuildAsync_ShouldUseTargetUrlForOfficialTrackingLinks()
    {
        var store = new FakeLinkTrackingStore(
            new LinkTrackingEntry
            {
                Id = "ML-019168",
                Slug = "ML-019168",
                TargetUrl = "https://www.mercadolivre.com.br/p/MLB63459487?matt_tool=98187057&matt_word=land177"
            },
            new LinkTrackingEntry
            {
                Id = "ML-019170",
                Slug = "ML-019170",
                TargetUrl = "https://www.mercadolivre.com.br/p/MLB63459487?matt_tool=98187057&matt_word=land177"
            });

        var first = await WhatsAppOutboundDedupeKeyBuilder.BuildAsync(
            "ZapOfertas",
            "120363405661434395@g.us",
            "Jogo de copos https://reidasofertas.ia.br/r/ML-W019168",
            true,
            true,
            store,
            CancellationToken.None);
        var second = await WhatsAppOutboundDedupeKeyBuilder.BuildAsync(
            "ZapOfertas",
            "120363405661434395@g.us",
            "Oferta relampago do mesmo item https://reidasofertas.ia.br/r/ML-W019170",
            true,
            true,
            store,
            CancellationToken.None);

        Assert.Equal(first, second);
    }

    [Fact]
    public async Task BuildAsync_ShouldKeepTextBasedDedupeOutsideOfficialDestination()
    {
        var store = new FakeLinkTrackingStore();

        var first = await WhatsAppOutboundDedupeKeyBuilder.BuildAsync(
            "ZapOfertas",
            "120363407838515221@g.us",
            "Oferta A https://reidasofertas.ia.br/r/ML-W019168",
            true,
            false,
            store,
            CancellationToken.None);
        var second = await WhatsAppOutboundDedupeKeyBuilder.BuildAsync(
            "ZapOfertas",
            "120363407838515221@g.us",
            "Oferta B https://reidasofertas.ia.br/r/ML-W019170",
            true,
            false,
            store,
            CancellationToken.None);

        Assert.NotEqual(first, second);
    }

    private sealed class FakeLinkTrackingStore(params LinkTrackingEntry[] entries) : ILinkTrackingStore
    {
        private readonly Dictionary<string, LinkTrackingEntry> _entries = entries.ToDictionary(x => x.Id, StringComparer.OrdinalIgnoreCase);

        public Task<LinkTrackingEntry> CreateAsync(string targetUrl, CancellationToken cancellationToken)
            => throw new NotSupportedException();

        public Task<LinkTrackingEntry> CreateAsync(LinkTrackingCreateRequest request, CancellationToken cancellationToken)
            => throw new NotSupportedException();

        public Task<LinkTrackingEntry> GetOrCreateAsync(string targetUrl, CancellationToken cancellationToken)
            => throw new NotSupportedException();

        public Task<LinkTrackingEntry> GetOrCreateAsync(LinkTrackingCreateRequest request, CancellationToken cancellationToken)
            => throw new NotSupportedException();

        public Task<LinkTrackingEntry?> RegisterClickAsync(string trackingId, CancellationToken cancellationToken)
            => throw new NotSupportedException();

        public Task<LinkTrackingEntry?> GetLinkAsync(string id, CancellationToken cancellationToken)
            => Task.FromResult(_entries.GetValueOrDefault(id));

        public Task<IReadOnlyList<LinkTrackingEntry>> ListAsync(CancellationToken cancellationToken)
            => Task.FromResult<IReadOnlyList<LinkTrackingEntry>>(_entries.Values.ToArray());
    }
}
