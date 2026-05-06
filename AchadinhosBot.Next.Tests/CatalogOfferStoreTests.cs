using System.Reflection;
using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Configuration;
using AchadinhosBot.Next.Domain.Instagram;
using AchadinhosBot.Next.Domain.Logs;
using AchadinhosBot.Next.Domain.Models;
using AchadinhosBot.Next.Infrastructure.Storage;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Options;
namespace AchadinhosBot.Next.Tests;

public sealed class CatalogOfferStoreTests
{
    [Fact]
    public void ResolveOfferUrl_ShouldPreferConvertedOfferUrl_WhenPresent()
    {
        var method = typeof(CatalogOfferStore).GetMethod("ResolveOfferUrl", BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(method);

        var draft = new InstagramPublishDraft
        {
            OriginalOfferUrl = "https://www.mercadolivre.com.br/p/MLB12345678",
            OfferUrl = "https://reidasofertas.ia.br/r/ML-000250"
        };

        var result = (string)method!.Invoke(null, new object[] { draft })!;

        Assert.Equal("https://reidasofertas.ia.br/r/ML-000250", result);
    }

    [Fact]
    public async Task ListAsync_ShouldRecoverFromLatestProdBackupWhenPrimaryFileIsEmpty()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), "achadinhos-catalog-tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempDir);
        var dataDir = Path.Combine(tempDir, "data");
        var versionsDir = Path.Combine(dataDir, "versions");
        Directory.CreateDirectory(versionsDir);

        var primaryPath = Path.Combine(dataDir, "catalog-offers.prod.json");
        await File.WriteAllTextAsync(primaryPath, string.Empty);

        var backupPath = Path.Combine(versionsDir, $"catalog-offers.prod.{DateTimeOffset.UtcNow:yyyyMMdd-HHmmss-fff}-{Guid.NewGuid():N}.json.bak");
        await File.WriteAllTextAsync(backupPath, """
        {
          "NextItemNumber": 11,
          "Items": [
            {
              "ItemNumber": 1,
              "Keyword": "CREATINA",
              "DraftId": "87ec7ed462e647a4a6c814231deca8ec",
              "ProductName": "Creatina Monohidratada Pura 1kg Dark Lab Unidade Sem sabor - R$ 69,9",
              "Store": "Loja",
              "OfferUrl": "https://meli.la/22qR7Py",
              "Active": true,
              "CatalogTarget": "prod"
            }
          ]
        }
        """);

        var store = new CatalogOfferStore(null, dataDir);
        var items = await store.ListAsync(null, 20, CancellationToken.None, catalogTarget: "prod");

        Assert.NotEmpty(items);
    }

    [Fact]
    public async Task SyncFromPublishedDraftsAsync_CreatesAffiliateTrackingMetadata()
    {
        var dataDir = Path.Combine(Path.GetTempPath(), "achadinhos-catalog-tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dataDir);
        var affiliate = new FakeAffiliateLinkService(new AffiliateLinkResult(
            true,
            "https://www.mercadolivre.com.br/p/MLB123?matt_tool=98187057&matt_word=land177",
            "Mercado Livre",
            true,
            null,
            null,
            true,
            "corrigido"));
        var tracking = new FakeLinkTrackingStore();
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["Catalog:DataDirectory"] = dataDir })
            .Build();
        var store = new CatalogOfferStore(
            null,
            affiliate,
            tracking,
            new FakePublishLogStore(),
            Options.Create(new WebhookOptions { PublicBaseUrl = "https://achadinhos.reidasofertas.ia.br" }),
            config,
            new FakeEnvironment(dataDir));

        await store.SyncFromPublishedDraftsAsync(new[]
        {
            new InstagramPublishDraft
            {
                Id = "draft-ml",
                Status = "published",
                SendToCatalog = true,
                CatalogTarget = CatalogTargets.Prod,
                ProductName = "Produto ML",
                OfferUrl = "https://meli.la/outro-afiliado"
            }
        }, CancellationToken.None);

        var items = await store.ListAsync(null, 10, CancellationToken.None, CatalogTargets.Prod);
        var item = Assert.Single(items);
        Assert.Equal(CatalogAffiliateValidationStatuses.Valid, item.AffiliateValidationStatus);
        Assert.Equal("https://www.mercadolivre.com.br/p/MLB123?matt_tool=98187057&matt_word=land177", item.AffiliateTargetUrl);
        Assert.StartsWith("https://reidasofertas.ia.br/r/ML-", item.TrackingUrl);
        Assert.Equal(item.AffiliateTargetUrl, tracking.Created.Single().TargetUrl);
    }

    [Fact]
    public async Task SyncFromPublishedDraftsAsync_BlocksInvalidAffiliateLink()
    {
        var dataDir = Path.Combine(Path.GetTempPath(), "achadinhos-catalog-tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dataDir);
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["Catalog:DataDirectory"] = dataDir })
            .Build();
        var affiliate = new FakeAffiliateLinkService(new AffiliateLinkResult(
            false,
            null,
            "Mercado Livre",
            false,
            "Link Mercado Livre invalido",
            "sem afiliado",
            false,
            null));
        var store = new CatalogOfferStore(
            null,
            affiliate,
            new FakeLinkTrackingStore(),
            new FakePublishLogStore(),
            Options.Create(new WebhookOptions { PublicBaseUrl = "https://reidasofertas.ia.br" }),
            config,
            new FakeEnvironment(dataDir));

        await store.SyncFromPublishedDraftsAsync(new[]
        {
            new InstagramPublishDraft
            {
                Id = "draft-invalid",
                Status = "published",
                SendToCatalog = true,
                CatalogTarget = CatalogTargets.Prod,
                ProductName = "Produto ruim",
                OfferUrl = "https://www.mercadolivre.com.br/p/MLB123?matt_tool=terceiro&matt_word=outro"
            }
        }, CancellationToken.None);

        var activeItems = await store.ListAsync(null, 10, CancellationToken.None, CatalogTargets.Prod);
        Assert.Empty(activeItems);

        var audit = await store.AuditLinksAsync(CancellationToken.None, CatalogTargets.Prod);
        Assert.Equal(1, audit.InvalidItems);
        Assert.Equal(1, audit.BlockedItems);
    }

    private sealed class FakeAffiliateLinkService(AffiliateLinkResult result) : IAffiliateLinkService
    {
        public Task<AffiliateLinkResult> ConvertAsync(string rawUrl, CancellationToken cancellationToken, string? source = null, bool forceResolution = false)
            => Task.FromResult(result);
    }

    private sealed class FakeLinkTrackingStore : ILinkTrackingStore
    {
        private readonly Dictionary<string, LinkTrackingEntry> _items = new(StringComparer.OrdinalIgnoreCase);
        public List<LinkTrackingCreateRequest> Created { get; } = new();

        public Task<LinkTrackingEntry> CreateAsync(LinkTrackingCreateRequest request, CancellationToken cancellationToken)
            => CreateCoreAsync(request);

        public Task<LinkTrackingEntry> CreateAsync(string targetUrl, CancellationToken cancellationToken)
            => CreateCoreAsync(new LinkTrackingCreateRequest { TargetUrl = targetUrl });

        public Task<LinkTrackingEntry> GetOrCreateAsync(LinkTrackingCreateRequest request, CancellationToken cancellationToken)
            => CreateCoreAsync(request);

        public Task<LinkTrackingEntry> GetOrCreateAsync(string targetUrl, CancellationToken cancellationToken)
            => CreateCoreAsync(new LinkTrackingCreateRequest { TargetUrl = targetUrl });

        public Task<LinkTrackingEntry?> RegisterClickAsync(string trackingId, CancellationToken cancellationToken)
            => Task.FromResult(_items.TryGetValue(trackingId, out var entry) ? entry : null);

        public Task<LinkTrackingEntry?> GetLinkAsync(string id, CancellationToken cancellationToken)
            => Task.FromResult(_items.TryGetValue(id, out var entry) ? entry : null);

        public Task<IReadOnlyList<LinkTrackingEntry>> ListAsync(CancellationToken cancellationToken)
            => Task.FromResult<IReadOnlyList<LinkTrackingEntry>>(_items.Values.ToArray());

        private Task<LinkTrackingEntry> CreateCoreAsync(LinkTrackingCreateRequest request)
        {
            Created.Add(request);
            var id = request.Store?.Contains("Mercado", StringComparison.OrdinalIgnoreCase) == true ? "ML-000200" : "LK-000200";
            var entry = new LinkTrackingEntry
            {
                Id = id,
                Slug = id,
                TargetUrl = request.TargetUrl,
                Store = request.Store ?? string.Empty,
                OriginSurface = request.OriginSurface ?? string.Empty,
                Campaign = request.Campaign
            };
            _items[id] = entry;
            return Task.FromResult(entry);
        }
    }

    private sealed class FakePublishLogStore : IInstagramPublishLogStore
    {
        public List<InstagramPublishLogEntry> Entries { get; } = new();
        public Task AppendAsync(InstagramPublishLogEntry entry, CancellationToken ct)
        {
            Entries.Add(entry);
            return Task.CompletedTask;
        }

        public Task<IReadOnlyList<InstagramPublishLogEntry>> ListAsync(int take, CancellationToken ct)
            => Task.FromResult<IReadOnlyList<InstagramPublishLogEntry>>(Entries.TakeLast(take).ToArray());

        public Task ClearAsync(CancellationToken ct)
        {
            Entries.Clear();
            return Task.CompletedTask;
        }
    }

    private sealed class FakeEnvironment(string contentRootPath) : IWebHostEnvironment
    {
        public string EnvironmentName { get; set; } = "Development";
        public string ApplicationName { get; set; } = "Tests";
        public string WebRootPath { get; set; } = contentRootPath;
        public IFileProvider WebRootFileProvider { get; set; } = new NullFileProvider();
        public string ContentRootPath { get; set; } = contentRootPath;
        public IFileProvider ContentRootFileProvider { get; set; } = new NullFileProvider();
    }
}
