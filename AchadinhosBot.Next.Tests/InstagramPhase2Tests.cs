using System.Net;
using System.Net.Http.Headers;
using System.Text;
using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Application.Consumers;
using AchadinhosBot.Next.Configuration;
using AchadinhosBot.Next.Domain.Instagram;
using AchadinhosBot.Next.Domain.Logs;
using AchadinhosBot.Next.Domain.Models;
using AchadinhosBot.Next.Domain.Settings;
using AchadinhosBot.Next.Infrastructure.Instagram;
using AchadinhosBot.Next.Infrastructure.Media;
using AchadinhosBot.Next.Infrastructure.Resilience;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace AchadinhosBot.Next.Tests;

public sealed class InstagramPhase2Tests
{
    [Fact]
    public async Task MetaGraphClient_PublishAsync_CreatesCarouselAndPublishesParent()
    {
        var handler = new RecordingHandler();
        handler.Queue(HttpMethod.Head, "https://cdn.example.com/a.jpg", new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new ByteArrayContent(Array.Empty<byte>())
            {
                Headers = { ContentType = new MediaTypeHeaderValue("image/jpeg") }
            }
        });
        handler.Queue(HttpMethod.Get, "https://cdn.example.com/a.jpg", new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new ByteArrayContent(Array.Empty<byte>())
            {
                Headers = { ContentType = new MediaTypeHeaderValue("image/jpeg") }
            }
        });
        handler.Queue(HttpMethod.Head, "https://cdn.example.com/b.jpg", new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new ByteArrayContent(Array.Empty<byte>())
            {
                Headers = { ContentType = new MediaTypeHeaderValue("image/jpeg") }
            }
        });
        handler.Queue(HttpMethod.Get, "https://cdn.example.com/b.jpg", new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new ByteArrayContent(Array.Empty<byte>())
            {
                Headers = { ContentType = new MediaTypeHeaderValue("image/jpeg") }
            }
        });
        handler.Queue(HttpMethod.Post, "https://graph.facebook.com/v19.0/ig-user/media", Json("""{"id":"child-1"}"""));
        handler.Queue(HttpMethod.Post, "https://graph.facebook.com/v19.0/ig-user/media", Json("""{"id":"child-2"}"""));
        handler.Queue(HttpMethod.Post, "https://graph.facebook.com/v19.0/ig-user/media", Json("""{"id":"carousel-parent"}"""));
        handler.Queue(HttpMethod.Post, "https://graph.facebook.com/v19.0/ig-user/media_publish", Json("""{"id":"media-123"}"""));

        var client = new MetaGraphClient(new FakeHttpClientFactory(handler));
        var settings = new InstagramPublishSettings
        {
            Enabled = true,
            AccessToken = "token-123",
            InstagramUserId = "ig-user"
        };

        var result = await client.PublishAsync(
            settings,
            "feed",
            new[] { "https://cdn.example.com/a.jpg", "https://cdn.example.com/b.jpg" },
            "Legenda teste",
            CancellationToken.None);

        Assert.True(result.Success);
        Assert.Equal("media-123", result.MediaId);

        var posts = handler.Requests.Where(r => r.Method == HttpMethod.Post).ToList();
        Assert.Equal(4, posts.Count);
        Assert.Contains("is_carousel_item=true", posts[0].Body);
        Assert.Contains("is_carousel_item=true", posts[1].Body);
        Assert.Contains("media_type=CAROUSEL", posts[2].Body);
        Assert.Contains("children=child-1%2Cchild-2", posts[2].Body);
    }

    [Fact]
    public async Task InstagramWebhookService_ProcessAsync_QueuesReplyAndDm_ForKeywordComment()
    {
        var settingsStore = new StubSettingsStore(new AutomationSettings
        {
            InstagramPublish = new InstagramPublishSettings
            {
                Enabled = true,
                AccessToken = "token-123",
                InstagramUserId = "ig-owner",
                AutoReplyEnabled = true,
                AutoDmEnabled = true,
                ReplyTemplate = "Aqui esta: {link}"
            }
        });
        var publishStore = new StubPublishStore(new InstagramPublishDraft
        {
            Id = "draft-1",
            MediaId = "media-1",
            Ctas = new List<InstagramCtaOption>
            {
                new() { Keyword = "LINK", Link = "https://oferta.example.com" }
            }
        });
        var commentStore = new StubCommentStore();
        var logStore = new StubPublishLogStore();
        var publisher = new RecordingInstagramPublisher();
        var service = new InstagramWebhookService(
            settingsStore,
            publishStore,
            commentStore,
            logStore,
            publisher,
            new InMemoryInstagramOutboxStore(),
            new StubIdempotencyStore(),
            NullLogger<InstagramWebhookService>.Instance);

        var body = """
        {
          "entry": [
            {
              "changes": [
                {
                  "field": "comments",
                  "value": {
                    "id": "comment-1",
                    "text": "quero LINK",
                    "media_id": "media-1",
                    "from": { "id": "user-99", "username": "cliente" }
                  }
                }
              ]
            }
          ]
        }
        """;

        var result = await service.ProcessAsync(body, CancellationToken.None);

        Assert.True(result.Success);
        Assert.Equal(1, result.CommentsProcessed);
        Assert.Single(publisher.Replies);
        Assert.Single(publisher.DirectMessages);
        Assert.Equal("comment-1", publisher.Replies[0].CommentId);
        Assert.Equal("user-99", publisher.DirectMessages[0].RecipientId);
        Assert.Contains(commentStore.Items, x => x.CommentId == "comment-1" && x.Status == "processing" && x.DmStatus == "queued");
    }

    [Fact]
    public async Task InstagramPublishService_QueuePublishAsync_PersistsOutbox_WhenPublisherFails()
    {
        var dir = Path.Combine(Path.GetTempPath(), "achadinhos-instagram-tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);

        try
        {
            var outbox = new FileInstagramOutboundOutboxStore(Options.Create(new MessagingOptions { DataDirectory = dir }));
            var service = new InstagramPublishService(
                new StubSettingsStore(new AutomationSettings
                {
                    InstagramPublish = new InstagramPublishSettings
                    {
                        Enabled = true,
                        AccessToken = "token-123",
                        InstagramUserId = "ig-user"
                    }
                }),
                new StubPublishStore(new InstagramPublishDraft
                {
                    Id = "draft-1",
                    ProductName = "Produto",
                    Caption = "Legenda",
                    ImageUrls = new List<string> { "https://cdn.example.com/a.jpg" }
                }),
                new StubPublishLogStore(),
                new FakeHttpClientFactory(new RecordingHandler()),
                new InMemoryMediaStore(),
                new StubMetaGraphClient(),
                new ThrowingInstagramPublisher(),
                outbox,
                new StubCatalogOfferStore(),
                Options.Create(new WebhookOptions { PublicBaseUrl = "https://bot.example.com" }),
                NullLogger<InstagramPublishService>.Instance);

            var result = await service.QueuePublishAsync("draft-1", "codex", CancellationToken.None);
            var pending = await outbox.ListPendingAsync(CancellationToken.None);

            Assert.True(result.Accepted);
            Assert.True(result.PersistedLocally);
            Assert.Equal("local-outbox", result.Mode);
            Assert.Single(pending);
            Assert.Equal(nameof(PublishInstagramPostCommand), pending[0].MessageType);
        }
        finally
        {
            Directory.Delete(dir, true);
        }
    }

    [Fact]
    public async Task InstagramPublishService_ExecutePublishAsync_SyncsCatalog_WhenDraftRequestsIt()
    {
        var catalogStore = new StubCatalogOfferStore();
        var publishStore = new StubPublishStore(new InstagramPublishDraft
        {
            Id = "draft-2",
            ProductName = "Produto Catalogo",
            Caption = "Confira https://oferta.example.com",
            ImageUrls = new List<string> { "https://cdn.example.com/a.jpg" },
            Ctas = new List<InstagramCtaOption> { new() { Keyword = "LINK", Link = "https://oferta.example.com" } },
            SendToCatalog = true
        });

        var service = new InstagramPublishService(
            new StubSettingsStore(new AutomationSettings
            {
                InstagramPublish = new InstagramPublishSettings
                {
                    Enabled = true,
                    AccessToken = "token-123",
                    InstagramUserId = "ig-user"
                }
            }),
            publishStore,
            new StubPublishLogStore(),
            new FakeHttpClientFactory(new RecordingHandler()),
            new InMemoryMediaStore(),
            new StubMetaGraphClient(),
            new RecordingInstagramPublisher(),
            new InMemoryInstagramOutboxStore(),
            catalogStore,
            Options.Create(new WebhookOptions { PublicBaseUrl = "https://bot.example.com" }),
            NullLogger<InstagramPublishService>.Instance);

        var result = await service.ExecutePublishAsync("draft-2", CancellationToken.None);

        Assert.True(result.Success);
        Assert.Single(catalogStore.SyncedDraftIds);
        Assert.Equal("draft-2", catalogStore.SyncedDraftIds[0]);
    }

    private static HttpResponseMessage Json(string body)
    {
        return new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(body, Encoding.UTF8, "application/json")
        };
    }

    private sealed class RecordingHandler : HttpMessageHandler
    {
        private readonly Queue<(HttpMethod Method, string Url, HttpResponseMessage Response)> _responses = new();
        public List<(HttpMethod Method, string Url, string Body)> Requests { get; } = new();

        public void Queue(HttpMethod method, string url, HttpResponseMessage response)
        {
            _responses.Enqueue((method, url, response));
        }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var body = request.Content is null ? string.Empty : await request.Content.ReadAsStringAsync(cancellationToken);
            Requests.Add((request.Method, request.RequestUri!.ToString(), body));

            var next = _responses.Dequeue();
            Assert.Equal(next.Method, request.Method);
            Assert.Equal(next.Url, request.RequestUri!.ToString());
            return next.Response;
        }
    }

    private sealed class FakeHttpClientFactory : IHttpClientFactory
    {
        private readonly HttpClient _client;

        public FakeHttpClientFactory(HttpMessageHandler handler)
        {
            _client = new HttpClient(handler, disposeHandler: false);
        }

        public HttpClient CreateClient(string name) => _client;
    }

    private sealed class StubSettingsStore : ISettingsStore
    {
        private readonly AutomationSettings _settings;
        public StubSettingsStore(AutomationSettings settings) => _settings = settings;
        public Task<AutomationSettings> GetAsync(CancellationToken ct) => Task.FromResult(_settings);
        public Task SaveAsync(AutomationSettings settings, CancellationToken ct) => Task.CompletedTask;
    }

    private sealed class StubPublishStore : IInstagramPublishStore
    {
        private readonly List<InstagramPublishDraft> _drafts;

        public StubPublishStore(params InstagramPublishDraft[] drafts)
        {
            _drafts = drafts.ToList();
        }

        public Task<IReadOnlyList<InstagramPublishDraft>> ListAsync(CancellationToken ct) => Task.FromResult<IReadOnlyList<InstagramPublishDraft>>(_drafts.ToList());
        public Task<InstagramPublishDraft?> GetAsync(string id, CancellationToken ct) => Task.FromResult(_drafts.FirstOrDefault(x => x.Id == id));
        public Task SaveAsync(InstagramPublishDraft draft, CancellationToken ct) { _drafts.Add(draft); return Task.CompletedTask; }
        public Task UpdateAsync(InstagramPublishDraft draft, CancellationToken ct)
        {
            var idx = _drafts.FindIndex(x => x.Id == draft.Id);
            if (idx >= 0) _drafts[idx] = draft;
            else _drafts.Add(draft);
            return Task.CompletedTask;
        }
        public Task ClearAsync(CancellationToken ct) { _drafts.Clear(); return Task.CompletedTask; }
    }

    private sealed class StubCommentStore : IInstagramCommentStore
    {
        public List<InstagramCommentPending> Items { get; } = new();

        public Task<IReadOnlyList<InstagramCommentPending>> ListPendingAsync(CancellationToken ct)
            => Task.FromResult<IReadOnlyList<InstagramCommentPending>>(Items.Where(x => x.Status == "pending").ToList());

        public Task AddAsync(InstagramCommentPending comment, CancellationToken ct)
        {
            Items.Add(comment);
            return Task.CompletedTask;
        }

        public Task<InstagramCommentPending?> GetAsync(string id, CancellationToken ct)
            => Task.FromResult(Items.FirstOrDefault(x => x.Id == id));

        public Task UpdateAsync(InstagramCommentPending comment, CancellationToken ct)
        {
            var idx = Items.FindIndex(x => x.Id == comment.Id);
            if (idx >= 0) Items[idx] = comment;
            else Items.Add(comment);
            return Task.CompletedTask;
        }
    }

    private sealed class StubPublishLogStore : IInstagramPublishLogStore
    {
        public List<InstagramPublishLogEntry> Entries { get; } = new();
        public Task AppendAsync(InstagramPublishLogEntry entry, CancellationToken ct) { Entries.Add(entry); return Task.CompletedTask; }
        public Task<IReadOnlyList<InstagramPublishLogEntry>> ListAsync(int take, CancellationToken ct) => Task.FromResult<IReadOnlyList<InstagramPublishLogEntry>>(Entries.Take(take).ToList());
        public Task ClearAsync(CancellationToken ct) { Entries.Clear(); return Task.CompletedTask; }
    }

    private sealed class RecordingInstagramPublisher : IInstagramOutboundPublisher
    {
        public List<ReplyInstagramCommentCommand> Replies { get; } = new();
        public List<SendInstagramDirectMessageCommand> DirectMessages { get; } = new();

        public Task PublishAsync(PublishInstagramPostCommand command, CancellationToken cancellationToken) => Task.CompletedTask;
        public Task PublishAsync(ReplyInstagramCommentCommand command, CancellationToken cancellationToken) { Replies.Add(command); return Task.CompletedTask; }
        public Task PublishAsync(SendInstagramDirectMessageCommand command, CancellationToken cancellationToken) { DirectMessages.Add(command); return Task.CompletedTask; }
    }

    private sealed class ThrowingInstagramPublisher : IInstagramOutboundPublisher
    {
        public Task PublishAsync(PublishInstagramPostCommand command, CancellationToken cancellationToken) => throw new InvalidOperationException("rabbitmq offline");
        public Task PublishAsync(ReplyInstagramCommentCommand command, CancellationToken cancellationToken) => throw new InvalidOperationException("rabbitmq offline");
        public Task PublishAsync(SendInstagramDirectMessageCommand command, CancellationToken cancellationToken) => throw new InvalidOperationException("rabbitmq offline");
    }

    private sealed class InMemoryInstagramOutboxStore : IInstagramOutboundOutboxStore
    {
        public List<InstagramOutboundEnvelope> Items { get; } = new();
        public Task SaveAsync(InstagramOutboundEnvelope envelope, CancellationToken cancellationToken) { Items.Add(envelope); return Task.CompletedTask; }
        public Task<IReadOnlyList<InstagramOutboundEnvelope>> ListPendingAsync(CancellationToken cancellationToken) => Task.FromResult<IReadOnlyList<InstagramOutboundEnvelope>>(Items.ToList());
        public Task DeleteAsync(string messageId, CancellationToken cancellationToken) { Items.RemoveAll(x => x.MessageId == messageId); return Task.CompletedTask; }
    }

    private sealed class StubIdempotencyStore : IIdempotencyStore
    {
        private readonly HashSet<string> _keys = new(StringComparer.OrdinalIgnoreCase);
        public bool TryBegin(string key, TimeSpan ttl) => _keys.Add(key);
        public void RemoveByPrefix(string prefix) { }
    }

    private sealed class StubMetaGraphClient : IMetaGraphClient
    {
        public Task<MetaGraphOperationResult> ValidateConfigurationAsync(InstagramPublishSettings settings, CancellationToken cancellationToken)
            => Task.FromResult(new MetaGraphOperationResult(true));

        public Task<MetaGraphOperationResult> GetMediaStatusAsync(InstagramPublishSettings settings, string mediaId, CancellationToken cancellationToken)
            => Task.FromResult(new MetaGraphOperationResult(true, RawResponse: "{}"));

        public Task<MetaGraphPublishResult> PublishAsync(InstagramPublishSettings settings, string postType, IReadOnlyList<string> mediaUrls, string caption, CancellationToken cancellationToken)
            => Task.FromResult(new MetaGraphPublishResult(true, "media-1"));

        public Task<MetaGraphOperationResult> ReplyToCommentAsync(InstagramPublishSettings settings, string commentId, string message, CancellationToken cancellationToken)
            => Task.FromResult(new MetaGraphOperationResult(true));

        public Task<MetaGraphOperationResult> SendDirectMessageAsync(InstagramPublishSettings settings, string recipientId, string message, CancellationToken cancellationToken)
            => Task.FromResult(new MetaGraphOperationResult(true));
    }

    private sealed class StubCatalogOfferStore : ICatalogOfferStore
    {
        public List<string> SyncedDraftIds { get; } = new();

        public Task<CatalogSyncResult> SyncFromPublishedDraftsAsync(IReadOnlyList<InstagramPublishDraft> drafts, CancellationToken cancellationToken)
        {
            SyncedDraftIds.AddRange(drafts.Select(x => x.Id));
            return Task.FromResult(new CatalogSyncResult { Created = drafts.Count, TotalActive = drafts.Count, HighestItemNumber = drafts.Count });
        }

        public Task<IReadOnlyList<CatalogOfferItem>> ListAsync(string? search, int limit, CancellationToken cancellationToken)
            => Task.FromResult<IReadOnlyList<CatalogOfferItem>>(Array.Empty<CatalogOfferItem>());

        public Task<CatalogOfferItem?> FindByCodeAsync(string query, CancellationToken cancellationToken)
            => Task.FromResult<CatalogOfferItem?>(null);

        public Task<IReadOnlyDictionary<string, CatalogOfferItem>> GetByDraftIdAsync(CancellationToken cancellationToken)
            => Task.FromResult<IReadOnlyDictionary<string, CatalogOfferItem>>(new Dictionary<string, CatalogOfferItem>());
    }
}
