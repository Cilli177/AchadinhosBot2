using System.Net;
using System.Net.Http.Json;
using System.Text;
using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Configuration;
using AchadinhosBot.Next.Domain.Models;
using AchadinhosBot.Next.Domain.Settings;
using AchadinhosBot.Next.Endpoints;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace AchadinhosBot.Next.Tests;

public sealed class ExternalWebhookEndpointsContractTests
{
    [Fact]
    public async Task BotConversor_UnauthorizedRequestNeverEnqueues()
    {
        await using var host = await Host.CreateAsync();
        var response = await host.Client.PostAsync("/webhook/bot-conversor", Json("{\"message\":\"offer\"}"));

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal(0, host.Orchestrator.Calls);
    }

    [Fact]
    public async Task BotConversor_AuthorizedRequestQueuesWithoutProcessingOffersInHttp()
    {
        await using var host = await Host.CreateAsync();
        using var request = new HttpRequestMessage(HttpMethod.Post, "/webhook/bot-conversor") { Content = Json("{\"message\":\"offer\"}") };
        request.Headers.Add("x-api-key", "webhook-test-key");

        var response = await host.Client.SendAsync(request);
        var payload = await response.Content.ReadFromJsonAsync<BotResponse>();

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(1, host.Orchestrator.Calls);
        Assert.Equal("queued-message", payload!.messageId);
        Assert.Equal("rabbitmq", payload.mode);
        Assert.False(payload.persistedLocally);
    }

    [Fact]
    public async Task Evolution_DuplicateRequestDoesNotMutateSettingsOrWriteAudit()
    {
        await using var host = await Host.CreateAsync(idempotencyAccepted: false);
        using var request = new HttpRequestMessage(HttpMethod.Post, "/webhooks/evolution") { Content = Json("{\"event\":\"connection.update\",\"eventId\":\"same\",\"data\":{\"state\":\"open\"}}") };
        request.Headers.Add("x-api-key", "webhook-test-key");

        var response = await host.Client.SendAsync(request);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(0, host.Settings.SaveCalls);
        Assert.Empty(host.Audit.Actions);
    }

    [Fact]
    public async Task Evolution_MonitoredMembershipEventIsRecorded()
    {
        await using var host = await Host.CreateAsync(monitoredGroupId: "group-1");
        using var request = new HttpRequestMessage(HttpMethod.Post, "/webhooks/evolution") { Content = Json("{\"event\":\"group-participants.update\",\"eventId\":\"membership-1\",\"data\":{\"id\":\"group-1\",\"action\":\"add\",\"participants\":[\"user-1\"]}}") };
        request.Headers.Add("x-api-key", "webhook-test-key");

        var response = await host.Client.SendAsync(request);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var membershipEvent = Assert.Single(host.Membership.Events);
        Assert.Equal("group-1", membershipEvent.GroupId);
        Assert.Equal("user-1", membershipEvent.ParticipantId);
        Assert.Equal("add", membershipEvent.Action);
    }

    private static StringContent Json(string body) => new(body, Encoding.UTF8, "application/json");

    private sealed record BotResponse(string messageId, string mode, bool persistedLocally);

    private sealed class Host : IAsyncDisposable
    {
        private readonly WebApplication _app;
        internal HttpClient Client { get; }
        internal Orchestrator Orchestrator { get; }
        internal Settings Settings { get; }
        internal Membership Membership { get; }
        internal Audit Audit { get; }

        private Host(WebApplication app, HttpClient client, Orchestrator orchestrator, Settings settings, Membership membership, Audit audit)
        {
            _app = app; Client = client; Orchestrator = orchestrator; Settings = settings; Membership = membership; Audit = audit;
        }

        internal static async Task<Host> CreateAsync(bool idempotencyAccepted = true, string? monitoredGroupId = null)
        {
            var builder = WebApplication.CreateBuilder();
            builder.WebHost.UseTestServer();
            var orchestrator = new Orchestrator(); var settings = new Settings(monitoredGroupId); var membership = new Membership(); var audit = new Audit();
            builder.Services.AddSingleton<IMessageOrchestrator>(orchestrator);
            builder.Services.AddSingleton<ISettingsStore>(settings);
            builder.Services.AddSingleton<IWhatsAppGroupMembershipStore>(membership);
            builder.Services.AddSingleton<IAuditTrail>(audit);
            builder.Services.AddSingleton<IIdempotencyStore>(new Idempotency(idempotencyAccepted));
            builder.Services.AddSingleton<IOptions<EvolutionOptions>>(Options.Create(new EvolutionOptions { WebhookSecret = "signature-secret" }));
            builder.Services.AddSingleton<IOptions<WebhookOptions>>(Options.Create(new WebhookOptions { ApiKey = "webhook-test-key" }));
            var app = builder.Build(); app.MapExternalWebhookEndpoints(); await app.StartAsync();
            return new Host(app, app.GetTestClient(), orchestrator, settings, membership, audit);
        }

        public async ValueTask DisposeAsync() { Client.Dispose(); await _app.StopAsync(); await _app.DisposeAsync(); }
    }

    private sealed class Orchestrator : IMessageOrchestrator
    {
        internal int Calls { get; private set; }
        public Task<MessageEnqueueResult> EnqueueBotConversorAsync(string body, IReadOnlyDictionary<string, string> headers, CancellationToken cancellationToken)
        {
            Calls++;
            return Task.FromResult(new MessageEnqueueResult("queued-message", true, false, "rabbitmq", null));
        }
    }

    private sealed class Idempotency(bool accepted) : IIdempotencyStore
    {
        public bool TryBegin(string key, TimeSpan ttl) => accepted;
        public void RemoveByPrefix(string prefix) { }
    }

    private sealed class Settings(string? monitoredGroupId) : ISettingsStore
    {
        private readonly AutomationSettings _settings = new() { MonitoredGroupIds = string.IsNullOrWhiteSpace(monitoredGroupId) ? [] : [monitoredGroupId] };
        internal int SaveCalls { get; private set; }
        public Task<AutomationSettings> GetAsync(CancellationToken cancellationToken) => Task.FromResult(_settings);
        public Task SaveAsync(AutomationSettings settings, CancellationToken cancellationToken) { SaveCalls++; return Task.CompletedTask; }
    }

    private sealed class Membership : IWhatsAppGroupMembershipStore
    {
        internal List<WhatsAppGroupMembershipEvent> Events { get; } = [];
        public Task AppendAsync(WhatsAppGroupMembershipEvent @event, CancellationToken cancellationToken) { Events.Add(@event); return Task.CompletedTask; }
        public Task<IReadOnlyList<WhatsAppGroupMembershipEvent>> ListAsync(CancellationToken cancellationToken) => Task.FromResult<IReadOnlyList<WhatsAppGroupMembershipEvent>>(Events);
        public Task<IReadOnlyList<string>> GetParticipantsAsync(string groupId, CancellationToken cancellationToken) => Task.FromResult<IReadOnlyList<string>>([]);
        public Task<IReadOnlyList<string>> GetParticipantsAsync(string groupId, string? instanceName, CancellationToken cancellationToken) => Task.FromResult<IReadOnlyList<string>>([]);
        public Task SetParticipantsAsync(string groupId, IEnumerable<string> participants, CancellationToken cancellationToken) => Task.CompletedTask;
        public Task SetParticipantsAsync(string groupId, string? instanceName, IEnumerable<string> participants, CancellationToken cancellationToken) => Task.CompletedTask;
    }

    private sealed class Audit : IAuditTrail
    {
        internal List<string> Actions { get; } = [];
        public Task WriteAsync(string action, string actor, object details, CancellationToken cancellationToken) { Actions.Add(action); return Task.CompletedTask; }
    }
}
