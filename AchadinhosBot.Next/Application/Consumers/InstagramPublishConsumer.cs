using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Configuration;
using AchadinhosBot.Next.Domain.Governance;
using MassTransit;
using Microsoft.Extensions.Options;

namespace AchadinhosBot.Next.Application.Consumers;

public sealed class InstagramPublishConsumer : IConsumer<PublishInstagramPostCommand>
{
    private readonly IInstagramPublishService _publishService;
    private readonly IIdempotencyStore _idempotencyStore;
    private readonly ITrafficCanaryResolver _canaryResolver;
    private readonly IGovernanceEventStore _governanceEventStore;
    private readonly MessagingOptions _messagingOptions;
    private readonly ILogger<InstagramPublishConsumer> _logger;

    public InstagramPublishConsumer(
        IInstagramPublishService publishService,
        IIdempotencyStore idempotencyStore,
        ITrafficCanaryResolver canaryResolver,
        IGovernanceEventStore governanceEventStore,
        IOptions<MessagingOptions> messagingOptions,
        ILogger<InstagramPublishConsumer> logger)
    {
        _publishService = publishService;
        _idempotencyStore = idempotencyStore;
        _canaryResolver = canaryResolver;
        _governanceEventStore = governanceEventStore;
        _messagingOptions = messagingOptions.Value;
        _logger = logger;
    }

    public async Task Consume(ConsumeContext<PublishInstagramPostCommand> context)
    {
        var command = context.Message;
        var canary = await _canaryResolver.ResolveAsync(new CanaryRoutingContext(
            "instagram_publish",
            null,
            null,
            "instagram"), context.CancellationToken);

        await _governanceEventStore.AppendEventAsync(new GovernanceEvent(
            GovernanceTracks.Observe,
            "instagram.publish.consume.start",
            "info",
            "ok",
            "instagram-autopilot-reviewer",
            "instagram_draft",
            command.DraftId,
            context.CorrelationId?.ToString(),
            context.ConversationId?.ToString(),
            null,
            DateTimeOffset.UtcNow,
            System.Text.Json.JsonSerializer.Serialize(new
            {
                command.DraftId,
                canary.Variant,
                canary.RuleId,
                canary.CanaryPercent
            })), context.CancellationToken);

        var ttl = TimeSpan.FromSeconds(Math.Max(30, _messagingOptions.OutboundDeduplicationWindowSeconds));
        if (!_idempotencyStore.TryBegin($"ig-publish:{command.DeduplicationKey}", ttl))
        {
            _logger.LogInformation("Publicacao Instagram duplicada ignorada. Draft={DraftId}", command.DraftId);
            return;
        }

        var result = await _publishService.ExecutePublishAsync(command.DraftId, context.CancellationToken);
        if (!result.Success && result.ShouldRetry)
        {
            await _governanceEventStore.AppendEventAsync(new GovernanceEvent(
                GovernanceTracks.Act,
                "instagram.publish.consume.failed",
                "warning",
                "failed",
                "instagram-autopilot-reviewer",
                "instagram_draft",
                command.DraftId,
                context.CorrelationId?.ToString(),
                context.ConversationId?.ToString(),
                null,
                DateTimeOffset.UtcNow,
                System.Text.Json.JsonSerializer.Serialize(new { result.Error })), context.CancellationToken);
            throw new InvalidOperationException(result.Error ?? "Falha transiente na publicacao do Instagram.");
        }

        await _governanceEventStore.AppendEventAsync(new GovernanceEvent(
            GovernanceTracks.Act,
            "instagram.publish.consume.finish",
            result.Success ? "info" : "warning",
            result.Success ? "ok" : "failed",
            "instagram-autopilot-reviewer",
            "instagram_draft",
            command.DraftId,
            context.CorrelationId?.ToString(),
            context.ConversationId?.ToString(),
            null,
            DateTimeOffset.UtcNow,
            System.Text.Json.JsonSerializer.Serialize(new { result.Success, result.Error, result.ShouldRetry })), context.CancellationToken);
    }
}
