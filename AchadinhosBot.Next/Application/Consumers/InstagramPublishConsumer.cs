using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Configuration;
using MassTransit;
using Microsoft.Extensions.Options;

namespace AchadinhosBot.Next.Application.Consumers;

public sealed class InstagramPublishConsumer : IConsumer<PublishInstagramPostCommand>
{
    private readonly IInstagramPublishService _publishService;
    private readonly IIdempotencyStore _idempotencyStore;
    private readonly MessagingOptions _messagingOptions;
    private readonly ILogger<InstagramPublishConsumer> _logger;

    public InstagramPublishConsumer(
        IInstagramPublishService publishService,
        IIdempotencyStore idempotencyStore,
        IOptions<MessagingOptions> messagingOptions,
        ILogger<InstagramPublishConsumer> logger)
    {
        _publishService = publishService;
        _idempotencyStore = idempotencyStore;
        _messagingOptions = messagingOptions.Value;
        _logger = logger;
    }

    public async Task Consume(ConsumeContext<PublishInstagramPostCommand> context)
    {
        var command = context.Message;
        var ttl = TimeSpan.FromSeconds(Math.Max(30, _messagingOptions.OutboundDeduplicationWindowSeconds));
        if (!_idempotencyStore.TryBegin($"ig-publish:{command.DeduplicationKey}", ttl))
        {
            _logger.LogInformation("Publicacao Instagram duplicada ignorada. Draft={DraftId}", command.DraftId);
            return;
        }

        var result = await _publishService.ExecutePublishAsync(command.DraftId, context.CancellationToken);
        if (!result.Success && result.ShouldRetry)
        {
            throw new InvalidOperationException(result.Error ?? "Falha transiente na publicacao do Instagram.");
        }
    }
}
