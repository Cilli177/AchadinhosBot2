using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Infrastructure.Content;
using MassTransit;

namespace AchadinhosBot.Next.Application.Consumers;

public sealed class ContentCalendarProcessDueConsumer : IConsumer<ProcessContentCalendarDueCommand>
{
    private readonly ContentCalendarAutomationService _automation;
    private readonly IIdempotencyStore _idempotency;
    private readonly IAuditTrail _audit;

    public ContentCalendarProcessDueConsumer(ContentCalendarAutomationService automation, IIdempotencyStore idempotency, IAuditTrail audit)
    { _automation = automation; _idempotency = idempotency; _audit = audit; }

    public async Task Consume(ConsumeContext<ProcessContentCalendarDueCommand> context)
    {
        var command = context.Message;
        var key = $"content-calendar:process-due:{command.DeduplicationKey}";
        if (!_idempotency.TryBegin(key, TimeSpan.FromMinutes(10))) return;
        try
        {
            var summary = await _automation.ProcessDueAsync(context.CancellationToken);
            await _audit.WriteAsync("content_calendar.process_due.completed", command.RequestedBy ?? "system", new { command.MessageId, summary }, context.CancellationToken);
        }
        catch
        {
            _idempotency.RemoveByPrefix(key);
            throw;
        }
    }
}
