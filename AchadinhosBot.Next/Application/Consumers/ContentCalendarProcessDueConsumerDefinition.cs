using MassTransit;

namespace AchadinhosBot.Next.Application.Consumers;

public sealed class ContentCalendarProcessDueConsumerDefinition : ConsumerDefinition<ContentCalendarProcessDueConsumer>
{
    public ContentCalendarProcessDueConsumerDefinition()
    {
        EndpointName = "content-calendar-process-due";
        ConcurrentMessageLimit = 1;
    }

    protected override void ConfigureConsumer(IReceiveEndpointConfigurator endpoint, IConsumerConfigurator<ContentCalendarProcessDueConsumer> consumer, IRegistrationContext context)
    {
        endpoint.PrefetchCount = 1;
        endpoint.ConcurrentMessageLimit = 1;
        endpoint.UseMessageRetry(retry => retry.Interval(3, TimeSpan.FromSeconds(20)));
    }
}
