using MassTransit;

namespace AchadinhosBot.Next.Application.Consumers;

public sealed class TelegramOutboundConsumerDefinition : ConsumerDefinition<TelegramOutboundConsumer>
{
    public TelegramOutboundConsumerDefinition()
    {
        EndpointName = "telegram-outbound";
        ConcurrentMessageLimit = 1;
    }

    protected override void ConfigureConsumer(
        IReceiveEndpointConfigurator endpointConfigurator,
        IConsumerConfigurator<TelegramOutboundConsumer> consumerConfigurator,
        IRegistrationContext context)
    {
        endpointConfigurator.PrefetchCount = 1;
        endpointConfigurator.ConcurrentMessageLimit = 1;
        endpointConfigurator.UseMessageRetry(retry => retry.Interval(5, TimeSpan.FromSeconds(15)));
    }
}
