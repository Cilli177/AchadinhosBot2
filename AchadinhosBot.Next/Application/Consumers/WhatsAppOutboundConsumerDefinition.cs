using MassTransit;

namespace AchadinhosBot.Next.Application.Consumers;

public sealed class WhatsAppOutboundConsumerDefinition : ConsumerDefinition<WhatsAppOutboundConsumer>
{
    public WhatsAppOutboundConsumerDefinition()
    {
        EndpointName = "whatsapp-outbound";
        ConcurrentMessageLimit = 1;
    }

    protected override void ConfigureConsumer(
        IReceiveEndpointConfigurator endpointConfigurator,
        IConsumerConfigurator<WhatsAppOutboundConsumer> consumerConfigurator,
        IRegistrationContext context)
    {
        endpointConfigurator.PrefetchCount = 1;
        endpointConfigurator.ConcurrentMessageLimit = 1;
        endpointConfigurator.UseMessageRetry(retry => retry.Interval(5, TimeSpan.FromSeconds(15)));
    }
}
