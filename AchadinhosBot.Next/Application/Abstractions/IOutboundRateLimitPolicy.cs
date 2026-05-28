namespace AchadinhosBot.Next.Application.Abstractions;

public interface IOutboundRateLimitPolicy
{
    bool TryGetDelay(string channel, string destination, out TimeSpan delay);
    void RecordSuccess(string channel, string destination);
    void RecordFailure(string channel, string destination, bool isRateLimit);
}
