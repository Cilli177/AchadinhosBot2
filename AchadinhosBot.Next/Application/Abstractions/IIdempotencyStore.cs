namespace AchadinhosBot.Next.Application.Abstractions;

public interface IIdempotencyStore
{
    bool TryBegin(string key, TimeSpan ttl);
}
