namespace AchadinhosBot.Next.Application.Abstractions;

public interface IAuditTrail
{
    Task WriteAsync(string action, string actor, object details, CancellationToken cancellationToken);
}
