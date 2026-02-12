using AchadinhosBot.Next.Domain.Models;

namespace AchadinhosBot.Next.Application.Abstractions;

public interface IMessageProcessor
{
    Task<ConversionResult> ProcessAsync(string input, string source, CancellationToken cancellationToken);
}
